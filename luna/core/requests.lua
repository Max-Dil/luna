--[[
MIT License

Copyright (c) 2025 Max-Dil

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
]]

local req = {}
local json = require("luna.libs.json")

req.new = function(router, config)
    local req_data
    req_data = {
        prefix = config.prefix,
        fun = config.fun,
        no_errors = config.no_errors,
        validate = config.validate,
        responce_validate = config.responce_validate,
        error_handler = config.error_handler or function(message) 
            print("Error in request prefix: "..req_data.prefix.." error: "..message) 
        end,
        async = config.async,
        router = router,
        max_message_size = config.max_message_size,
        message_penalty = config.message_penalty or "timeout",
        timeout_duration = config.timeout_duration,
        middlewares = config.middlewares or {},
    }

    router.requests[config.prefix] = req_data

    return req_data
end

req.remove = function(router, req_data)
    if type(req_data) == "string" then
        req_data = router.requests[req_data]
    end

    router.requests[req_data.prefix] = nil
end

local function split(str, sep)
    local result = {}
    for part in str:gmatch("[^"..sep.."]+") do
        table.insert(result, part)
    end
    return result
end

local function parse_request(data)
    data = data:gsub("^%s*(.-)%s*$", "%1")

    local path, args_str = data:match("^(%S+)%s*(.*)$")
    if not path then
        return nil, "Invalid request format"
    end

    local max_iterations = 300
    local iteration = 0

    local args = {}

    while args_str and args_str ~= "" do
        iteration = iteration + 1
        local key, value, remaining
        local matched = false

        -- JSON: key=<json='["test",550]'>
        key, value, remaining = args_str:match("^(%S+)=<json='([^']*)'>%s*(.*)$")
        if key then
            local success, decoded = pcall(json.decode, value)
            if success then
                args[key] = decoded
                args_str = remaining
                matched = true
            else
                return nil, "Invalid JSON in parameter '"..key.."': "..decoded
            end
        end

        if not matched then
            -- String: key='value'
            key, value, remaining = args_str:match("^(%S+)='([^']*)'%s*(.*)$")
            if key then
                args[key] = value
                args_str = remaining
                matched = true
            end
        end

        if not matched then
            -- Boolean: key=True or key=False
            key, remaining = args_str:match("^(%S+)=True%s*(.*)$")
            if key then
                args[key] = true
                args_str = remaining
                matched = true
            end
        end

        if not matched then
            key, remaining = args_str:match("^(%S+)=False%s*(.*)$")
            if key then
                args[key] = false
                args_str = remaining
                matched = true
            end
        end

        if not matched then
            -- Number: key=100 or key=-100
            key, value, remaining = args_str:match("^(%S+)=([%-%d%.]+)%s*(.*)$")
            if key then
                value = tonumber(value)
                if value then
                    args[key] = value
                    args_str = remaining
                    matched = true
                else
                    return nil, "Invalid number in parameter '"..key.."': "..tostring(value)
                end
            end
        end

        if not matched then
            if args_str:match("%S") then
                key, remaining = args_str:match("^(%S+)%s*(.*)$")
                if key then
                    args[key] = true
                    args_str = remaining
                    matched = true
                else
                    break
                end
            else
                break
            end
        end

        if iteration > max_iterations then
            -- print("Request processing limit exceeded (300)")
            break
        end
    end

    return {
        path = path,
        args = args
    }
end

local function validate_value(value, expected_types)
    if value == nil then
        for _, t in ipairs(expected_types) do
            if t == "nil" then
                return true
            end
        end
        return false
    end

    local actual_type = type(value)

    for _, expected_type in ipairs(expected_types) do
        if expected_type == "number" and tonumber(value) ~= nil then
            return true
        elseif actual_type == expected_type then
            return true
        end
    end

    return false
end

local function validate_args(validate_config, args)
    for key, expected_types in pairs(validate_config) do
        local value = args[key]

        if not validate_value(value, expected_types) then
            local expected_str = table.concat(expected_types, " or ")
            local actual_type = type(value)
            return false, string.format("Argument '%s' expected to be %s, got %s (%s)", 
                key, expected_str, actual_type, tostring(value))
        end
    end

    return true
end

local function apply_penalty(app, client_data, penalty, timeout_duration, error_msg)
    if penalty == "closed" then
        app.ip_counts[client_data.ip] = (app.ip_counts[client_data.ip] or 1) - 1
        if app.ip_counts[client_data.ip] <= 0 then
            app.ip_counts[client_data.ip] = nil
        end
        if app.debug then
            print("app: "..app.name, "Client disconnected ip: "..client_data.ip..":"..client_data.port.." due to penalty")
        end
        app.clients[client_data.ip..":"..client_data.port] = nil
        if app.close_client then
            local ok, cb_err = pcall(app.close_client, client_data)
            if not ok then
                print("Error in close_client callback: "..cb_err)
            end
        end
        return {error = error_msg, __luna = true}
    elseif penalty == "timeout" then
        app.blocked_ips = app.blocked_ips or {}
        app.blocked_ips[client_data.ip] = os.time() + timeout_duration
        if app.debug then
            print("app: "..app.name, "Client timed out ip: "..client_data.ip..":"..client_data.port.." for "..timeout_duration.." seconds")
        end
        return {error = error_msg.." Timed out for "..timeout_duration.." seconds", __luna = true}
    end
    return {error = error_msg, __luna = true}
end

req.process = function(router, client_data, data)
    router.app.blocked_ips = router.app.blocked_ips or {}
    if router.app.blocked_ips[client_data.ip] then
        if os.time() < router.app.blocked_ips[client_data.ip] then
            return {error = "Client IP "..client_data.ip.." is temporarily blocked", __luna = true}
        else
            router.app.blocked_ips[client_data.ip] = nil
        end
    end

    local request_handler
    local path_parts = split(data:match("^(%S+)") or "", "/")
    if #path_parts >= 2 then
        local router_prefix = path_parts[1]
        local request_prefix = path_parts[2]
        local router_data = router.app.routers[router_prefix]
        if router_data then
            request_handler = router_data.requests[request_prefix]
        end
    end

    if request_handler and request_handler.max_message_size then
        if #data > request_handler.max_message_size then
            local error_msg = "Message size exceeds limit of "..request_handler.max_message_size.." bytes"
            return apply_penalty(router.app, client_data, request_handler.message_penalty, request_handler.timeout_duration, error_msg)
        end
    end

    local request, err = parse_request(data)
    if not request then
        return nil, err
    end

    if #path_parts < 2 then
        return nil, "Invalid path format"
    end

    local router_prefix = path_parts[1]
    local request_prefix = path_parts[2]

    local router_data = router.app.routers[router_prefix]
    if not router_data then
        return nil, "No router found for prefix: "..router_prefix
    end

    request_handler = router_data.requests[request_prefix]
    if not request_handler or not request_handler.fun then
        return nil, "No handler found for path: "..request.path
    end

    local context = { request = request, client = client_data, stop = false, ip = client_data.ip, port = client_data.port }
    for _, middleware in ipairs(request_handler.middlewares) do
        local ok, result = pcall(middleware, context, true)
        if not ok then
            if request_handler.error_handler then
                request_handler.error_handler("Middleware error: "..result)
            end
            return {request = request.path, error = "Middleware error: "..result, time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil}
        end
        if context.stop then
            return result or {request = request.path, error = "Request stopped by middleware", time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil}
        end
    end

    if request_handler.validate then
        local valid, err_msg = validate_args(request_handler.validate, request.args)
        if not valid then
            if request_handler.error_handler then
                request_handler.error_handler(err_msg)
            end
            return {request = request.path, error = err_msg, time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil}
        end
    end

    if request.args.__client_token ~= client_data.token then
        return {request = request.path, error = "Couldn't confirm the client's token", time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil}
    end

    local result
    if request_handler.async then
        local coro = coroutine.create(request_handler.fun)
        router.app.running_funs[coro] = {request_handler, request, client_data}
        result = {request = request.path, time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil, no_responce = true}
    else
        local ok, handler_result = pcall(request_handler.fun, request.args, client_data)
        if not ok then
            if request_handler.error_handler then
                request_handler.error_handler(handler_result)
            end
            return {request = request.path, error = handler_result, time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil}
        end
        result = {request = request.path, response = handler_result, time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil}
    end

    context.response = result
    for _, middleware in ipairs(request_handler.middlewares) do
        local ok, mw_result = pcall(middleware, context, false)
        if not ok then
            if request_handler.error_handler then
                request_handler.error_handler("Middleware error: "..mw_result)
            end
            return {request = request.path, error = "Middleware error: "..mw_result, time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil}
        end
        if mw_result then
            result = mw_result
        end
        if context.stop then
            return result or {request = request.path, error = "Request stopped by middleware", time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil}
        end
    end

    if not request_handler.async and request_handler.responce_validate then
        if not validate_value(result.response, request_handler.responce_validate) then
            local expected_str = table.concat(request_handler.responce_validate, " or ")
            local actual_type = type(result.response)
            local err_msg = string.format("Response expected to be %s, got %s (%s)",
                expected_str, actual_type, tostring(result.response))
            if request_handler.error_handler then
                request_handler.error_handler(err_msg)
            end
            return {request = request.path, error = err_msg, time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil}
        end
    end

    return result
end

return req