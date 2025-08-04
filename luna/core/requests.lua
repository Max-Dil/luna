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
        router = router
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

    local args = {}

    while args_str and args_str ~= "" do
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
            -- Number: key=100
            key, value, remaining = args_str:match("^(%S+)=([%d%.]+)%s*(.*)$")
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
            key, remaining = args_str:match("^(%S+)%s*(.*)$")
            if not key then break end
            args[key] = true
            args_str = remaining
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

local workers = require("luna.core.workers")
req.process = function(router, client_data, data)
    local request, err = parse_request(data)
    if not request then
        return nil, err
    end

    local path_parts = split(request.path, "/")
    if #path_parts < 2 then
        return nil, "Invalid path format"
    end

    local router_prefix = path_parts[1]
    local request_prefix = path_parts[2]

    local router_data = router.app.routers[router_prefix]
    if not router_data then
        return nil, "No router found for prefix: "..router_prefix
    end

    local request_handler = router_data.requests[request_prefix]
    if not request_handler or not request_handler.fun then
        return nil, "No handler found for path: "..request.path
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

    if request_handler.async then
        local worker = workers.getFreeWorker()
        coroutine.resume(worker, request_handler, request, client_data)
        return {request = request.path, time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = true}
    end

    local ok, result = pcall(request_handler.fun, request.args, client_data.client)
    if not ok then
        if request_handler.error_handler then
            request_handler.error_handler(result)
        end
        return {request = request.path, error = result, time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil}
    end

    if request_handler.responce_validate then
        if not validate_value(result, request_handler.responce_validate) then
            local expected_str = table.concat(request_handler.responce_validate, " or ")
            local actual_type = type(result)
            local err_msg = string.format("Response expected to be %s, got %s (%s)", 
                expected_str, actual_type, tostring(result))
            
            if request_handler.error_handler then
                request_handler.error_handler(err_msg)
            end
            return {request = request.path, error = err_msg, time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil}
        end
    end

    return {request = request.path, response = result, time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil}
end

return req