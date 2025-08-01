local req = {}

req.new = function(router, config)
    local req_data
    req_data = {
        prefix = config.prefix,
        fun = config.fun,
        no_errors = config.no_errors,
        error_handler = config.error_handler or function(message) 
            print(f("Error in request prefix: {req_data.prefix} error: {message}", {req_data = req_data, message = message})) 
        end,
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
    if not path then return nil, "Invalid request format" end

    local args = {}

    while args_str and args_str ~= "" do
        local key, value, remaining

        key, value, remaining = args_str:match("^(%S+)=%('([^']*)'%)%s*(.*)$")
        
        if not key then
            key, value, remaining = args_str:match("^(%S+)=%(\"([^\"]*)\"%)%s*(.*)$")
        end

        if not key then
            key, value, remaining = args_str:match("^(%S+)=%(true%)%s*(.*)$")
            if key then
                value = true
            else
                key, value, remaining = args_str:match("^(%S+)=%(false%)%s*(.*)$")
                if key then
                    value = false
                end
            end
        end

        if not key then
            key, value, remaining = args_str:match("^(%S+)=%(([%d%.]+)%)%s*(.*)$")
            if key then
                value = tonumber(value)
            end
        end

        if not key then break end

        args[key] = value
        args_str = remaining
    end

    return {
        path = path,
        args = args
    }
end

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

    local ok, result = pcall(request_handler.fun, request.args, client_data)
    if ok then
        return result
    else
        if request_handler.error_handler then
            request_handler.error_handler(result)
        end
        return nil, result
    end
end

return req