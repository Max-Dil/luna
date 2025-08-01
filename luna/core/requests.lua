local req = {}

req.new = function(router, config)
    local req_data
    req_data = {
        prefix = config.prefix,
        fun = config.fun,
        no_errors = config.no_errors,
        validate = config.validate,
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

local function validate_args(validate_config, args)
    for key, expected_types in pairs(validate_config) do
        local value = args[key]

        if value == nil then
            local nil_allowed = false
            for _, t in ipairs(expected_types) do
                if t == "nil" then
                    nil_allowed = true
                    break
                end
            end
            if nil_allowed then goto continue end
        end

        if value ~= nil then
            local type_match = false
            local actual_type = type(value)
            
            for _, expected_type in ipairs(expected_types) do
                if expected_type == "number" and tonumber(value) ~= nil then
                    type_match = true
                    break
                elseif actual_type == expected_type then
                    type_match = true
                    break
                end
            end
            
            if not type_match then
                local expected_str = table.concat(expected_types, " or ")
                return false, string.format("Argument '%s' expected to be %s, got %s (%s)", 
                    key, expected_str, actual_type, tostring(value))
            end
        end
        
        ::continue::
    end
    
    return true
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

    if request_handler.validate then
        local valid, err_msg = validate_args(request_handler.validate, request.args)
        if not valid then
            if request_handler.error_handler then
                request_handler.error_handler(err_msg)
            end
            return nil, err_msg
        end
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