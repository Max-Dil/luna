local socket = require("socket")
local json = require("lunac.libs.json")

local app = {}
local apps = {}

local function parse_response(line)
    local ok, result = pcall(json.decode, line)
    if ok and type(result) == "table" then
        return result
    end
    return {request = "unknown", response = line, id = "unknown id"}
end

local uuid = function()
    local template = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
    return string.gsub(template, '[xy]', function(c)
        local v = (c == 'x') and math.random(0, 15) or math.random(8, 11)
        return string.format('%x', v)
    end)
end

local function try_connect(app_data)
    local client, err = socket.connect(app_data.host, app_data.port)
    if client then
        client:settimeout(0)
        app_data.client = client
        app_data.connected = true
        app_data.trying_to_reconnect = false
        print("Connected to "..app_data.host..":"..app_data.port)
        return true
    else
        if not app_data.trying_to_reconnect then
            app_data.error_handler("Connection failed: "..err)
            if app_data.reconnect_time then
                app_data.trying_to_reconnect = true
                app_data.reconnect_timer = 0
            end
        end
        return false
    end
end

local class = {
    fetch = function(app_data, path, args, timeout)
        if type(app_data) == "string" then
            app_data = apps[app_data]
        end

        if not app_data or not app_data.connected then
            if app_data.no_errors then
                app_data.error_handler("Not connected to server")
                return nil, "Not connected to server"
            else
                error("Not connected to server", 2)
            end
        end

        local request_id = uuid()

        local request = path
        if args then
            local arg_parts = {}
            for k, v in pairs(args) do
                local text
                if type(v) == "string" then
                    text = "'"..v.."'"
                elseif type(v) == "number" then
                    text = v
                elseif type(v) == "boolean" then
                    text = tostring(v)
                else
                    text = "'no support "..type(v).."'"
                    error("'no support "..type(v).."'", 2)
                end
                table.insert(arg_parts, string.format(k.."=("..text..")"))
            end
            table.insert(arg_parts, "__id=('"..request_id.."')")
            request = request .. " " .. table.concat(arg_parts, " ")
        end

        local success, err = app_data.client:send(request .. "\n")
        if not success then
            if app_data.no_errors then
                app_data.error_handler("Send failed: "..err)
                return nil, err or "Failed to send request"
            else
                error("Send failed: "..err, 2)
            end
        end

        local start_time = socket.gettime()
        timeout = timeout or 5

        while true do
            if app_data.server then
                app_data.server.update()
            end

            if not app_data.connected then
                if app_data.reconnect_time then
                    if try_connect(app_data) then
                        success, err = app_data.client:send(request .. "\n")
                        if not success then
                            return nil, err or "Failed to resend request after reconnect"
                        end
                    else
                        return nil, "Disconnected and reconnect failed"
                    end
                else
                    return nil, "Disconnected"
                end
            end

            local line, err = app_data.client:receive("*l")
            if line then
                local response = parse_response(line)
                if response.__luna and response.request == path and response.id == request_id then
                    if response.error then
                        return nil, response.error
                    end
                    return response.response
                else
                    if app_data.listener and not response.__luna then
                        app_data.listener(line)
                    end
                end
            elseif err == "timeout" then
                if socket.gettime() - start_time > timeout then
                    if app_data.no_errors then
                        app_data.error_handler("Request timed out")
                        return nil, "Request timed out"
                    else
                        error("Request timed out", 2)
                    end
                end
                socket.sleep(0.001)
            else
                app_data.connected = false
                if app_data.no_errors then
                    app_data.error_handler("Receive failed: "..err)
                    return nil, err or "Failed to receive response"
                else
                    error("Receive failed: "..err, 2)
                end
            end
        end
    end,
    noawait_fetch = function(app_data, path, args)
        if type(app_data) == "string" then
            app_data = apps[app_data]
        end

        if not app_data or not app_data.connected then
            if app_data.no_errors then
                app_data.error_handler("Not connected to server")
                return nil, "Not connected to server"
            else
                error("Not connected to server", 2)
            end
        end

        local request_id = uuid()

        local request = path
        if args then
            local arg_parts = {}
            for k, v in pairs(args) do
                local text
                if type(v) == "string" then
                    text = "'"..v.."'"
                elseif type(v) == "number" then
                    text = v
                elseif type(v) == "boolean" then
                    text = tostring(v)
                else
                    text = "'no support "..type(v).."'"
                    error("'no support "..type(v).."'", 2)
                end
                table.insert(arg_parts, string.format(k.."=("..text..")"))
            end
            table.insert(arg_parts, "__id=('"..request_id.."')")
            table.insert(arg_parts, "__noawait=(true)")
            request = request .. " " .. table.concat(arg_parts, " ")
        end

        local success, err = app_data.client:send(request .. "\n")
        if not success then
            if app_data.no_errors then
                app_data.error_handler("Send failed: "..err)
                return nil, err or "Failed to send request"
            else
                error("Send failed: "..err, 2)
            end
        end
    end,
}

app.connect = function(config)
    if not config.host then
        error("Error connect to app unknown host, app_name: "..config.name, 2)
    end

    local app_data = setmetatable({
        name = config.name or "unknown name",
        host = config.host,
        port = config.port or 433,
        no_errors = config.no_errors,
        error_handler = config.error_handler or function(message) 
            print("Error in app '"..config.name.."': "..message) 
        end,
        listener = config.listener,
        connected = false,
        client = nil,
        server = config.server,
        reconnect_time = config.reconnect_time,
        reconnect_timer = 0,
        trying_to_reconnect = false
    }, {__index = class})

    if not try_connect(app_data) and not app_data.reconnect_time then
        if not app_data.no_errors then
            error("Connection failed", 2)
        end
        return nil
    end

    apps[app_data.name] = app_data
    return app_data
end

app.update = function(dt)
    for name, app_data in pairs(apps) do
        if app_data.connected then
            local line, err = app_data.client:receive("*l")
            if line then
                if app_data.listener then
                    app_data.listener(line)
                end
                print("["..name.."] Received: "..line)
            elseif err and err ~= "timeout" then
                app_data.connected = false
                app_data.error_handler("Receive failed: "..err)
                if app_data.reconnect_time then
                    app_data.trying_to_reconnect = true
                    app_data.reconnect_timer = 0
                end
            end
        elseif app_data.trying_to_reconnect and app_data.reconnect_time then
            app_data.reconnect_timer = app_data.reconnect_timer + dt
            if app_data.reconnect_timer >= app_data.reconnect_time then
                app_data.reconnect_timer = 0
                try_connect(app_data)
            end
        end
    end
end

app.send = function(app_data, data)
    if type(app_data) == "string" then
        app_data = apps[app_data]
    end

    if not app_data then
        if app_data and app_data.no_errors then
            app_data.error_handler("App not found")
            return false
        else
            error("App not found", 2)
        end
    end

    if not app_data.connected then
        if app_data.no_errors then
            app_data.error_handler("Not connected to server")
            return false
        else
            error("Not connected to server", 2)
        end
    end

    local success, err = app_data.client:send(data .. "\n")
    if not success then
        app_data.connected = false
        if app_data.reconnect_time then
            app_data.trying_to_reconnect = true
            app_data.reconnect_timer = 0
        end
        if app_data.no_errors then
            app_data.error_handler("Send failed: "..err)
            return false
        else
            error("Send failed: "..err, 2)
        end
    end

    return true
end

app.close = function(app_data)
    if type(app_data) == "string" then
        app_data = apps[app_data]
    end

    if not app_data then return end

    if app_data.connected then
        app_data.client:close()
        app_data.connected = false
        app_data.trying_to_reconnect = false
        print("Disconnected from "..app_data.host..":"..app_data.port)
    end

    apps[app_data.name] = nil
end

return app