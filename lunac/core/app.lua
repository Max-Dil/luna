local socket = require("socket")

local app = {}
local apps = {}

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
                    text = "no support "..type(v)
                end
                table.insert(arg_parts, string.format(k.."=("..text..")"))
            end
            if #arg_parts > 0 then
                request = request .. " " .. table.concat(arg_parts, " ")
            end
        end

        local success, err = app_data.client:send(request .. "\n")
        if not success then
            if app_data.no_errors then
                app_data.error_handler(f("Send failed: {err}", {err = err}))
                return nil, err or "Failed to send request"
            else
                error(f("Send failed: {err}", {err = err}), 2)
            end
        end

        local start_time = socket.gettime()
        timeout = timeout or 5

        while true do
            if app_data.server then
                app_data.server.update()
            end
            local line, err = app_data.client:receive("*l")
            if line then
                return line
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
                    app_data.error_handler(f("Receive failed: {err}", {err = err}))
                    return nil, err or "Failed to receive response"
                else
                    error(f("Receive failed: {err}", {err = err}), 2)
                end
            end
        end
    end,
}

app.connect = function(config)
    if not config.host then
        error(f("Error connect to app unknown host, app_name: {name}", {name = config.name or "unknown name"}), 2)
    end

    local app_data = setmetatable({
        name = config.name or "unknown name",
        host = config.host,
        port = config.port or 433,
        no_errors = config.no_errors,
        error_handler = config.error_handler or function(message) 
            print(f("Error in app '{name}': {message}", {name = config.name or "unknown name", message = message})) 
        end,
        connected = false,
        client = nil,
        server = config.server
    }, {__index = class})

    local client, err = socket.connect(config.host, config.port)
    if not client then
        if app_data.no_errors then
            app_data.error_handler(f("Connection failed: {err}", {err = err}))
            return nil
        else
            error(f("Connection failed: {err}", {err = err}), 2)
        end
    end

    client:settimeout(0)
    app_data.client = client
    app_data.connected = true

    print(f("Connected to {host}:{port}", {host = config.host, port = config.port}))

    apps[app_data.name] = app_data
    return app_data
end

app.send = function(app_data, data)
    if type(app_data) == "string" then
        app_data = apps[app_data]
    end

    if not app_data or not app_data.connected then
        if app_data.no_errors then
            app_data.error_handler("Not connected to server")
            return false
        else
            error("Not connected to server", 2)
        end
    end

    local success, err = app_data.client:send(data .. "\n")
    if not success then
        if app_data.no_errors then
            app_data.error_handler(f("Send failed: {err}", {err = err}))
            return false
        else
            error(f("Send failed: {err}", {err = err}), 2)
        end
    end

    return true
end

app.receive = function(app_data)
    if type(app_data) == "string" then
        app_data = apps[app_data]
    end

    if not app_data or not app_data.connected then
        if app_data.no_errors then
            app_data.error_handler("Not connected to server")
            return nil
        else
            error("Not connected to server", 2)
        end
    end

    local line, err = app_data.client:receive("*l")
    if line then
        return line
    elseif err == "timeout" then
        return nil
    else
        app_data.connected = false
        if app_data.no_errors then
            app_data.error_handler(f("Receive failed: {err}", {err = err}))
            return nil
        else
            error(f("Receive failed: {err}", {err = err}), 2)
        end
    end
end

app.update = function(dt)
    for name, app_data in pairs(apps) do
        if app_data.connected then
            local line = app.receive(app_data)
            if line then
                print(f("[{name}] Received: {line}", {name = name, line = line}))
            end
        end
    end
end

app.close = function(app_data)
    if type(app_data) == "string" then
        app_data = apps[app_data]
    end

    if not app_data then return end

    if app_data.connected then
        app_data.client:close()
        app_data.connected = false
        print(f("Disconnected from {host}:{port}", {host = app_data.host, port = app_data.port}))
    end

    apps[app_data.name] = nil
end

return app