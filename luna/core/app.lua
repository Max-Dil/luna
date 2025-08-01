local socket = require("socket")
local router = require("luna.core.router")
local json = require("luna.libs.json")

local app = {}
local apps = {}

local function handle_error(app_data, message, err_level)
    if not app_data.no_errors then
        if app_data.error_handler then
            app_data.error_handler(message)
        else
            error(message, err_level or 2)
        end
    end
end

--[[
table config:
str name
int max_ip_connected
func error_handler
boolean no_errors
str host
int port
]]
app.new_app = function(config)
    local app_data
    app_data = setmetatable({
        max_ip_connected = config.max_ip_connected or 100,
        name = config.name or "unknown name",
        error_handler = config.error_handler or function(message) 
            print(f("Error in app '{app_data.name}': {message}", {app_data = app_data, message = message})) 
        end,
        no_errors = config.no_errors,
        host = config.host or "*",
        port = config.port or 433,

        clients = {},
        ip_counts = {},
        routers = {},

        get_clients = function ()
            local clients = {}
            for key, value in pairs(app_data.clients) do
                table.insert(clients, value.client)
            end
            return clients
        end,
    }, {__index = router})

    local ok, err = pcall(function()
        app_data.server = assert(socket.bind(app_data.host, app_data.port))
        app_data.server:settimeout(0)
    end)

    if not ok then
        handle_error(app_data, f("Failed to start app on {app_data.host}:{app_data.port}: {err}", {app_data = app_data, err = err}))
        return nil, err
    end

    print(f("App '{app_data.name}' started on {app_data.host}:{app_data.port}", {app_data = app_data}))
    apps[app_data.name] = app_data
    return app_data
end

app.remove = function(app_data)
    if type(app_data) == "string" then
        app_data = apps[app_data]
        if not app_data then
            return false, "App not found"
        end
    end

    local name = app_data["name"]
    apps[name] = nil

    for _, client_data in ipairs(app_data.clients) do
        local ok, err = pcall(function() client_data.client:close() end)
        if not ok then
            handle_error(app_data, f("Error closing client connection: {err}", {err = err}))
        end
    end

    local ok, err = pcall(function() app_data.server:close() end)
    if not ok then
        handle_error(app_data, f("Error closing server: {err}", {err = err}))
    end

    print(f("Server '{name}' stopped", {name = name}))
    return true
end

app.update = function(dt)
    for key, m in pairs(apps) do
        local new_client, err = m.server:accept()
        if err and err ~= "timeout" then
            handle_error(m, f("Error accepting connection: {err}", {err = err}))
        end

        if new_client then
            local ok, ip, port = pcall(function() return new_client:getpeername() end)
            if not ok then
                handle_error(m, f("Error getting peer name: {ip}", {ip = ip}))
                new_client:close()
            else
                new_client:settimeout(0)
                m.ip_counts[ip] = (m.ip_counts[ip] or 0) + 1

                if m.ip_counts[ip] <= m.max_ip_connected then
                    local client_data = {
                        ip = ip,
                        port = port,
                        client = new_client
                    }
                    table.insert(m.clients, client_data)
                    print("app: "..m.name, "New client connected ip: "..ip..", port: "..port)
                else
                    new_client:close()
                    print(f("Rejected connection from {ip}: max connections ({m.max_ip_connected}) reached", {ip = ip, m = m}))
                    m.ip_counts[ip] = m.ip_counts[ip] - 1
                end
            end
        end

        for i = #m.clients, 1, -1 do
            local client_data = m.clients[i]
            local data, err = client_data.client:receive("*l")

            if err then
                if err == "closed" then
                    m.ip_counts[client_data.ip] = (m.ip_counts[client_data.ip] or 1) - 1
                    if m.ip_counts[client_data.ip] <= 0 then
                        m.ip_counts[client_data.ip] = nil
                    end
                    print("app: "..m.name, "Client disconnected ip: "..client_data.ip..":"..client_data.port)
                    table.remove(m.clients, i)
                elseif err ~= "timeout" then
                    handle_error(m, f("Error receiving data from client {client_data.ip}:{client_data.port}: {err}", {
                        client_data = client_data,
                        err = err
                    }))
                end
            elseif data then
                print("app: "..m.name, client_data.ip..":"..client_data.port, data)

                local response
                for _, router_data in pairs(m.routers) do
                    local res = router_data:process(client_data, data)
                    if res then
                        response = res
                        break
                    end
                end

                local response_to_send
                if type(response) == "table" and (response.request or response.error or response.response or response.id) then
                    response_to_send = response
                else
                    response_to_send = {request = "unknown", response = response, id = "unknown id", __luna = true}
                end

                if not response_to_send.__noawait then
                    local ok, send_err = pcall(function()
                        client_data.client:send(json.encode(response_to_send) .. "\n")
                    end)
                    if not ok then
                        handle_error(m, f("Error sending data to client {client_data.ip}:{client_data.port}: {send_err}", {
                            client_data = client_data,
                            send_err = send_err
                        }))
                        table.remove(m.clients, i)
                    end
                end
            end
        end
    end
end

return app