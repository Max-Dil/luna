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
func new_client
func close_client
func request_listener
boolean debug
]]
app.new_app = function(config)
    local app_data
    if config.debug == nil then
        config.debug = true
    end
    app_data = setmetatable({
        max_ip_connected = config.max_ip_connected or 100,
        name = config.name or "unknown name",
        error_handler = config.error_handler or function(message) 
            print("Error in app '"..app_data.name.."': "..message) 
        end,
        no_errors = config.no_errors,
        host = config.host or "*",
        port = config.port or 433,

        new_client = config.new_client,
        close_client = config.close_client,

        request_listener = config.request_listener,

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

        debug = config.debug,
    }, {__index = router})

    local ok, err = pcall(function()
        app_data.server = assert(socket.bind(app_data.host, app_data.port))
        app_data.server:settimeout(0)
    end)

    if not ok then
        handle_error(app_data, "Failed to start app on "..app_data.host..":"..app_data.port..": "..err)
        return nil, err
    end

    print("App '"..app_data.name.."' started on "..app_data.host..":"..app_data.port)
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
            handle_error(app_data, "Error closing client connection: "..err)
        end
    end

    local ok, err = pcall(function() app_data.server:close() end)
    if not ok then
        handle_error(app_data, "Error closing server: "..err)
    end

    print("Server '"..name.."' stopped")
    return true
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

local workers = require("luna.core.workers")
app.update = function(dt)

    for coro, data in pairs(workers.running_funs) do
        local request_handler, request, client_data = data[1], data[2], data[3]
        local client = client_data.client
        local request_result = nil

        local ok, ok2, result = pcall(coroutine.resume, coro, request.args, client)
        if result then
            if not ok then
                if request_handler.error_handler then
                    request_handler.error_handler(tostring(ok2))
                end
                request_result = {client = client, response = {request = request.path, error = tostring(ok2), time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil}}
            end

            if not ok2 then
                if request_handler.error_handler then
                    request_handler.error_handler(result)
                end
                request_result = {client = client, response = {request = request.path, error = tostring(ok2), time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil}}
            end

            if not request_result and request_handler.responce_validate then
                if not validate_value(result, request_handler.responce_validate) then
                    local expected_str = table.concat(request_handler.responce_validate, " or ")
                    local actual_type = type(result)
                    local err_msg = string.format("Response expected to be %s, got %s (%s)", 
                        expected_str, actual_type, tostring(result))

                    if request_handler.error_handler then
                        request_handler.error_handler(err_msg)
                    end
                    request_result = {client = client, response = {request = request.path, error = err_msg, time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil}}
                end
            end

            if not request_result then
                request_result = {client = client, response = {request = request.path, response = result, time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil}}
            end

            if request_result and request_result.response then
                local response = request_result.response
                if not response.__noawait then
                    local ok, send_err = pcall(function()
                        client:send(json.encode(response) .. "\n")
                    end)
                    if not ok then
                        print("Error in async request: "..send_err.."  id:"..response.id.."  path:"..response.request)
                    end
                end
                workers.running_funs[coro] = nil
            end
        end
    end

    for key, m in pairs(apps) do
        local new_client, err = m.server:accept()
        if err and err ~= "timeout" then
            handle_error(m, "Error accepting connection: "..err)
        end

        if new_client then
            local ok, ip, port = pcall(function() return new_client:getpeername() end)
            if not ok then
                handle_error(m, "Error getting peer name: "..ip)
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
                    if m.debug then
                        print("app: "..m.name, "New client connected ip: "..ip..", port: "..port)
                    end
                    if m.new_client then
                        local ok, cb_err = pcall(m.new_client, client_data.client)
                        if not ok then
                            handle_error(m, "Error in new_client callback: "..cb_err)
                        end
                    end
                else
                    new_client:close()
                    print("Rejected connection from "..ip"..: max connections ("..m.max_ip_connected..") reached")
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
                    if m.debug then
                        print("app: "..m.name, "Client disconnected ip: "..client_data.ip..":"..client_data.port)
                    end
                    table.remove(m.clients, i)
                    if m.close_client then
                        local ok, cb_err = pcall(m.close_client, client_data.client)
                        if not ok then
                            handle_error(m, "Error in close_client callback: "..cb_err)
                        end
                    end
                elseif err ~= "timeout" then
                    handle_error(m, "Error receiving data from client "..client_data.ip..":"..client_data.port..": "..err)
                end
            elseif data then
                if m.debug then
                    print("app: "..m.name, client_data.ip..":"..client_data.port, data)
                end
                if m.request_listener then
                    m.request_listener(data)
                end

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
                    response_to_send = {request = "unknown", response = response, id = "unknown id", __luna = true, time = 0}
                end

                if not response_to_send.__noawait then
                    local ok, send_err = pcall(function()
                        client_data.client:send(json.encode(response_to_send) .. "\n")
                    end)
                    if not ok then
                        handle_error(m, "Error sending data to client "..client_data.ip..":"..client_data.port..": "..send_err)
                        table.remove(m.clients, i)
                    end
                end
            end
        end
    end
end

return app