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

local socket = require("socket")
local router = require("luna.core.router")
local json = require("luna.libs.json")
local message_manager = require("luna.libs.udp_messages")

local app = {}
local apps = {}
local TIMEOUT_SECONDS = 10

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
            print("Error in app '" .. app_data.name .. "': " .. message)
        end,
        no_errors = config.no_errors,
        host = config.host or "0.0.0.0",
        port = config.port or 433,

        new_client = config.new_client,
        close_client = config.close_client,

        request_listener = config.request_listener,

        clients = {},
        ip_counts = {},
        routers = {},

        running_funs = {},

        get_clients = function()
            local clients = {}
            for key, value in pairs(app_data.clients) do
                table.insert(clients, { ip = value.ip, port = value.port })
            end
            return clients
        end,

        debug = config.debug,
    }, { __index = router })

    local ok, err = pcall(function()
        app_data.server = assert(socket.udp(), "Failed to create UDP socket")
        assert(app_data.server:setsockname(app_data.host, app_data.port), "Failed to bind to port")
        app_data.server:settimeout(0)

        app_data.socket = message_manager()
    end)

    if not ok then
        handle_error(app_data, "Failed to start app on " .. app_data.host .. ":" .. app_data.port .. ": " .. err)
        return nil, err
    end

    print("App '" .. app_data.name .. "' started on " .. app_data.host .. ":" .. app_data.port)
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

    for client_key, client_data in pairs(app_data.clients) do
        if app_data.close_client then
            local ok, err = pcall(app_data.close_client, client_data)
            if not ok then
                handle_error(app_data, "Error in close_client callback: " .. err)
            end
        end
    end

    local ok, err = pcall(function() app_data.server:close() end)
    if not ok then
        handle_error(app_data, "Error closing server: " .. err)
    end

    print("Server '" .. name .. "' stopped")
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

app.update = function(dt)
    dt = dt or (1 / 60)
    for key, m in pairs(apps) do
        for coro, data in pairs(m.running_funs) do
            local request_handler, request, client_data = data[1], data[2], data[3]
            local client = client_data
            local request_result = nil

            local ok, ok2, result = pcall(coroutine.resume, coro, request.args, client)
            if result then
                if not ok then
                    if request_handler.error_handler then
                        request_handler.error_handler(tostring(ok2))
                    end
                    request_result = { response = { request = request.path, error = tostring(ok2), time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil } }
                end

                if not ok2 then
                    if request_handler.error_handler then
                        request_handler.error_handler(result)
                    end
                    request_result = { response = { request = request.path, error = tostring(result), time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil } }
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
                        request_result = { response = { request = request.path, error = err_msg, time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil } }
                    end
                end

                if not request_result then
                    request_result = { response = { request = request.path, response = result, time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil } }
                end

                if request_result and request_result.response then
                    local response = request_result.response
                    local ok, send_err = pcall(function()
                        client:send(json.encode(response))
                    end)
                    if not ok then
                        print("Error in async request: " .. send_err .. "  id:" ..
                        response.id .. "  path:" .. response.request)
                    end
                    m.running_funs[coro] = nil
                end
            end
        end

        m.socket.update(m.server, dt)

        local messages = m.socket.receive_message(m.server)
        for _, msg in ipairs(messages) do
            local data, ip, port = msg.message, msg.ip, msg.port
            local client_key = ip .. ":" .. port

            if not m.clients[client_key] then
                m.ip_counts[ip] = (m.ip_counts[ip] or 0) + 1
                if m.ip_counts[ip] <= m.max_ip_connected then
                    m.clients[client_key] = m.socket.new_connect(m.server, ip, port)
                    m.clients[client_key].lastActive = os.time()
                    if m.debug then
                        print("app: " .. m.name, "New client connected ip: " .. ip .. ", port: " .. port)
                    end
                    if m.new_client then
                        local ok, cb_err = pcall(m.new_client, { ip = ip, port = port })
                        if not ok then
                            handle_error(m, "Error in new_client callback: " .. cb_err)
                        end
                    end
                else
                    print("Rejected connection from " ..
                    ip .. ":" .. port .. ": max connections (" .. m.max_ip_connected .. ") reached")
                    m.ip_counts[ip] = m.ip_counts[ip] - 1
                    m.socket.send_message(json.encode({ error = "Max connections reached", __luna = true }), ip, port)
                end
            else
                m.clients[client_key].lastActive = os.time()
            end

            if m.clients[client_key] then
                if data ~= "ping" then
                    if m.debug then
                        print("app: " .. m.name, client_key, data)
                    end
                    if m.request_listener then
                        m.request_listener(data)
                    end

                    local response
                    for _, router_data in pairs(m.routers) do
                        local res = router_data:process(m.clients[client_key], data)
                        if res then
                            response = res
                            break
                        end
                    end

                    local response_to_send
                    if type(response) == "table" and (response.request or response.error or response.response or response.id) then
                        response_to_send = response
                    else
                        response_to_send = { no_responce = true }
                    end

                    if not response_to_send.no_responce then
                        local ok, send_err = pcall(function()
                            m.clients[client_key]:send(json.encode(response_to_send), dt)
                        end)
                        if not ok then
                            handle_error(m, "Error sending data to client " .. client_key .. ": " .. send_err)
                        end
                    end
                end
            end
        end

        local currentTime = os.time()
        for client_key, client in pairs(m.clients) do
            if currentTime - client.lastActive > TIMEOUT_SECONDS then
                if m.debug then
                    print("app: " .. m.name, "Client disconnected ip: " .. client.ip ..
                    ":" .. client.port .. " due to timeout")
                end
                m.ip_counts[client.ip] = (m.ip_counts[client.ip] or 1) - 1
                if m.ip_counts[client.ip] <= 0 then
                    m.ip_counts[client.ip] = nil
                end
                m.clients[client_key]:close()
                m.clients[client_key] = nil
                if m.close_client then
                    local ok, cb_err = pcall(m.close_client, { ip = client.ip, port = client.port })
                    if not ok then
                        handle_error(m, "Error in close_client callback: " .. cb_err)
                    end
                end
            end
        end
    end
end

return app
