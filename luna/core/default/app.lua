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

local socket, router, json, message_manager, security =
    require("socket"),
    require("luna.core.default.router"),
    require("luna.libs.json"),
    require("luna.libs.udp_messages"),
    require("luna.libs.security")

local type, pairs, pcall, error, setmetatable, tostring, tonumber, coroutine, table, string =
    type, pairs, pcall, error, setmetatable, tostring, tonumber, coroutine, table, string

local app, apps = {}, {}

local function handle_error(app_data, message, err_level)
    if app_data.no_errors then
        if app_data.error_handler then
            app_data.error_handler(message)
        end
    else
        error(message, err_level or 2)
    end
end

local encrypt_message = function(app_data, message)
    if app_data.shared_secret and app_data.nonce then
        local success, err = pcall(security.chacha20.encrypt, message,
            app_data.shared_secret, app_data.nonce)
        if success then
            err = err:match("^(.-)%z*$") or err
            success, err = pcall(security.base64.encode, err)
        end
        return success, err
    else
        return false, "Error not found connect args"
    end
end

local decrypt_message = function(app_data, message)
    if app_data.shared_secret and app_data.nonce then
        local success, err = pcall(security.base64.decode, message)
        if success then
            success, err = pcall(security.chacha20.encrypt, err,
                app_data.shared_secret, app_data.nonce)
            if success then
                err = err:match("^(.-)%z*$") or err
            end
        end
        return success, err
    else
        return false, "Error not found connect args"
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
int disconnect_time

boolean encryption
]]
app.new_app = function(config)
    local app_data
    if config.debug == nil then
        config.debug = true
    end

    config.encryption = config.encryption == nil and true or config.encryption
    local server_private, server_public
    if config.encryption then
        server_private, server_public = security.x25519.generate_keypair()
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
        timeout_client = config.timeout_client,

        request_listener = config.request_listener,

        clients = {},
        ip_counts = {},
        routers = {},

        running_funs = {},

        get_clients = function()
            local clients = {}
            for key, value in pairs(app_data.clients) do
                table.insert(clients, value)
            end
            return clients
        end,

        debug = config.debug,

        set_max_message_size = function(new_max_messages_size)
            app_data.socket.set_max_messages_size(new_max_messages_size)
        end,
        set_max_retries = function(new_max_retries)
            app_data.socket.set_max_retries(new_max_retries)
        end,
        set_message_timeout = function(new_message_timeout)
            app_data.socket.set_message_timeout(new_message_timeout)
        end,

        server_private = server_private,
        server_public = server_public,

        disconnect_time = config.disconnect_time or 10,

        set_disconnect_time = function(new_time)
            app_data.disconnect_time = new_time
        end,

        encryption = config.encryption,
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
    else
        if app_data.debug then
            print("App '" .. app_data.name .. "' started on " .. app_data.host .. ":" .. app_data.port)
        end
        if apps[app_data.name] then
            handle_error(app_data, "An application with that name already exists.", 2)
            return
        end
        apps[app_data.name] = app_data
    end

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

    for _, client_data in pairs(app_data.clients) do
        client_data:close()
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

app.close = function()
    for name, app_data in pairs(apps) do
        app.remove(app_data)
    end
end

local function validate_value(value, expected_types)
    if value == nil then
        for _, t in pairs(expected_types) do
            if t == "nil" then
                return true
            end
        end
        return false
    end

    local actual_type = type(value)

    for _, expected_type in pairs(expected_types) do
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
            local request_handler, request, client, request_result = data[1], data[2], data[3], nil

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

                if not request_result and request_handler.response_validate then
                    if not validate_value(result, request_handler.response_validate) then
                        local expected_str = table.concat(request_handler.response_validate, " or ")
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
                    if not client.is_close then
                        local response = request_result.response
                        local ok, send_err = pcall(function()
                            client:send(json.encode(response))
                        end)
                        if not ok then
                            print("Error in async request: " .. send_err .. "  id:" ..
                                response.id .. "  path:" .. response.request)
                        end
                    end
                    m.running_funs[coro] = nil
                end
            end
        end

        m.socket.update(m.server, dt)

        local messages = m.socket.receive_message(m.server)
        local currentTime = os.time()
        for _, msg in pairs(messages) do
            local data, ip, port = msg.message, msg.ip, msg.port
            local client_key = ip .. ":" .. port
            local client = m.clients[client_key]

            if not client then
                if not ip:match("^%d+%.%d+%.%d+%.%d+$") then
                    handle_error(m, "The client's IP address is invalid", 2)
                end
                m.ip_counts[ip] = (m.ip_counts[ip] or 0) + 1
                if m.ip_counts[ip] <= m.max_ip_connected then
                    client = m.socket.new_connect(m.server, ip, port)
                    m.clients[client_key] = client
                    client.lastActive = currentTime

                    if m.encryption then
                        client.auth_token = security.utils.uuid()
                        local nonce = security.base64.encode(security.utils.generate_nonce())
                        client.nonce = security.base64.decode(nonce)

                        client.__send = client.send
                        client.send = function(self, data)
                            local success, message = encrypt_message(client, data)
                            if success then
                                pcall(self.__send, self, message)
                            end
                        end

                        local ok, send_err = pcall(function()
                            client:__send(json.encode({
                                __luna = true,
                                request = "handshake",
                                response = json.encode({
                                    pub = security.utils.key_to_string(m.server_public),
                                    token = client.auth_token,
                                    nonce = nonce
                                }),
                                id = "handshake",
                                time = 0,
                                __noawait = true,
                            }))
                        end)

                        if not ok then
                            handle_error(m, "Error sending handshake: " .. send_err)
                        end
                    end

                    client.__close = client.close
                    client.close = function(self)
                        pcall(self.send, self, "__luna__close")
                        self.__close()
                        if self.is_close then
                            if m.debug then
                                print("app: " .. m.name, "Client disconnected ip: " .. self.ip ..
                                    ":" .. self.port)
                            end
                            m.ip_counts[self.ip] = (m.ip_counts[self.ip] or 1) - 1
                            if m.ip_counts[self.ip] <= 0 then
                                m.ip_counts[self.ip] = nil
                            end
                            if m.close_client then
                                local ok, cb_err = pcall(m.close_client, self)
                                if not ok then
                                    handle_error(m, "Error in close_client callback: " .. cb_err)
                                end
                            end
                            m.clients[self.ip .. ":" .. self.port] = nil
                            self = nil
                        end
                    end
                    if m.debug then
                        print("app: " .. m.name, "New client connected ip: " .. ip .. ", port: " .. port)
                    end
                    if m.new_client then
                        local ok, cb_err = pcall(m.new_client, client)
                        if not ok then
                            handle_error(m, "Error in new_client callback: " .. cb_err)
                        end
                    end
                else
                    print("Rejected connection from " ..
                        ip .. ":" .. port .. ": max connections (" .. m.max_ip_connected .. ") reached")
                    m.ip_counts[ip] = m.ip_counts[ip] - 1
                    local success, message
                    if m.encryption then
                        success, message = encrypt_message(client,
                        json.encode({ error = "Max connections reached", __luna = true }))
                    else
                        success, message = true, json.encode({ error = "Max connections reached", __luna = true })
                    end
                    if success then
                        m.socket.send_message(message, ip, port)
                    end
                end
            end

            if client then
                client.lastActive = currentTime
                if client.auth_token then
                    local name = string.sub(data, 1, 10)
                    local params = string.sub(data, 11, string.len(data))

                    if name and params then
                        if name == "client_pub" then
                            local args = security.utils.split(params, "|")
                            local client_pub, auth_token = args[1], args[2]

                            if auth_token == client.auth_token then
                                client_pub = security.utils.string_to_key(client_pub)
                                client.shared_secret = security.utils.key_to_string(security.x25519.get_shared_key(
                                m.server_private, client_pub))
                                local ok, send_err = pcall(function()
                                    client:__send(json.encode({
                                        __luna = true,
                                        request = "connect",
                                        response = true,
                                        id = "connect",
                                        time = 0,
                                        __noawait = true,
                                    }))
                                end)
                                if not ok then
                                    handle_error(m, "Error sending connect: " .. send_err)
                                end
                            end
                        elseif name == "client_tok" then
                            if client.shared_secret and client.nonce then
                                local success, decrypted = decrypt_message(client, params)
                                if success and decrypted then
                                    client.auth_token = nil
                                    client.token = decrypted

                                    local ok, send_err = pcall(function()
                                        client:__send(json.encode({
                                            __luna = true,
                                            request = "connect",
                                            response = true,
                                            id = "connect",
                                            time = 0,
                                            __noawait = true,
                                        }))
                                    end)
                                    if not ok then
                                        handle_error(m, "Error sending token connect: " .. send_err)
                                    end
                                end
                            end
                        end
                    end
                else
                    local success, err
                    if m.encryption then
                        success, err = decrypt_message(client, data)
                    else
                        success, err = true, data
                    end
                    if success and err then
                        data = err
                        if m.debug then
                            print("app: " .. m.name, client_key, data)
                        end

                        if m.request_listener then
                            m.request_listener(data, client)
                        end

                        if not client.is_close then
                            local response
                            for _, router_data in pairs(m.routers) do
                                local res = router_data:process(client, data)
                                if res then
                                    response = res
                                    break
                                end
                            end

                            if not client.is_close then
                                local response_to_send
                                if type(response) == "table" and (response.request or response.error or response.response or response.id) then
                                    response_to_send = response
                                else
                                    response_to_send = { no_response = true }
                                end

                                if not response_to_send.no_response then
                                    local ok, send_err = pcall(function()
                                        client:send(json.encode(response_to_send))
                                    end)
                                    if not ok then
                                        handle_error(m, "Error sending data to client " .. client_key .. ": " .. send_err)
                                    end
                                end
                            end
                        else
                            handle_error(m,
                                "Error sending data to client " .. client_key .. ": " .. (err or "unknown decrypt error"))
                        end
                    end
                end
            end
        end

        for client_key, client in pairs(m.clients) do
            if currentTime - client.lastActive > m.disconnect_time then
                if m.timeout_client then
                    local r = m.timeout_client(client, currentTime - client.lastActive, m.disconnect_time)
                    if r or r == nil then
                        if m.debug then
                            print("app: " .. m.name, "Client disconnected ip: " .. client.ip ..
                                ":" .. client.port .. " <due to timeout>", "Time: " .. currentTime - client.lastActive,
                                "disconnect_time: " .. m.disconnect_time, "currentTime: " .. currentTime)
                        end
                        m.clients[client_key]:close()
                    else
                        client.lastActive = currentTime
                    end
                else
                    if m.debug then
                        print("app: " .. m.name, "Client disconnected ip: " .. client.ip ..
                            ":" .. client.port .. " <due to timeout>", "Time: " .. currentTime - client.lastActive,
                            "disconnect_time: " .. m.disconnect_time, "currentTime: " .. currentTime)
                    end
                    m.clients[client_key]:close()
                end
            end
        end
    end
end

return app
