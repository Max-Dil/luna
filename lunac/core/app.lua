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
local json = require("lunac.libs.json")
local message_manager = require("lunac.libs.udp_messages")
local security = require("lunac.libs.security")

local app = {}
local apps = {}

local encrypt_message = function(app_data, message)
    if app_data.shared_secret and app_data.nonce then
        local success, err = pcall(security.chacha20.encrypt, message,
            app_data.shared_secret, app_data.nonce)
        if success then
            err = err:match("^(.-)%z*$") or err
        end
        return success, err
    else
        return false, "Error not found connect args"
    end
end

local decrypt_message = function(app_data, message)
    return encrypt_message(app_data, message)
end

local function parse_response(line)
    local ok, result = pcall(json.decode, line)
    if ok and type(result) == "table" then
        return result
    end
    return { request = "unknown", response = line, id = "unknown id", time = 0 }
end

local function try_connect(app_data)
    local client, err = socket.udp()
    if client then
        app_data.pending_noawait_requests = {}
        app_data.pending_requests = {}
        client:setsockname(app_data.host, 0)
        client:settimeout(0)
        app_data.client = client
        app_data.connected = true
        app_data.trying_to_reconnect = false

        ---------------- Подключение ---------------
        app_data.nonce = nil
        app_data.shared_secret = nil

        app_data.no_server_decrypt = true
        local TIMEOUT = 5
        local start_time

        local success, err = pcall(app_data.socket.send_message, "pls connect", app_data.host, app_data.port)
        if not success then
            app_data.error_handler("Init send failed: " .. err)
            app_data.connected = false
            app_data.trying_to_reconnect = true
            app_data.client = nil
            return false
        end

        local server_pub, token, nonce
        local error_message
        app_data.pending_noawait_requests["handshake"] = {
            path = "handshake",
            timestamp = 0,
            callback = function(data, err)
                if data then
                    local success, decoded = pcall(json.decode, data)
                    if success then
                        if decoded.pub and decoded.token and decoded.nonce then
                            server_pub, token, nonce = security.utils.string_to_key(decoded.pub), decoded.token,
                                decoded.nonce
                        else
                            error_message = "Error not found connect args"
                        end
                    else
                        error_message = decoded
                    end
                else
                    error_message = err
                end
            end
        }

        start_time = socket.gettime()
        while not (token and server_pub and nonce) and (socket.gettime() - start_time < TIMEOUT) and not error_message do
            if app_data.server then app_data.server.update(1 / 60) end
            app.update(1 / 60)
            socket.sleep(0.001)
        end

        if error_message then
            app_data.error_handler("handshake: " .. error_message)
            app_data.connected = false
            app_data.trying_to_reconnect = true
            app_data.client = nil
            return false
        end

        app_data.nonce = security.base64.decode(nonce)
        app_data.shared_secret = security.utils.key_to_string(security.x25519.get_shared_key(app_data.client_private, server_pub))

        success, err = pcall(app_data.socket.send_message,
            "client_pub" .. security.utils.key_to_string(app_data.client_public) .. "|" .. token,
            app_data.host, app_data.port)
        if not success then
            app_data.error_handler("Client pub send failed: " .. err)
            return false
        end

        local connect, error_message
        app_data.pending_noawait_requests["connect"] = {
            path = "connect",
            timestamp = 0,
            callback = function(data, err)
                if data then
                    connect = true
                else
                    error_message = err
                end
            end
        }

        start_time = socket.gettime()
        while not connect and (socket.gettime() - start_time < TIMEOUT) and not error_message do
            if app_data.server then app_data.server.update(1 / 60) end
            app.update(1 / 60)
            socket.sleep(0.001)
        end

        if error_message then
            app_data.error_handler("connect: " .. error_message)
            app_data.connected = false
            app_data.trying_to_reconnect = true
            app_data.client = nil
            return false
        end

        local client_token = security.chacha20.encrypt(app_data.client_token, app_data.shared_secret, app_data.nonce)
        success, err = pcall(app_data.socket.send_message,
            "client_tok" .. client_token,
            app_data.host, app_data.port)
        if not success then
            app_data.error_handler("Client token send failed: " .. err)
            return false
        end

        connect, error_message = nil, nil
        app_data.pending_noawait_requests["connect"] = {
            path = "connect",
            timestamp = 0,
            callback = function(data, err)
                if data then
                    connect = true
                else
                    error_message = err
                end
            end
        }

        start_time = socket.gettime()
        while not connect and (socket.gettime() - start_time < TIMEOUT) and not error_message do
            if app_data.server then app_data.server.update(1 / 60) end
            app.update(1 / 60)
            socket.sleep(0.001)
        end

        if error_message then
            app_data.error_handler("connect client token: " .. error_message)
            app_data.connected = false
            app_data.trying_to_reconnect = true
            app_data.client = nil
            return false
        end

        print("Successfully new security CONNECTION")
        app_data.no_server_decrypt = nil
        --------------------------------------------

        if type(jit) ~= "table" then
            start_time = socket.gettime()
            while (socket.gettime() - start_time < 0.1) do socket.sleep(0.001) end
        end

        print("Initialized UDP client for " .. app_data.host .. ":" .. app_data.port)
        if app_data.connect_server then
            local ok, cb_err = pcall(app_data.connect_server)
            if not ok then
                app_data.error_handler("Error in connect_server callback: " .. cb_err)
            end
        end
        return true
    else
        if not app_data.trying_to_reconnect then
            app_data.error_handler("UDP socket creation failed: " .. err)
            if app_data.reconnect_time then
                app_data.trying_to_reconnect = true
                app_data.reconnect_timer = 0
            end
        end
        return false
    end
end

local function serialize_request(args, app_data, request_id, timestamp, request, noawait)
    local arg_parts = {}
    for k, v in pairs(args) do
        local text
        if type(v) == "string" then
            text = "'" .. v .. "'"
        elseif type(v) == "number" then
            text = v
        elseif type(v) == "table" then
            local s, e = pcall(json.encode, v)
            if not s then
                if app_data.no_errors then
                    app_data.error_handler("Serialization failed: " .. e)
                    return nil, e or "Failed to serialize request"
                else
                    error("Serialization failed: " .. e, 2)
                end
            end
            text = "<json='" .. e .. "'>"
        elseif type(v) == "boolean" then
            if v then
                text = "True"
            else
                text = "False"
            end
        else
            text = "'no support " .. type(v) .. "'"
            error("'no support " .. type(v) .. "'", 2)
        end
        table.insert(arg_parts, string.format(k .. "=" .. text))
    end
    table.insert(arg_parts, "__id='" .. request_id .. "'")
    table.insert(arg_parts, "__time='" .. timestamp .. "'")
    table.insert(arg_parts, "__client_token='" .. app_data.client_token .. "'")
    if noawait then
        table.insert(arg_parts, "__noawait=True")
    end
    request = request .. " " .. table.concat(arg_parts, " ")
    return request
end

local class = {
    fetch = function(app_data, path, args, timeout)
        if type(app_data) == "string" then
            app_data = apps[app_data]
        end

        if not app_data or not app_data.connected then
            if app_data and app_data.no_errors then
                app_data.error_handler("Not connected to server")
                return nil, "Not connected to server"
            else
                error("Not connected to server", 2)
            end
        end

        local request_id = security.utils.uuid()
        local timestamp = tostring(os.time())

        local request = path
        if args then
            request = serialize_request(args, app_data, request_id, timestamp, request, false)
            if not request then
                return nil, "Failed to serialize request"
            end
        end

        app_data.pending_requests = app_data.pending_requests or {}
        app_data.pending_requests[request_id] = {
            path = path,
            timestamp = timestamp,
            start_time = socket.gettime()
        }

        local success, err = encrypt_message(app_data, request)
        if not success then
            app_data.pending_requests[request_id] = nil
            if app_data.no_errors then
                app_data.error_handler("Encrypt failed: " .. err)
                return nil, err or "Failed to encrypt request"
            else
                error("Encrypt failed: " .. err, 2)
            end
        end
        local message = err

        success, err = pcall(app_data.socket.send_message, message, app_data.host, app_data.port)
        if not success then
            app_data.pending_requests[request_id] = nil
            if app_data.no_errors then
                app_data.error_handler("Send failed: " .. err)
                return nil, err or "Failed to send request"
            else
                error("Send failed: " .. err, 2)
            end
        end

        local start_time = socket.gettime()
        timeout = timeout or 5

        local final_response = nil
        local final_error = nil

        while true do
            if app_data.server then
                app_data.server.update(app_data.dt)
            end

            if not app_data.connected then
                if app_data.reconnect_time then
                    if try_connect(app_data) then
                        success, err = pcall(app_data.socket.send_message, app_data.client, message, app_data.host,
                            app_data.port, app_data.dt)
                        if not success then
                            app_data.pending_requests[request_id] = nil
                            return nil, err or "Failed to resend request after reconnect"
                        end
                    else
                        app_data.pending_requests[request_id] = nil
                        return nil, "Disconnected and reconnect failed"
                    end
                else
                    app_data.pending_requests[request_id] = nil
                    return nil, "Disconnected"
                end
            end

            app_data.socket.update(app_data.client, app_data.dt)

            local messages = app_data.socket.receive_message(app_data.client)
            for _, msg in pairs(messages) do
                if app_data.no_server_decrypt then
                    success, err = true, msg.message
                else
                    success, err = decrypt_message(app_data, msg.message)
                end
                if success then
                    local request_message = err

                    local response = parse_response(request_message)

                    if response.__luna and response.request == path and response.id == request_id and response.time == timestamp then
                        app_data.pending_requests[request_id] = nil
                        if response.error then
                            final_error = response.error
                        else
                            final_response = response.response
                        end
                    elseif response.__luna and response.__noawait then
                        if app_data.pending_noawait_requests and app_data.pending_noawait_requests[response.id] and app_data.pending_noawait_requests[response.id].timestamp == response.time then
                            local callback = app_data.pending_noawait_requests[response.id].callback
                            app_data.pending_noawait_requests[response.id] = nil
                            if callback then
                                if response.error then
                                    callback(nil, response.error)
                                else
                                    callback(response.response, nil)
                                end
                            end
                        end
                    elseif request_message == "__luna__close" then
                        if app_data.connected then
                            app_data.client:close()
                            app_data.connected = false
                            app_data.trying_to_reconnect = true
                            app_data.pending_requests = {}
                            app_data.shared_secret = nil
                            print("Disconnected from " .. app_data.host .. ":" .. app_data.port)
                        end
                        break
                    else
                        if app_data.listener and not response.__luna then
                            app_data.listener(request_message)
                        end
                    end
                end
            end

            if final_response or final_error or app_data.client.is_close then
                break
            end

            if socket.gettime() - start_time > timeout then
                app_data.pending_requests[request_id] = nil
                if app_data.no_errors then
                    app_data.error_handler("Request timed out")
                    return nil, "Request timed out"
                else
                    error("Request timed out", 2)
                end
            end
            socket.sleep(0.001)
        end

        if final_error then
            return nil, final_error
        end
        return final_response
    end,

    noawait_fetch = function(app_data, path, callback, args)
        if type(app_data) == "string" then
            app_data = apps[app_data]
        end

        if not app_data or not app_data.connected then
            if app_data and app_data.no_errors then
                app_data.error_handler("Not connected to server")
                return nil, "Not connected to server"
            else
                error("Not connected to server", 2)
            end
        end

        local request_id = security.utils.uuid()
        local timestamp = tostring(os.time())

        local request = path
        if args then
            request = serialize_request(args, app_data, request_id, timestamp, request, true)
            if not request then
                return nil, "Failed to serialize request"
            end
        end

        app_data.pending_noawait_requests = app_data.pending_noawait_requests or {}
        app_data.pending_noawait_requests[request_id] = {
            path = path,
            timestamp = timestamp,
            callback = callback
        }

        local success, err = encrypt_message(app_data, request)
        if not success then
            app_data.pending_requests[request_id] = nil
            if app_data.no_errors then
                app_data.error_handler("Encrypt failed: " .. err)
                return nil, err or "Failed to encrypt request"
            else
                error("Encrypt failed: " .. err, 2)
            end
        end
        local message = err

        success, err = pcall(app_data.socket.send_message, message, app_data.host, app_data.port)
        if not success then
            app_data.pending_noawait_requests[request_id] = nil
            if app_data.no_errors then
                app_data.error_handler("Send failed: " .. err)
                return nil, err or "Failed to send request"
            else
                error("Send failed: " .. err, 2)
            end
        end

        return request_id
    end,
}

app.connect = function(config)
    if not config.host then
        error("Error connect to app unknown host, app_name: " .. config.name, 2)
    end

    local client_token = security.utils.uuid()
    local client_private, client_public = security.x25519.generate_keypair()

    local app_data
    app_data = setmetatable({
        name = config.name or "unknown name",
        host = config.host,
        port = config.port or 433,
        no_errors = config.no_errors,
        error_handler = config.error_handler or function(message)
            print("Error in app '" .. config.name .. "': " .. message)
        end,
        listener = config.listener,
        connected = false,
        client = nil,
        server = config.server,
        reconnect_time = config.reconnect_time,
        reconnect_timer = 0,
        trying_to_reconnect = false,
        pending_requests = {},
        pending_noawait_requests = {},
        connect_server = config.connect_server,
        disconnect_server = config.disconnect_server,
        dt = 1 / 60,
        socket = message_manager(),
        set_max_message_size = function(new_max_messages_size)
            app_data.socket.set_max_messages_size(new_max_messages_size)
        end,
        set_max_retries = function(new_max_retries)
            app_data.socket.set_max_retries(new_max_retries)
        end,
        set_message_timeout = function(new_message_timeout)
            app_data.socket.set_message_timeout(new_message_timeout)
        end,

        client_token = client_token,
        client_private = client_private,
        client_public = client_public,
    }, { __index = class })

    apps[app_data.name] = app_data

    if not try_connect(app_data) and not app_data.reconnect_time then
        if not app_data.no_errors then
            error("UDP socket creation failed", 2)
        end
        return nil
    end

    return app_data
end

app.update = function(dt)
    dt = dt or (1 / 60)
    for name, app_data in pairs(apps) do
        app_data.dt = dt
        if app_data.connected then
            app_data.socket.update(app_data.client, dt)

            local messages = app_data.socket.receive_message(app_data.client)
            for _, msg in pairs(messages) do
                local success, err = true, msg.message
                if not app_data.no_server_decrypt then
                    success, err = decrypt_message(app_data, msg.message)
                end

                if success then
                    local request_message = err
                    local response = parse_response(request_message)

                    if response.__luna and response.__noawait and app_data.pending_noawait_requests and app_data.pending_noawait_requests[response.id] and app_data.pending_noawait_requests[response.id].timestamp == response.time then
                        local callback = app_data.pending_noawait_requests[response.id].callback
                        app_data.pending_noawait_requests[response.id] = nil
                        if callback then
                            if response.error then
                                callback(nil, response.error)
                            else
                                callback(response.response, nil)
                            end
                        end
                    elseif response.__luna and app_data.pending_requests and app_data.pending_requests[response.id] and app_data.pending_requests[response.id].timestamp == response.time then
                        app_data.pending_requests[response.id] = nil
                    elseif request_message == "__luna__close" then
                        if app_data.connected then
                            app_data.client:close()
                            app_data.connected = false
                            app_data.trying_to_reconnect = true
                            app_data.pending_requests = {}
                            app_data.shared_secret = nil
                            print("Disconnected from " .. app_data.host .. ":" .. app_data.port)
                        end
                    elseif app_data.listener then
                        app_data.listener(request_message)
                    end
                end
            end

            local current_time = socket.gettime()
            for request_id, req_data in pairs(app_data.pending_requests or {}) do
                if current_time - req_data.start_time > (req_data.timeout or 5) then
                    app_data.pending_requests[request_id] = nil
                    app_data.error_handler("Request timed out: " .. req_data.path)
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

    local success, err = pcall(app_data.socket.send_message, data, app_data.host, app_data.port)
    if not success then
        if app_data.no_errors then
            app_data.error_handler("Send failed: " .. err)
            return false
        else
            error("Send failed: " .. err, 2)
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
        print("Disconnected from " .. app_data.host .. ":" .. app_data.port)
    end

    if app_data.disconnect_server then
        local ok, cb_err = pcall(app_data.disconnect_server, "Close server")
        if not ok then
            app_data.error_handler("Error in disconnect_server callback: " .. cb_err)
        end
    end

    app_data.pending_requests = {}
    app_data.pending_noawait_requests = {}
    apps[app_data.name] = nil
end

return app
