-- Lupack: Packed code
-- Entry file: lunac
-- Generated: 14.10.2025, 22:39:18

local __lupack__ = {}
local __orig_require__ = require
local require = function(path)
  if __lupack__[path] then
    return __lupack__[path]()
  elseif __lupack__[path..".init"] then
    return __lupack__[path..".init"]()
  end
  return __orig_require__(path)
end


-- lunac/core/default/app.lua
__lupack__["lunac.core.default.app"] = function()
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

local socket, json, message_manager, security =
    require("socket"),
    require("lunac.libs.json"),
    require("lunac.libs.udp_messages"),
    require("lunac.libs.security")

local print, error, tostring, type, pairs, pcall, setmetatable, security_chacha20_encrypt,
    security_base64_encode, security_base64_decode, json_decode, security_utils_string_to_key,
    socket_gettime, socket_sleep, security_utils_key_to_string, security_x25519_get_shared_key,
    json_encode, table_insert, string_format, table_concat, security_utils_uuid, os_time,
    security_x25519_generate_keypair =
        print, error, tostring, type, pairs, pcall, setmetatable, security.chacha20.encrypt,
        security.base64.encode, security.base64.decode, json.decode, security.utils.string_to_key,
        socket.gettime, socket.sleep, security.utils.key_to_string, security.x25519.get_shared_key,
        json.encode, table.insert, string.format, table.concat, security.utils.uuid, os.time,
        security.x25519.generate_keypair

local app, apps = {}, {}

local encrypt_message = function(app_data, message)
    if app_data.shared_secret and app_data.nonce then
        local success, err = pcall(security_chacha20_encrypt, message,
            app_data.shared_secret, app_data.nonce)
        if success then
            err = err:match("^(.-)%z*$") or err
            success, err = pcall(security_base64_encode, err)
        end
        return success, err
    else
        return false, "Error not found connect args"
    end
end

local decrypt_message = function(app_data, message)
    if app_data.shared_secret and app_data.nonce then
        local success, err = pcall(security_base64_decode, message)
        if success then
            success, err = pcall(security_chacha20_encrypt, err,
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

local function parse_response(line)
    local ok, result = pcall(json_decode, line)
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

        if app_data.encryption then
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
                        local success, decoded = pcall(json_decode, data)
                        if success then
                            if decoded.pub and decoded.token and decoded.nonce then
                                server_pub, token, nonce = security_utils_string_to_key(decoded.pub), decoded.token,
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

            start_time = socket_gettime()
            while not (token and server_pub and nonce) and (socket_gettime() - start_time < TIMEOUT) and not error_message do
                if app_data.server then app_data.server.update(1 / 60) end
                app.update(1 / 60)
                socket_sleep(0.001)
            end

            if error_message then
                app_data.error_handler("handshake: " .. error_message)
                app_data.connected = false
                app_data.trying_to_reconnect = true
                app_data.client = nil
                return false
            end

            app_data.nonce = security_base64_decode(nonce)
            app_data.shared_secret = security_utils_key_to_string(security_x25519_get_shared_key(app_data.client_private,
                server_pub))

            success, err = pcall(app_data.socket.send_message,
                "client_pub" .. security_utils_key_to_string(app_data.client_public) .. "|" .. token,
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

            start_time = socket_gettime()
            while not connect and (socket_gettime() - start_time < TIMEOUT) and not error_message do
                if app_data.server then app_data.server.update(1 / 60) end
                app.update(1 / 60)
                socket_sleep(0.001)
            end

            if error_message then
                app_data.error_handler("connect: " .. error_message)
                app_data.connected = false
                app_data.trying_to_reconnect = true
                app_data.client = nil
                return false
            end

            local client_token = security_chacha20_encrypt(app_data.client_token, app_data.shared_secret, app_data.nonce)
            client_token = client_token:match("^(.-)%z*$") or client_token
            client_token = security_base64_encode(client_token)
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

            start_time = socket_gettime()
            while not connect and (socket_gettime() - start_time < TIMEOUT) and not error_message do
                if app_data.server then app_data.server.update(1 / 60) end
                app.update(1 / 60)
                socket_sleep(0.001)
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

            app_data.client_connect = app_data.socket.new_connect(app_data.client, app_data.host, app_data.port)
            --------------------------------------------
        else
            app_data.no_server_decrypt = true
            app_data.client_connect = app_data.socket.new_connect(app_data.client, app_data.host, app_data.port)
        end

        local start_time = socket_gettime()
        while (socket_gettime() - start_time < 0.1) do socket_sleep(0.001) end

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
            local s, e = pcall(json_encode, v)
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
        table_insert(arg_parts, string_format(k .. "=" .. text))
    end
    table_insert(arg_parts, "__id='" .. request_id .. "'")
    table_insert(arg_parts, "__time='" .. timestamp .. "'")
    if app_data.encryption then
        table_insert(arg_parts, "__client_token='" .. app_data.client_token .. "'")
    end
    if noawait then
        table_insert(arg_parts, "__noawait=True")
    end
    request = request .. " " .. table_concat(arg_parts, " ")
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

        local request_id = security_utils_uuid()
        local timestamp = tostring(os_time())

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
            start_time = socket_gettime()
        }

        local success, err
        if app_data.encryption then
            success, err = encrypt_message(app_data, request)
        else
            success, err = true, request
        end
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

        local start_time = socket_gettime()
        timeout = timeout or 5

        local final_response, final_error
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
                            if app_data.client_connect then
                                app_data.client_connect:close()
                            else
                                pcall(function() app_data.client:close() end)
                            end
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

            if final_response or final_error or (app_data.client_connect and app_data.client_connect.is_close) then
                break
            end

            if socket_gettime() - start_time > timeout then
                app_data.pending_requests[request_id] = nil
                if app_data.no_errors then
                    app_data.error_handler("Request timed out")
                    return nil, "Request timed out"
                else
                    error("Request timed out", 2)
                end
            end
            socket_sleep(0.001)
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

        local request_id = security_utils_uuid()
        local timestamp = tostring(os_time())

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

        local success, err
        if app_data.encryption then
            success, err = encrypt_message(app_data, request)
        else
            success, err = true, request
        end
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

    config.encryption = config.encryption == nil and true or config.encryption

    local client_token
    local client_private, client_public
    if config.encryption then
        local client_token_private = security_x25519_generate_keypair()
        client_token = security_base64_encode(security_utils_key_to_string(client_token_private))
        client_private, client_public = security_x25519_generate_keypair()
    end

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

        encryption = config.encryption,
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
                            if app_data.client_connect then
                                app_data.client_connect:close()
                            else
                                pcall(function() app_data.client:close() end)
                            end
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

            local current_time = socket_gettime()
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
        if app_data.client_connect then
            app_data.client_connect:close()
        else
            pcall(function() app_data.client:close() end)
        end
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

app.close_all = function()
    for name, app_data in pairs(apps) do
        app.close(app_data)
    end
end

return app

end

-- lunac/core/http/http.lua
__lupack__["lunac.core.http.http"] = function()
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

local luna, lunac
local socket                  = require("socket")
local url                     = require("socket.url")
local ltn12                   = require("ltn12")
local mime                    = require("mime")
local string                  = require("string")
local headers                 = require("socket.headers")
local base                    = _G
local table                   = require("table")
local _M                      = {}
local async_requests          = {}

_M.TIMEOUT                    = 60
_M.PORT                       = 80
_M.USERAGENT                  = socket._VERSION

local STATE_CONNECTING        = 1
local STATE_SENDING           = 2
local STATE_RECEIVING_STATUS  = 3
local STATE_RECEIVING_HEADERS = 4
local STATE_RECEIVING_BODY    = 5
local STATE_REDIRECTING       = 6
local STATE_COMPLETED         = 7
local STATE_ERROR             = 8

local function receiveheaders(sock, headers)
    local line, name, value, err
    headers = headers or {}
    line, err = sock:receive()
    if err then return nil, err end
    while line ~= "" do
        name, value = socket.skip(2, string.find(line, "^(.-):%s*(.*)"))
        if not (name and value) then return nil, "malformed reponse headers" end
        name      = string.lower(name)
        line, err = sock:receive()
        if err then return nil, err end
        while string.find(line, "^%s") do
            value = value .. line
            line, err = sock:receive()
            if err then return nil, err end
        end
        if headers[name] then
            headers[name] = headers[name] .. ", " .. value
        else
            headers[name] = value
        end
    end
    return headers
end

socket.sourcet["http-chunked"] = function(sock, headers)
    return base.setmetatable({
        getfd = function() return sock:getfd() end,
        dirty = function() return sock:dirty() end
    }, {
        __call = function()
            local line, err = sock:receive()
            if err then return nil, err end
            local size = base.tonumber(string.gsub(line, ";.*", ""), 16)
            if not size then return nil, "invalid chunk size" end
            if size > 0 then
                local chunk, err = sock:receive(size)
                if chunk then sock:receive() end
                return chunk, err
            else
                headers, err = receiveheaders(sock, headers)
                if not headers then return nil, err end
            end
        end
    })
end

socket.sinkt["http-chunked"] = function(sock)
    return base.setmetatable({
        getfd = function() return sock:getfd() end,
        dirty = function() return sock:dirty() end
    }, {
        __call = function(self, chunk, err)
            if not chunk then return sock:send("0\r\n\r\n") end
            local size = string.format("%X\r\n", string.len(chunk))
            return sock:send(size .. chunk .. "\r\n")
        end
    })
end

local metat = { __index = {} }

function _M.open(reqt)
    local sock, err = reqt:create()
    local c = socket.try(sock)
    local h = base.setmetatable({ c = c }, metat)
    h.try = socket.newtry(function() h:close() end)
    local to = reqt.timeout or _M.TIMEOUT
    if type(to) == "table" then
        h.try(c:settimeouts(
            to.connect or _M.TIMEOUT,
            to.send or _M.TIMEOUT,
            to.receive or _M.TIMEOUT))
    else
        h.try(c:settimeout(to))
    end
    return h
end

function metat.__index:sendrequestline(method, uri)
    local reqline = string.format("%s %s HTTP/1.1\r\n", method or "GET", uri)
    return self.try(self.c:send(reqline))
end

function metat.__index:sendheaders(tosend)
    local canonic = headers.canonic
    local h = "\r\n"
    for f, v in base.pairs(tosend) do
        h = (canonic[f] or f) .. ": " .. v .. "\r\n" .. h
    end
    self.try(self.c:send(h))
    return 1
end

function metat.__index:sendbody(headers, source, step)
    source = source or ltn12.source.empty()
    step = step or ltn12.pump.step
    local mode = "http-chunked"
    if headers["content-length"] then mode = "keep-open" end
    return self.try(ltn12.pump.all(source, socket.sink(mode, self.c), step))
end

function metat.__index:receivestatusline()
    local status, err, partial = self.c:receive(5)
    if err then
        return nil, err
    end
    if status ~= "HTTP/" then return nil, "invalid status" end
    local line, err, partial = self.c:receive("*l")
    if err then
        if err == "timeout" and partial then
            status = status .. partial
        else
            return nil, err
        end
    else
        status = status .. line
    end
    local code = socket.skip(2, string.find(status, "HTTP/%d*%.%d* (%d%d%d)"))
    return base.tonumber(code), status
end

function metat.__index:receiveheaders()
    return self.try(receiveheaders(self.c))
end

function metat.__index:receivebody(headers, sink, step)
    sink = sink or ltn12.sink.null()
    step = step or ltn12.pump.step
    local length = base.tonumber(headers["content-length"])
    local t = headers["transfer-encoding"]
    local mode = "default"
    if t and t ~= "identity" then
        mode = "http-chunked"
    elseif base.tonumber(headers["content-length"]) then
        mode = "by-length"
    end
    return self.try(ltn12.pump.all(socket.source(mode, self.c, length),
        sink, step))
end

function metat.__index:receive09body(status, sink, step)
    local source = ltn12.source.rewind(socket.source("until-closed", self.c))
    source(status)
    return self.try(ltn12.pump.all(source, sink, step))
end

function metat.__index:close()
    return self.c:close()
end

local function adjusturi(reqt)
    local u = reqt
    if not reqt.proxy and not _M.PROXY then
        u = {
            path = socket.try(reqt.path, "invalid path 'nil'"),
            params = reqt.params,
            query = reqt.query,
            fragment = reqt.fragment
        }
    end
    return url.build(u)
end

local function adjustproxy(reqt)
    local proxy = reqt.proxy or _M.PROXY
    if proxy then
        proxy = url.parse(proxy)
        return proxy.host, proxy.port or 3128
    else
        return reqt.host, reqt.port
    end
end

local function adjustheaders(reqt)
    local host = string.gsub(reqt.authority, "^.-@", "")
    local lower = {
        ["user-agent"] = _M.USERAGENT,
        ["host"] = host,
        ["connection"] = "close, TE",
        ["te"] = "trailers"
    }
    if reqt.user and reqt.password then
        lower["authorization"] =
            "Basic " .. (mime.b64(reqt.user .. ":" .. reqt.password))
    end
    for i, v in base.pairs(reqt.headers or lower) do
        lower[string.lower(i)] = v
    end
    return lower
end

local default = {
    host = "",
    port = _M.PORT,
    path = "/",
    scheme = "http"
}

local function adjustrequest(reqt)
    local nreqt = reqt.url and url.parse(reqt.url, default) or {}
    for i, v in base.pairs(reqt) do nreqt[i] = v end
    if nreqt.port == "" then nreqt.port = 80 end
    socket.try(nreqt.host and nreqt.host ~= "",
        "invalid host '" .. base.tostring(nreqt.host) .. "'")
    socket.try(nreqt.scheme == "http", "HTTPS not supported")
    nreqt.uri = reqt.uri or adjusturi(nreqt)
    nreqt.host, nreqt.port = adjustproxy(nreqt)
    nreqt.headers = adjustheaders(nreqt)
    return nreqt
end

local function shouldredirect(reqt, code, headers)
    return headers.location and
        string.gsub(headers.location, "%s", "") ~= "" and
        (reqt.redirect ~= false) and
        (code == 301 or code == 302 or code == 303 or code == 307) and
        (not reqt.method or reqt.method == "GET" or reqt.method == "HEAD")
        and (not reqt.nredirects or reqt.nredirects < 5)
end

local function shouldreceivebody(reqt, code)
    if reqt.method == "HEAD" then return nil end
    if code == 204 or code == 304 then return nil end
    if code >= 100 and code < 200 then return nil end
    return 1
end

local function create_async_request(reqt, callback)
    local nreqt = adjustrequest(reqt)
    nreqt.create = nreqt.create or _M.getcreatefunc(nreqt)

    local async_req = {
        reqt = reqt,
        callback = callback,
        state = STATE_CONNECTING,
        nreqt = nreqt,
        h = nil,
        result = nil,
        code = nil,
        headers = nil,
        status = nil,
        error = nil,
    }

    return async_req
end

local function process_async_request(async_req)
    if async_req.state == STATE_COMPLETED or async_req.state == STATE_ERROR then
        return true
    end

    local step_done = false

    while not step_done do
        if async_req.state == STATE_CONNECTING then
            local sock, err = async_req.nreqt.create(async_req.nreqt)
            if not sock then
                async_req.state = STATE_ERROR
                async_req.error = "Connection failed: " .. (err or "unknown error")
                break
            end

            async_req.h = base.setmetatable({ c = sock }, metat)
            async_req.h.try = socket.newtry(function()
                if async_req.h then
                    async_req.h:close()
                end
            end)

            local to = async_req.nreqt.timeout or _M.TIMEOUT
            if type(to) == "table" then
                sock:settimeouts(
                    to.connect or _M.TIMEOUT,
                    to.send or _M.TIMEOUT,
                    to.receive or _M.TIMEOUT
                )
            else
                sock:settimeout(to)
            end

            async_req.state = STATE_SENDING
            step_done = true
        elseif async_req.state == STATE_SENDING then
            local ok, err = async_req.h:sendrequestline(async_req.nreqt.method, async_req.nreqt.uri)
            if not ok then
                async_req.state = STATE_ERROR
                async_req.error = "Send request line failed: " .. (err or "unknown error")
                break
            end

            ok, err = async_req.h:sendheaders(async_req.nreqt.headers)
            if not ok then
                async_req.state = STATE_ERROR
                async_req.error = "Send headers failed: " .. (err or "unknown error")
                break
            end

            if async_req.nreqt.source then
                ok, err = async_req.h:sendbody(async_req.nreqt.headers, async_req.nreqt.source, async_req.nreqt.step)
                if not ok then
                    async_req.state = STATE_ERROR
                    async_req.error = "Send body failed: " .. (err or "unknown error")
                    break
                end
            end

            async_req.state = STATE_RECEIVING_STATUS
            step_done = true
        elseif async_req.state == STATE_RECEIVING_STATUS then
            local code, status, err = async_req.h:receivestatusline()
            if not code and err then
                async_req.state = STATE_ERROR
                async_req.error = "Receive status failed: " .. (err or "unknown error")
                break
            end

            if not code then
                local chunks = {}
                local sink = ltn12.sink.table(chunks)
                local ok, err = async_req.h:receive09body(status, sink, async_req.nreqt.step)
                if not ok then
                    async_req.state = STATE_ERROR
                    async_req.error = "Receive body failed: " .. (err or "unknown error")
                    break
                end
                async_req.result = table.concat(chunks)
                async_req.code = 200
                async_req.state = STATE_COMPLETED
                break
            end

            async_req.code = code
            async_req.status = status
            async_req.state = STATE_RECEIVING_HEADERS
            step_done = true
        elseif async_req.state == STATE_RECEIVING_HEADERS then
            while async_req.code == 100 do
                local headers, err = async_req.h:receiveheaders()
                if not headers then
                    async_req.state = STATE_ERROR
                    async_req.error = "Receive headers failed: " .. (err or "unknown error")
                    break
                end

                local code, status, err = async_req.h:receivestatusline()
                if not code then
                    async_req.state = STATE_ERROR
                    async_req.error = "Receive status after 100 failed: " .. (err or "unknown error")
                    break
                end
                async_req.code = code
                async_req.status = status
            end

            if async_req.state == STATE_ERROR then break end

            local headers, err = async_req.h:receiveheaders()
            if not headers then
                async_req.state = STATE_ERROR
                async_req.error = "Receive final headers failed: " .. (err or "unknown error")
                break
            end

            async_req.headers = headers

            if shouldredirect(async_req.reqt, async_req.code, headers) and not async_req.nreqt.source then
                async_req.h:close()
                async_req.state = STATE_REDIRECTING
                step_done = true
            else
                async_req.state = STATE_RECEIVING_BODY
                step_done = true
            end
        elseif async_req.state == STATE_RECEIVING_BODY then
            if shouldreceivebody(async_req.reqt, async_req.code) then
                local sink = async_req.nreqt.sink
                local collected_data

                if not sink then
                    local chunks = {}
                    sink = ltn12.sink.table(chunks)
                    collected_data = chunks
                end

                local ok, err = async_req.h:receivebody(async_req.headers, sink, async_req.nreqt.step)
                if not ok then
                    async_req.state = STATE_ERROR
                    async_req.error = "Receive body failed: " .. (err or "unknown error")
                    break
                end

                if collected_data then
                    async_req.result = table.concat(collected_data)
                else
                    async_req.result = 1
                end
            else
                async_req.result = ""
            end

            if async_req.h then
                async_req.h:close()
            end
            async_req.state = STATE_COMPLETED
            step_done = true
        elseif async_req.state == STATE_REDIRECTING then
            async_req.state = STATE_ERROR
            async_req.error = "Redirect not fully supported in async mode"
            break
        end
    end

    return async_req.state == STATE_COMPLETED or async_req.state == STATE_ERROR
end

_M.request_async = function(reqt, callback)
    local async_req = create_async_request(reqt, callback)
    table.insert(async_requests, async_req)
    return async_req
end

_M.update = function()
    if async_requests[1] then
        local async_req = async_requests[1]
        local completed = process_async_request(async_req)

        if completed then
            table.remove(async_requests, 1)
            if async_req.callback then
                if async_req.state == STATE_COMPLETED then
                    async_req.callback(async_req.result, async_req.code, async_req.headers, async_req.status)
                else
                    async_req.callback(nil, async_req.error)
                end
            end
        end
    end
end

function _M.getcreatefunc(params)
    params = params or {}

    return function(reqt)
        local u = url.parse(reqt.url or "")

        local scheme = reqt.scheme or u.scheme or "http"
        local host = reqt.host or u.host
        local port = reqt.port or u.port or _M.PORT

        if scheme ~= "http" then
            return nil, "Only HTTP scheme is supported"
        end

        if not host then
            return nil, "No host specified"
        end

        local sock = socket.tcp()
        if not sock then
            return nil, "Failed to create TCP socket"
        end

        local timeout = reqt.timeout or _M.TIMEOUT
        if type(timeout) == "table" then
            sock:settimeouts(
                timeout.connect or _M.TIMEOUT,
                timeout.send or _M.TIMEOUT, 
                timeout.receive or _M.TIMEOUT
            )
        else
            sock:settimeout(timeout)
        end

        local connect_ok, connect_err = sock:connect(host, port)
        if not connect_ok then
            sock:close()
            return nil, "Connection failed: " .. (connect_err or "unknown error")
        end

        return sock
    end
end

local https = require("lunac.core.http.https")
local socket_url = require("socket.url")
local http = {}

http.update = function()
    https.update()
    _M.update()
end

http.http = {
    fetch = function(url, options)
        options = options or {}
        options.url = url

        local parsed_url = socket_url.parse(url, { scheme = "http" })
        if parsed_url.scheme == "https" then
            return https.http.fetch(url, options)
        end

        local result, code, headers, status, err

        local completed = false
        local callback = function(res, c, h, s, e)
            result = res
            code = c
            headers = h
            status = s
            err = e
            completed = true
        end

        _M.request_async(options, callback)

        while not completed do
            if luna and luna.update then
                luna.update()
            end
            if lunac and lunac.update then
                lunac.update()
            else
                _M.update()
            end
            socket.sleep(0.01)
        end

        if result then
            return result, code, headers, status
        else
            return nil, err
        end
    end
}

http.http.init = function(config)
    luna = config.luna
    lunac = config.lunac
    https.http.init(config)
end

http.http.close = function()
    for i = #async_requests, 1, -1 do
        local async_req = async_requests[i]
        if async_req.h then
            async_req.h:close()
        end
        table.remove(async_requests, i)
    end
    https.http.close()
end

http.http.noawait_fetch = function(url, options, callback)
    options = options or {}
    options.url = url

    local parsed_url = socket_url.parse(url, { scheme = "http" })
    if parsed_url.scheme == "https" then
        return https.http.noawait_fetch(url, options, callback)
    end

    return _M.request_async(options, function(result, code, headers, status, err)
        if callback then
            if result then
                callback(result, code, headers, status)
            else
                callback(nil, err)
            end
        end
    end)
end

return http
end

-- lunac/core/http/https.lua
__lupack__["lunac.core.http.https"] = function()
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

local luna, lunac
local socket                  = require("socket")
local url                     = require("socket.url")
local ltn12                   = require("ltn12")
local mime                    = require("mime")
local string                  = require("string")
local headers                 = require("socket.headers")
local base                    = _G
local table                   = require("table")
local _M                      = {}
local async_requests          = {}
local ssl

_M.TIMEOUT                    = 60
_M.PORT                       = 443
_M.USERAGENT                  = socket._VERSION

_M.SSLPROTOCOL                = "tlsv1_2"
_M.SSLOPTIONS                 = "all"
_M.SSLVERIFY                  = "none"
_M.SSLSNISTRICT               = false

local STATE_CONNECTING        = 1
local STATE_SENDING           = 2
local STATE_RECEIVING_STATUS  = 3
local STATE_RECEIVING_HEADERS = 4
local STATE_RECEIVING_BODY    = 5
local STATE_REDIRECTING       = 6
local STATE_COMPLETED         = 7
local STATE_ERROR             = 8

local function receiveheaders(sock, headers)
    local line, name, value, err
    headers = headers or {}
    line, err = sock:receive()
    if err then return nil, err end
    while line ~= "" do
        name, value = socket.skip(2, string.find(line, "^(.-):%s*(.*)"))
        if not (name and value) then return nil, "malformed reponse headers" end
        name      = string.lower(name)
        line, err = sock:receive()
        if err then return nil, err end
        while string.find(line, "^%s") do
            value = value .. line
            line, err = sock:receive()
            if err then return nil, err end
        end
        if headers[name] then
            headers[name] = headers[name] .. ", " .. value
        else
            headers[name] = value
        end
    end
    return headers
end

socket.sourcet["http-chunked"] = function(sock, headers)
    return base.setmetatable({
        getfd = function() return sock:getfd() end,
        dirty = function() return sock:dirty() end
    }, {
        __call = function()
            local line, err = sock:receive()
            if err then return nil, err end
            local size = base.tonumber(string.gsub(line, ";.*", ""), 16)
            if not size then return nil, "invalid chunk size" end
            if size > 0 then
                local chunk, err = sock:receive(size)
                if chunk then sock:receive() end
                return chunk, err
            else
                headers, err = receiveheaders(sock, headers)
                if not headers then return nil, err end
            end
        end
    })
end

socket.sinkt["http-chunked"] = function(sock)
    return base.setmetatable({
        getfd = function() return sock:getfd() end,
        dirty = function() return sock:dirty() end
    }, {
        __call = function(self, chunk, err)
            if not chunk then return sock:send("0\r\n\r\n") end
            local size = string.format("%X\r\n", string.len(chunk))
            return sock:send(size .. chunk .. "\r\n")
        end
    })
end

local metat = { __index = {} }

function _M.open(reqt)
    local sock, err = reqt:create()
    local c = socket.try(sock)
    local h = base.setmetatable({ c = c }, metat)
    h.try = socket.newtry(function() h:close() end)
    local to = reqt.timeout or _M.TIMEOUT
    if type(to) == "table" then
        h.try(c:settimeouts(
            to.connect or _M.TIMEOUT,
            to.send or _M.TIMEOUT,
            to.receive or _M.TIMEOUT))
    else
        h.try(c:settimeout(to))
    end
    return h
end

function metat.__index:sendrequestline(method, uri)
    local reqline = string.format("%s %s HTTP/1.1\r\n", method or "GET", uri)
    return self.try(self.c:send(reqline))
end

function metat.__index:sendheaders(tosend)
    local canonic = headers.canonic
    local h = "\r\n"
    for f, v in base.pairs(tosend) do
        h = (canonic[f] or f) .. ": " .. v .. "\r\n" .. h
    end
    self.try(self.c:send(h))
    return 1
end

function metat.__index:sendbody(headers, source, step)
    source = source or ltn12.source.empty()
    step = step or ltn12.pump.step
    local mode = "http-chunked"
    if headers["content-length"] then mode = "keep-open" end
    return self.try(ltn12.pump.all(source, socket.sink(mode, self.c), step))
end

function metat.__index:receivestatusline()
    local status, err, partial = self.c:receive(5)
    if err then
        return nil, err
    end
    if status ~= "HTTP/" then return nil, "invalid status" end
    local line, err, partial = self.c:receive("*l")
    if err then
        if err == "timeout" and partial then
            status = status .. partial
        else
            return nil, err
        end
    else
        status = status .. line
    end
    local code = socket.skip(2, string.find(status, "HTTP/%d*%.%d* (%d%d%d)"))
    return base.tonumber(code), status
end

function metat.__index:receiveheaders()
    return self.try(receiveheaders(self.c))
end

function metat.__index:receivebody(headers, sink, step)
    sink = sink or ltn12.sink.null()
    step = step or ltn12.pump.step
    local length = base.tonumber(headers["content-length"])
    local t = headers["transfer-encoding"]
    local mode = "default"
    if t and t ~= "identity" then
        mode = "http-chunked"
    elseif base.tonumber(headers["content-length"]) then
        mode = "by-length"
    end
    return self.try(ltn12.pump.all(socket.source(mode, self.c, length),
        sink, step))
end

function metat.__index:receive09body(status, sink, step)
    local source = ltn12.source.rewind(socket.source("until-closed", self.c))
    source(status)
    return self.try(ltn12.pump.all(source, sink, step))
end

function metat.__index:close()
    return self.c:close()
end

local function adjusturi(reqt)
    local u = reqt
    if not reqt.proxy and not _M.PROXY then
        u = {
            path = socket.try(reqt.path, "invalid path 'nil'"),
            params = reqt.params,
            query = reqt.query,
            fragment = reqt.fragment
        }
    end
    return url.build(u)
end

local function adjustproxy(reqt)
    local proxy = reqt.proxy or _M.PROXY
    if proxy then
        proxy = url.parse(proxy)
        return proxy.host, proxy.port or 3128
    else
        return reqt.host, reqt.port
    end
end

local function adjustheaders(reqt)
    local host = string.gsub(reqt.authority, "^.-@", "")
    local lower = {
        ["user-agent"] = _M.USERAGENT,
        ["host"] = host,
        ["connection"] = "close, TE",
        ["te"] = "trailers"
    }
    if reqt.user and reqt.password then
        lower["authorization"] =
            "Basic " .. (mime.b64(reqt.user .. ":" .. reqt.password))
    end
    for i, v in base.pairs(reqt.headers or lower) do
        lower[string.lower(i)] = v
    end
    return lower
end

local default = {
    host = "",
    port = _M.PORT,
    path = "/",
    scheme = "https"
}

local function adjustrequest(reqt)
    local nreqt = reqt.url and url.parse(reqt.url, default) or {}
    for i, v in base.pairs(reqt) do nreqt[i] = v end
    if nreqt.port == "" then nreqt.port = 443 end
    socket.try(nreqt.host and nreqt.host ~= "",
        "invalid host '" .. base.tostring(nreqt.host) .. "'")
    socket.try(nreqt.scheme == "https", "Only HTTPS supported")
    nreqt.uri = reqt.uri or adjusturi(nreqt)
    nreqt.host, nreqt.port = adjustproxy(nreqt)
    nreqt.headers = adjustheaders(nreqt)
    return nreqt
end

local function shouldredirect(reqt, code, headers)
    return headers.location and
        string.gsub(headers.location, "%s", "") ~= "" and
        (reqt.redirect ~= false) and
        (code == 301 or code == 302 or code == 303 or code == 307) and
        (not reqt.method or reqt.method == "GET" or reqt.method == "HEAD")
        and (not reqt.nredirects or reqt.nredirects < 5)
end

local function shouldreceivebody(reqt, code)
    if reqt.method == "HEAD" then return nil end
    if code == 204 or code == 304 then return nil end
    if code >= 100 and code < 200 then return nil end
    return 1
end

local function create_async_request(reqt, callback)
    local nreqt = adjustrequest(reqt)
    nreqt.create = nreqt.create or _M.getcreatefunc(nreqt)

    local async_req = {
        reqt = reqt,
        callback = callback,
        state = STATE_CONNECTING,
        nreqt = nreqt,
        h = nil,
        result = nil,
        code = nil,
        headers = nil,
        status = nil,
        error = nil,
    }

    return async_req
end

local function process_async_request(async_req)
    if async_req.state == STATE_COMPLETED or async_req.state == STATE_ERROR then
        return true
    end

    local step_done = false

    while not step_done do
        if async_req.state == STATE_CONNECTING then
            local sock, err = async_req.nreqt.create(async_req.nreqt)
            if not sock then
                async_req.state = STATE_ERROR
                async_req.error = "Connection failed: " .. (err or "unknown error")
                break
            end

            async_req.h = base.setmetatable({ c = sock }, metat)
            async_req.h.try = socket.newtry(function()
                if async_req.h then
                    async_req.h:close()
                end
            end)

            local to = async_req.nreqt.timeout or _M.TIMEOUT
            if type(to) == "table" then
                sock:settimeouts(
                    to.connect or _M.TIMEOUT,
                    to.send or _M.TIMEOUT,
                    to.receive or _M.TIMEOUT
                )
            else
                sock:settimeout(to)
            end

            async_req.state = STATE_SENDING
            step_done = true
        elseif async_req.state == STATE_SENDING then
            local ok, err = async_req.h:sendrequestline(async_req.nreqt.method, async_req.nreqt.uri)
            if not ok then
                async_req.state = STATE_ERROR
                async_req.error = "Send request line failed: " .. (err or "unknown error")
                break
            end

            ok, err = async_req.h:sendheaders(async_req.nreqt.headers)
            if not ok then
                async_req.state = STATE_ERROR
                async_req.error = "Send headers failed: " .. (err or "unknown error")
                break
            end

            if async_req.nreqt.source then
                ok, err = async_req.h:sendbody(async_req.nreqt.headers, async_req.nreqt.source, async_req.nreqt.step)
                if not ok then
                    async_req.state = STATE_ERROR
                    async_req.error = "Send body failed: " .. (err or "unknown error")
                    break
                end
            end

            async_req.state = STATE_RECEIVING_STATUS
            step_done = true
        elseif async_req.state == STATE_RECEIVING_STATUS then
            local code, status, err = async_req.h:receivestatusline()
            if not code and err then
                async_req.state = STATE_ERROR
                async_req.error = "Receive status failed: " .. (err or "unknown error")
                break
            end

            if not code then
                local chunks = {}
                local sink = ltn12.sink.table(chunks)
                local ok, err = async_req.h:receive09body(status, sink, async_req.nreqt.step)
                if not ok then
                    async_req.state = STATE_ERROR
                    async_req.error = "Receive body failed: " .. (err or "unknown error")
                    break
                end
                async_req.result = table.concat(chunks)
                async_req.code = 200
                async_req.state = STATE_COMPLETED
                break
            end

            async_req.code = code
            async_req.status = status
            async_req.state = STATE_RECEIVING_HEADERS
            step_done = true
        elseif async_req.state == STATE_RECEIVING_HEADERS then
            while async_req.code == 100 do
                local headers, err = async_req.h:receiveheaders()
                if not headers then
                    async_req.state = STATE_ERROR
                    async_req.error = "Receive headers failed: " .. (err or "unknown error")
                    break
                end

                local code, status, err = async_req.h:receivestatusline()
                if not code then
                    async_req.state = STATE_ERROR
                    async_req.error = "Receive status after 100 failed: " .. (err or "unknown error")
                    break
                end
                async_req.code = code
                async_req.status = status
            end

            if async_req.state == STATE_ERROR then break end

            local headers, err = async_req.h:receiveheaders()
            if not headers then
                async_req.state = STATE_ERROR
                async_req.error = "Receive final headers failed: " .. (err or "unknown error")
                break
            end

            async_req.headers = headers

            if shouldredirect(async_req.reqt, async_req.code, headers) and not async_req.nreqt.source then
                async_req.h:close()
                async_req.state = STATE_REDIRECTING
                step_done = true
            else
                async_req.state = STATE_RECEIVING_BODY
                step_done = true
            end
        elseif async_req.state == STATE_RECEIVING_BODY then
            if shouldreceivebody(async_req.reqt, async_req.code) then
                local sink = async_req.nreqt.sink
                local collected_data

                if not sink then
                    local chunks = {}
                    sink = ltn12.sink.table(chunks)
                    collected_data = chunks
                end

                local ok, err = async_req.h:receivebody(async_req.headers, sink, async_req.nreqt.step)
                if not ok then
                    async_req.state = STATE_ERROR
                    async_req.error = "Receive body failed: " .. (err or "unknown error")
                    break
                end

                if collected_data then
                    async_req.result = table.concat(collected_data)
                else
                    async_req.result = 1
                end
            else
                async_req.result = ""
            end

            if async_req.h then
                async_req.h:close()
            end
            async_req.state = STATE_COMPLETED
            step_done = true
        elseif async_req.state == STATE_REDIRECTING then
            async_req.state = STATE_ERROR
            async_req.error = "Redirect not fully supported in async mode"
            break
        end
    end

    return async_req.state == STATE_COMPLETED or async_req.state == STATE_ERROR
end

_M.request_async = function(reqt, callback)
    local async_req = create_async_request(reqt, callback)
    table.insert(async_requests, async_req)
    return async_req
end

_M.update = function()
    if async_requests[1] then
        local async_req = async_requests[1]
        local completed = process_async_request(async_req)

        if completed then
            table.remove(async_requests, 1)
            if async_req.callback then
                if async_req.state == STATE_COMPLETED then
                    async_req.callback(async_req.result, async_req.code, async_req.headers, async_req.status)
                else
                    async_req.callback(nil, async_req.error)
                end
            end
        end
    end
end

function _M.getcreatefunc(params)
    params = params or {}
    local ssl_params = params.sslparams or {}
    ssl_params.wrap = ssl_params.wrap or {
        protocol = params.protocol or "any",
        options = params.options or _M.SSLOPTIONS,
        verify = params.verify or _M.SSLVERIFY,
        mode = "client"
    }

    return function(reqt)
        local u = url.parse(reqt.url or "")

        local scheme = reqt.scheme or u.scheme or "https"
        local host = reqt.host or u.host
        local port = reqt.port or u.port or _M.PORT

        if not host then
            return nil, "No host specified"
        end

        local sock = socket.tcp()
        if not sock then
            return nil, "Failed to create TCP socket"
        end

        local timeout = reqt.timeout or _M.TIMEOUT
        if type(timeout) == "table" then
            sock:settimeouts(
                timeout.connect or _M.TIMEOUT,
                timeout.send or _M.TIMEOUT, 
                timeout.receive or _M.TIMEOUT
            )
        else
            sock:settimeout(timeout)
        end

        local connect_ok, connect_err = sock:connect(host, port)
        if not connect_ok then
            sock:close()
            return nil, "Connection failed: " .. (connect_err or "unknown error")
        end

        if not ssl then
            local ssl_ok, ssl_mod = pcall(require, "ssl")
            if not ssl_ok then
                sock:close()
                return nil, "SSL module not available: " .. tostring(ssl_mod)
            end
            ssl = ssl_mod
        end

        if ssl and ssl.wrap then
            local ssl_sock, ssl_err = ssl.wrap(sock, ssl_params.wrap)
            if not ssl_sock then
                sock:close()
                return nil, "SSL wrap failed: " .. (ssl_err or "unknown error")
            end

            if type(timeout) == "table" then
                ssl_sock:settimeouts(
                    timeout.connect or _M.TIMEOUT,
                    timeout.send or _M.TIMEOUT,
                    timeout.receive or _M.TIMEOUT
                )
            else
                ssl_sock:settimeout(timeout)
            end

            ssl_sock:sni(host)

            local handshake_ok, handshake_err = ssl_sock:dohandshake()
            if not handshake_ok then
                ssl_sock:close()
                return nil, "SSL handshake failed: " .. (handshake_err or "unknown error")
            end

            local proxy = {
                send = function(self, ...) return ssl_sock:send(...) end,
                receive = function(self, ...) return ssl_sock:receive(...) end,
                close = function(self, ...) return ssl_sock:close(...) end,
                settimeout = function(self, ...) return ssl_sock:settimeout(...) end,
                settimeouts = function(self, ...) return ssl_sock:settimeouts(...) end,
                getfd = function(self, ...) return sock:getfd(...) end,
                dirty = function(self, ...) return sock:dirty(...) end,
            }

            return proxy
        else
            sock:close()
            return nil, "SSL wrap function not available"
        end
    end
end

local http = {}

http.update = function()
    _M.update()
end

http.http = {
    fetch = function(url, options)
        options = options or {}
        options.url = url

        local result, code, headers, status, err

        local completed = false
        local callback = function(res, c, h, s, e)
            result = res
            code = c
            headers = h
            status = s
            err = e
            completed = true
        end

        _M.request_async(options, callback)

        while not completed do
            if luna and luna.update then
                luna.update()
            end
            if lunac and lunac.update then
                lunac.update()
            else
                _M.update()
            end
            socket.sleep(0.01)
        end

        if result then
            return result, code, headers, status
        else
            return nil, err
        end
    end
}

http.http.init = function(config)
    luna = config.luna
    lunac = config.lunac
end

http.http.close = function()
    for i = #async_requests, 1, -1 do
        local async_req = async_requests[i]
        if async_req.h then
            async_req.h:close()
        end
        table.remove(async_requests, i)
    end
end

http.http.noawait_fetch = function(url, options, callback)
    options = options or {}
    options.url = url

    return _M.request_async(options, function(result, code, headers, status, err)
        if callback then
            if result then
                callback(result, code, headers, status)
            else
                callback(nil, err)
            end
        end
    end)
end

return http
end

-- lunac/core/init.lua
__lupack__["lunac.core.init"] = function()
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

local core = {}
local result = { core, {} }

local s, e = pcall(function()
    local app = require("lunac.core.default.app")
    core.connect_to_app = function(config)
        return app.connect(config)
    end

    core.disconnect_to_app = function(app_reference)
        return app.close(app_reference)
    end

    result[2].app_update = app.update
    result[2].app_close = app.close_all
end)

if not s then
    print("Lunac error init default apps: " .. e)
end

s, e = pcall(function()
    if not _G["python"] then
        local http = require("lunac.core.http.http")
        core.http = http.http

        result[2].http_update = http.update
        result[2].http_close = http.http.close_all
    end
end)

if not s then
    print("Lunac error init http request: " .. e)
end

s, e = pcall(function()
    if not _G["python"] then
        local web = require("lunac.core.web.web_app")

        core.connect_to_web_app = function(config)
            return web.connect(config)
        end

        core.disconnect_to_web_app = function(app_reference)
            return web.close(app_reference)
        end

        result[2].web_update = web.update
        result[2].web_close = web.close_all
    end
end)

if not s then
    print("Lunac error init web-apps: " .. e)
end

return result

end

-- lunac/core/web/web_app.lua
__lupack__["lunac.core.web.web_app"] = function()
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

local webserv = require("lunac.libs.web-serv")

local function handle_error(app_data, message, err_level)
    if app_data.no_errors then
        if app_data.error_handler then
            app_data.error_handler(message)
        end
    else
        error(message, err_level or 2)
    end
end

local apps, web_app = {}, {}

--[[
config:
str name
str url

boolean debug

func error_handler(error_message)
boolean no_errors

str protocol

tbl ssl

func on_connect(self)
func on_message(self, message, opcode)
func on_close(self, code, reason)
]]
web_app.connect = function(config)
    local app_data
    app_data = {
        name = config.name or "unknown name",
        url = config.url or "ws://localhost:80",

        error_handler = config.error_handler or function(message)
            print("Error in web-app '" .. app_data.name .. "': " .. message)
        end,
        no_errors = config.no_errors,

        ssl = config.ssl,
        protocol = config.protocol,

        debug = config.debug == nil and true or config.debug,

        on_connect = config.on_connect,
        on_message = config.on_message,
        on_close = config.on_close,

        send = function(self, message, opcode)
            self.client:send(message, opcode)
        end,

        opcodes = {
            CLOSE = webserv.CLOSE,
            TEXT = webserv.TEXT,
            BINARY = webserv.BINARY,
            PING = webserv.PING,
            PONG = webserv.PONG,
            CONTINUATION = webserv.CONTINUATION,
        }
    }

    if apps[app_data.name] then
        handle_error(app_data, "An application with that name already exists.", 2)
        return
    end

    local ok, err = pcall(function()
        local client = webserv.client.new()
        app_data.client = client

        client:start(function(self)
            local success, protocol, headers = self:connect(app_data.url, app_data.protocol, app_data.ssl)
            if not success then
                handle_error(app_data, "Connection failed. Error: " .. tostring(protocol), 2)
                return
            end

            if app_data.on_connect then
                app_data.on_connect(app_data)
            end

            client.on_error = function(self, err)
                handle_error(app_data, err, 2)
            end

            if app_data.on_close then
                client.on_close = function(self, was_clean, code, reason)
                    app_data.on_close(app_data, code, reason)
                end
            end

            while self.state == 'OPEN' do
                local data, opcode, was_clean, code, reason = self:receive()
                if data then
                    if opcode == 8 then
                        local result
                        if app_data.on_close then
                            result = app_data.on_close(self, code, reason)
                        end
                        if result ~= false then
                            handle_error(app_data,
                                "Server closed connection. Code: " .. tostring(code) .. "   Reason: " .. tostring(reason),
                                2)
                            break
                        end
                    end
                    if app_data.on_message then
                        app_data.on_message(app_data, data, opcode)
                    end
                elseif not was_clean then
                    handle_error(app_data, "Receive error. Code: " .. tostring(code) .. "   Reason: " .. tostring(reason),
                        2)
                    break
                end
            end
        end)
    end)

    if not ok then
        handle_error(app_data, "Failed to start web-app on " .. app_data.url .. ": " .. err)
        return nil, err
    else
        if app_data.debug then
            print("Web-App '" .. app_data.name .. "' started on " .. app_data.url)
        end
        if apps[app_data.name] then
            handle_error(app_data, "An application with that name already exists.", 2)
            return
        end
        apps[app_data.name] = app_data
    end

    return app_data
end

web_app.update = function()
    for name, app_data in pairs(apps) do
        app_data.client:update()
    end
end

web_app.close = function(app_data_or_name)
    if type(app_data_or_name) == "string" then
        app_data_or_name = apps[app_data_or_name]
        if not app_data_or_name then
            return false, "Web-App not found"
        end
    end

    local name = app_data_or_name["name"]
    apps[name] = nil

    if app_data_or_name.debug then
        print("Web-App '" .. app_data_or_name.name .. "' close.")
    end
    app_data_or_name.client:close(1000, "App closing")
end

web_app.close_all = function()
    for name, app_data in pairs(apps) do
        web_app.remove(app_data)
    end
end

return web_app

end

-- lunac/init.lua
__lupack__["lunac.init"] = function()
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

local lunac = {}

local core = require("lunac.core.init")

for key, value in pairs(core[1]) do
    lunac[key] = value
end

lunac.update = function (dt)
    if core[2].app_update then
        core[2].app_update(dt)
    end
    if core[2].http_update then
        core[2].http_update()
    end
    if core[2].web_update then
        core[2].web_update()
    end
end

lunac.close = function ()
    if core[2].app_close then
        print(pcall(core[2].app_close))
    end
    if core[2].http_close then
        print(pcall(core[2].http_close))
    end
    if core[2].web_close then
        print(pcall(core[2].web_close))
    end
end

return lunac
end

-- lunac/libs/json.lua
__lupack__["lunac.libs.json"] = function()
--
-- json.lua
--
-- Copyright (c) 2020 rxi
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy of
-- this software and associated documentation files (the "Software"), to deal in
-- the Software without restriction, including without limitation the rights to
-- use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
-- of the Software, and to permit persons to whom the Software is furnished to do
-- so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.
--

local json = { _version = "0.1.2" }

-------------------------------------------------------------------------------
-- Encode
-------------------------------------------------------------------------------

local encode

local escape_char_map = {
  [ "\\" ] = "\\",
  [ "\"" ] = "\"",
  [ "\b" ] = "b",
  [ "\f" ] = "f",
  [ "\n" ] = "n",
  [ "\r" ] = "r",
  [ "\t" ] = "t",
}

local escape_char_map_inv = { [ "/" ] = "/" }
for k, v in pairs(escape_char_map) do
  escape_char_map_inv[v] = k
end


local function escape_char(c)
  return "\\" .. (escape_char_map[c] or string.format("u%04x", c:byte()))
end


local function encode_nil(val)
  return "null"
end


local function encode_table(val, stack)
  local res = {}
  stack = stack or {}

  -- Circular reference?
  if stack[val] then error("circular reference") end

  stack[val] = true

  if rawget(val, 1) ~= nil or next(val) == nil then
    -- Treat as array -- check keys are valid and it is not sparse
    local n = 0
    for k in pairs(val) do
      if type(k) ~= "number" then
        error("invalid table: mixed or invalid key types")
      end
      n = n + 1
    end
    if n ~= #val then
      error("invalid table: sparse array")
    end
    -- Encode
    for i, v in ipairs(val) do
      table.insert(res, encode(v, stack))
    end
    stack[val] = nil
    return "[" .. table.concat(res, ",") .. "]"

  else
    -- Treat as an object
    for k, v in pairs(val) do
      if type(k) ~= "string" then
        error("invalid table: mixed or invalid key types")
      end
      table.insert(res, encode(k, stack) .. ":" .. encode(v, stack))
    end
    stack[val] = nil
    return "{" .. table.concat(res, ",") .. "}"
  end
end


local function encode_string(val)
  return '"' .. val:gsub('[%z\1-\31\\"]', escape_char) .. '"'
end


local function encode_number(val)
  -- Check for NaN, -inf and inf
  if val ~= val or val <= -math.huge or val >= math.huge then
    error("unexpected number value '" .. tostring(val) .. "'")
  end
  return string.format("%.14g", val)
end


local type_func_map = {
  [ "nil"     ] = encode_nil,
  [ "table"   ] = encode_table,
  [ "string"  ] = encode_string,
  [ "number"  ] = encode_number,
  [ "boolean" ] = tostring,
  [ "function" ] = function()return'"no support functions"'end
}


encode = function(val, stack)
  local t = type(val)
  local f = type_func_map[t]
  if f then
    return f(val, stack)
  end
  error("unexpected type '" .. t .. "'")
end


function json.encode(val)
  return ( encode(val) )
end


-------------------------------------------------------------------------------
-- Decode
-------------------------------------------------------------------------------

local parse

local function create_set(...)
  local res = {}
  for i = 1, select("#", ...) do
    res[ select(i, ...) ] = true
  end
  return res
end

local space_chars   = create_set(" ", "\t", "\r", "\n")
local delim_chars   = create_set(" ", "\t", "\r", "\n", "]", "}", ",")
local escape_chars  = create_set("\\", "/", '"', "b", "f", "n", "r", "t", "u")
local literals      = create_set("true", "false", "null")

local literal_map = {
  [ "true"  ] = true,
  [ "false" ] = false,
  [ "null"  ] = nil,
}


local function next_char(str, idx, set, negate)
  for i = idx, #str do
    if set[str:sub(i, i)] ~= negate then
      return i
    end
  end
  return #str + 1
end


local function decode_error(str, idx, msg)
  local line_count = 1
  local col_count = 1
  for i = 1, idx - 1 do
    col_count = col_count + 1
    if str:sub(i, i) == "\n" then
      line_count = line_count + 1
      col_count = 1
    end
  end
  error( string.format("%s at line %d col %d", msg, line_count, col_count) )
end


local function codepoint_to_utf8(n)
  -- http://scripts.sil.org/cms/scripts/page.php?site_id=nrsi&id=iws-appendixa
  local f = math.floor
  if n <= 0x7f then
    return string.char(n)
  elseif n <= 0x7ff then
    return string.char(f(n / 64) + 192, n % 64 + 128)
  elseif n <= 0xffff then
    return string.char(f(n / 4096) + 224, f(n % 4096 / 64) + 128, n % 64 + 128)
  elseif n <= 0x10ffff then
    return string.char(f(n / 262144) + 240, f(n % 262144 / 4096) + 128,
                       f(n % 4096 / 64) + 128, n % 64 + 128)
  end
  error( string.format("invalid unicode codepoint '%x'", n) )
end


local function parse_unicode_escape(s)
  local n1 = tonumber( s:sub(1, 4),  16 )
  local n2 = tonumber( s:sub(7, 10), 16 )
   -- Surrogate pair?
  if n2 then
    return codepoint_to_utf8((n1 - 0xd800) * 0x400 + (n2 - 0xdc00) + 0x10000)
  else
    return codepoint_to_utf8(n1)
  end
end


local function parse_string(str, i)
  local res = ""
  local j = i + 1
  local k = j

  while j <= #str do
    local x = str:byte(j)

    if x < 32 then
      decode_error(str, j, "control character in string")

    elseif x == 92 then -- `\`: Escape
      res = res .. str:sub(k, j - 1)
      j = j + 1
      local c = str:sub(j, j)
      if c == "u" then
        local hex = str:match("^[dD][89aAbB]%x%x\\u%x%x%x%x", j + 1)
                 or str:match("^%x%x%x%x", j + 1)
                 or decode_error(str, j - 1, "invalid unicode escape in string")
        res = res .. parse_unicode_escape(hex)
        j = j + #hex
      else
        if not escape_chars[c] then
          decode_error(str, j - 1, "invalid escape char '" .. c .. "' in string")
        end
        res = res .. escape_char_map_inv[c]
      end
      k = j + 1

    elseif x == 34 then -- `"`: End of string
      res = res .. str:sub(k, j - 1)
      return res, j + 1
    end

    j = j + 1
  end

  decode_error(str, i, "expected closing quote for string")
end


local function parse_number(str, i)
  local x = next_char(str, i, delim_chars)
  local s = str:sub(i, x - 1)
  local n = tonumber(s)
  if not n then
    decode_error(str, i, "invalid number '" .. s .. "'")
  end
  return n, x
end


local function parse_literal(str, i)
  local x = next_char(str, i, delim_chars)
  local word = str:sub(i, x - 1)
  if not literals[word] then
    decode_error(str, i, "invalid literal '" .. word .. "'")
  end
  return literal_map[word], x
end


local function parse_array(str, i)
  local res = {}
  local n = 1
  i = i + 1
  while 1 do
    local x
    i = next_char(str, i, space_chars, true)
    -- Empty / end of array?
    if str:sub(i, i) == "]" then
      i = i + 1
      break
    end
    -- Read token
    x, i = parse(str, i)
    res[n] = x
    n = n + 1
    -- Next token
    i = next_char(str, i, space_chars, true)
    local chr = str:sub(i, i)
    i = i + 1
    if chr == "]" then break end
    if chr ~= "," then decode_error(str, i, "expected ']' or ','") end
  end
  return res, i
end


local function parse_object(str, i)
  local res = {}
  i = i + 1
  while 1 do
    local key, val
    i = next_char(str, i, space_chars, true)
    -- Empty / end of object?
    if str:sub(i, i) == "}" then
      i = i + 1
      break
    end
    -- Read key
    if str:sub(i, i) ~= '"' then
      decode_error(str, i, "expected string for key")
    end
    key, i = parse(str, i)
    -- Read ':' delimiter
    i = next_char(str, i, space_chars, true)
    if str:sub(i, i) ~= ":" then
      decode_error(str, i, "expected ':' after key")
    end
    i = next_char(str, i + 1, space_chars, true)
    -- Read value
    val, i = parse(str, i)
    -- Set
    res[key] = val
    -- Next token
    i = next_char(str, i, space_chars, true)
    local chr = str:sub(i, i)
    i = i + 1
    if chr == "}" then break end
    if chr ~= "," then decode_error(str, i, "expected '}' or ','") end
  end
  return res, i
end


local char_func_map = {
  [ '"' ] = parse_string,
  [ "0" ] = parse_number,
  [ "1" ] = parse_number,
  [ "2" ] = parse_number,
  [ "3" ] = parse_number,
  [ "4" ] = parse_number,
  [ "5" ] = parse_number,
  [ "6" ] = parse_number,
  [ "7" ] = parse_number,
  [ "8" ] = parse_number,
  [ "9" ] = parse_number,
  [ "-" ] = parse_number,
  [ "t" ] = parse_literal,
  [ "f" ] = parse_literal,
  [ "n" ] = parse_literal,
  [ "[" ] = parse_array,
  [ "{" ] = parse_object,
}


parse = function(str, idx)
  local chr = str:sub(idx, idx)
  local f = char_func_map[chr]
  if f then
    return f(str, idx)
  end
  decode_error(str, idx, "unexpected character '" .. chr .. "'")
end


function json.decode(str)
  if type(str) ~= "string" then
    error("expected argument of type string, got " .. type(str))
  end
  local res, idx = parse(str, next_char(str, 1, space_chars, true))
  idx = next_char(str, idx, space_chars, true)
  if idx <= #str then
    decode_error(str, idx, "trailing garbage")
  end
  return res
end


return json
end

-- lunac/libs/security.lua
__lupack__["lunac.libs.security"] = function()
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
SOFTWARE.]]

local security = {}

do
    do
        local string_char, math_floor, math_log, table_concat = string.char, math.floor, math.log, table.concat;
        local number_to_bytestring = function(num, n)
            n = n or math_floor(math_log(num) / math_log(0x100) + 1);
            n = n > 0 and n or 1;
            local t = {};
            for i = 1, n do
                t[n - i + 1] = string_char((num % 0x100 ^ i - num % 0x100 ^ (i - 1)) / 0x100 ^ (i - 1));
            end
            local s = table_concat(t);
            s = ("\0"):rep(n - #s) .. s;
            return s, n;
        end

        local function bytestring_to_number(s)
            local num = 0;
            local len = s:len();
            for i = 0, len - 1 do
                num = num + s:byte(len - i) * 0x100 ^ i;
            end
            return num;
        end

        security.util = {
            number_to_bytestring = number_to_bytestring,
            bytestring_to_number = bytestring_to_number,
        }
    end

    do
        local has_bit32, bit32 = pcall(require, "bit32");
        local has_bit, bit = pcall(require, "bit");
        local u32_xor, u32_lrot;
        if has_bit32 then
            u32_xor = bit32.bxor;
            u32_lrot = function(a, n)
                return bit32.lrotate(a, n % 32);
            end
        elseif has_bit then
            u32_xor = bit.bxor;
            u32_lrot = bit.rol;
        else
            local and_table = {};
            do
                for i = 0, 255 do
                    and_table[i] = {};
                    for j = 0, 255 do
                        local result = 0;
                        local bit_val = 1;
                        for k = 0, 7 do
                            if (i % (2 * bit_val)) >= bit_val and (j % (2 * bit_val)) >= bit_val then
                                result = result + bit_val;
                            end
                            bit_val = bit_val * 2;
                        end
                        and_table[i][j] = result;
                    end
                end
            end

            local math_floor = math.floor;
            function u32_xor(a, b)
                local a1, a2, b1, b2 = math_floor(a / 0x10000), a % 0x10000, math_floor(b / 0x10000), b % 0x10000;

                local a161, a162, b161, b162 = math_floor(a1 / 0x100), a1 % 0x100, math_floor(b1 / 0x100), b1 % 0x100;
                local r1 = (a161 + b161 - 2 * and_table[a161 % 0x100][b161 % 0x100]) % 0x100 * 0x100 + (a162 + b162 - 2 * and_table[a162 % 0x100][b162 % 0x100]) % 0x100;

                a161, a162, b161, b162 = math_floor(a2 / 0x100), a2 % 0x100, math_floor(b2 / 0x100), b2 % 0x100;
                local r2 = (a161 + b161 - 2 * and_table[a161 % 0x100][b161 % 0x100]) % 0x100 * 0x100 + (a162 + b162 - 2 * and_table[a162 % 0x100][b162 % 0x100]) % 0x100;
                return r1 * 0x10000 + r2;
            end

            function u32_lrot(a, n)
                n = n % 32;
                return ((a * (2 ^ n)) % 0x100000000 + math_floor(a / (2 ^ (32 - n)))) % 0x100000000;
            end
        end

        local num_to_bytes, num_from_bytes, MOD, char, XOR, LROT =
            security.util.number_to_bytestring, security.util.bytestring_to_number, 0x100000000, string.char, u32_xor,
            u32_lrot

        local function unpack(s, len)
            local array = {};
            local count = 0;
            len = len or s:len();

            for i = 1, len, 4 do
                local chunk = s:sub(i, i + 3);
                if #chunk < 4 then
                    chunk = chunk .. char(0):rep(4 - #chunk);
                end
                count = count + 1;
                array[count] = num_from_bytes(chunk);
            end
            return array;
        end

        local min, table_concat = math.min, table.concat;
        local function pack(a, len)
            local t = {};
            local array_len = #a;
            local remaining = len or (array_len * 4);
            for i = 1, array_len do
                local bytes = num_to_bytes(a[i], 4);
                local take = min(4, remaining - (i - 1) * 4);
                t[i] = bytes:sub(1, take);
            end
            return table_concat(t);
        end

        local function quarter_round(s, a, b, c, d)
            local sa, sb, sc, sd = s[a], s[b], s[c], s[d]
            sa = (sa + sb) % MOD; sd = LROT(XOR(sd, sa), 16)
            sc = (sc + sd) % MOD; sb = LROT(XOR(sb, sc), 12)
            sa = (sa + sb) % MOD; sd = LROT(XOR(sd, sa), 8)
            sc = (sc + sd) % MOD; sb = LROT(XOR(sb, sc), 7)
            s[a], s[b], s[c], s[d] = sa, sb, sc, sd
        end

        local CONSTANTS = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };
        local function block(key, nonce, counter)
            local state = {
                CONSTANTS[1], CONSTANTS[2], CONSTANTS[3], CONSTANTS[4],
                key[1], key[2], key[3], key[4],
                key[5], key[6], key[7], key[8],
                counter, nonce[1], nonce[2], nonce[3]
            }

            local init = {}
            for i = 1, 16 do init[i] = state[i] end

            for _ = 1, 10 do
                quarter_round(state, 1, 5, 9, 13)
                quarter_round(state, 2, 6, 10, 14)
                quarter_round(state, 3, 7, 11, 15)
                quarter_round(state, 4, 8, 12, 16)
                quarter_round(state, 1, 6, 11, 16)
                quarter_round(state, 2, 7, 12, 13)
                quarter_round(state, 3, 8, 9, 14)
                quarter_round(state, 4, 5, 10, 15)
            end

            for i = 1, 16 do
                state[i] = (state[i] + init[i]) % MOD
            end

            return state
        end

        local unpack, pack, floor, ceil, table_concat = unpack, pack, math.floor, math.ceil, table.concat;
        local encrypt = function(plain, key, nonce)
            key = unpack(key);
            nonce = unpack(nonce);
            local counter = 0;
            local cipher = {};
            local cipher_count = 0;

            local plain_len = plain:len()

            local chunks = floor(plain_len / 64)
            while counter < chunks do
                local key_stream = block(key, nonce, counter);
                local plain_block = unpack(plain:sub(counter * 64 + 1, (counter + 1) * 64));

                local cipher_block = {};
                for j = 1, 16 do
                    cipher_block[j] = XOR(plain_block[j], key_stream[j]);
                end

                cipher_count = cipher_count + 1;
                cipher[cipher_count] = pack(cipher_block);

                counter = counter + 1;
            end
            if plain_len % 64 ~= 0 then
                local key_stream = block(key, nonce, counter);
                local plain_block = unpack(plain:sub(counter * 64 + 1));
                local cipher_block = {};

                chunks = ceil((plain_len % 64) / 4);
                for j = 1, chunks do
                    cipher_block[j] = XOR(plain_block[j], key_stream[j]);
                end

                cipher_count = cipher_count + 1;
                cipher[cipher_count] = pack(cipher_block);
            end
            return table_concat(cipher);
        end

        local decrypt = function(cipher, key, nonce)
            return encrypt(cipher, key, nonce);
        end

        security.chacha20 = {
            encrypt = encrypt,
            decrypt = decrypt,
        }
    end

    do
        local enc = {
            [0] =
            "A",
            "B",
            "C",
            "D",
            "E",
            "F",
            "G",
            "H",
            "I",
            "J",
            "K",
            "L",
            "M",
            "N",
            "O",
            "P",
            "Q",
            "R",
            "S",
            "T",
            "U",
            "V",
            "W",
            "X",
            "Y",
            "Z",
            "a",
            "b",
            "c",
            "d",
            "e",
            "f",
            "g",
            "h",
            "i",
            "j",
            "k",
            "l",
            "m",
            "n",
            "o",
            "p",
            "q",
            "r",
            "s",
            "t",
            "u",
            "v",
            "w",
            "x",
            "y",
            "z",
            "0",
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
            "8",
            "9",
            "+",
            "/"
        };

        local dec = {
            ["A"] = 0,
            ["B"] = 1,
            ["C"] = 2,
            ["D"] = 3,
            ["E"] = 4,
            ["F"] = 5,
            ["G"] = 6,
            ["H"] = 7,
            ["I"] = 8,
            ["J"] = 9,
            ["K"] = 10,
            ["L"] = 11,
            ["M"] = 12,
            ["N"] = 13,
            ["O"] = 14,
            ["P"] = 15,
            ["Q"] = 16,
            ["R"] = 17,
            ["S"] = 18,
            ["T"] = 19,
            ["U"] = 20,
            ["V"] = 21,
            ["W"] = 22,
            ["X"] = 23,
            ["Y"] = 24,
            ["Z"] = 25,
            ["a"] = 26,
            ["b"] = 27,
            ["c"] = 28,
            ["d"] = 29,
            ["e"] = 30,
            ["f"] = 31,
            ["g"] = 32,
            ["h"] = 33,
            ["i"] = 34,
            ["j"] = 35,
            ["k"] = 36,
            ["l"] = 37,
            ["m"] = 38,
            ["n"] = 39,
            ["o"] = 40,
            ["p"] = 41,
            ["q"] = 42,
            ["r"] = 43,
            ["s"] = 44,
            ["t"] = 45,
            ["u"] = 46,
            ["v"] = 47,
            ["w"] = 48,
            ["x"] = 49,
            ["y"] = 50,
            ["z"] = 51,
            ["0"] = 52,
            ["1"] = 53,
            ["2"] = 54,
            ["3"] = 55,
            ["4"] = 56,
            ["5"] = 57,
            ["6"] = 58,
            ["7"] = 59,
            ["8"] = 60,
            ["9"] = 61,
            ["+"] = 62,
            ["/"] = 63
        }

        local floor, table_concat = math.floor, table.concat;
        local encode = function(s)
            local r = s:len() % 3;
            s = r == 0 and s or s .. ("\0"):rep(3 - r);
            local b64 = {};
            local count = 0;
            local len = s:len();
            for i = 1, len, 3 do
                local b1, b2, b3 = s:byte(i, i + 2);
                count = count + 1;
                b64[count] = enc[floor(b1 / 0x04)];
                count = count + 1;
                b64[count] = enc[floor(b2 / 0x10) + (b1 % 0x04) * 0x10];
                count = count + 1;
                b64[count] = enc[floor(b3 / 0x40) + (b2 % 0x10) * 0x04];
                count = count + 1;
                b64[count] = enc[b3 % 0x40];
            end
            count = count + 1;
            b64[count] = (r == 0 and "" or ("="):rep(3 - r));
            return table_concat(b64);
        end

        local char, floor, table_concat = string.char, math.floor, table.concat;
        local decode = function(b64)
            local b, p = b64:gsub("=", "");
            local s = {};
            local count = 0;
            local len = b:len();
            for i = 1, len, 4 do
                local b1 = dec[b:sub(i, i)];
                local b2 = dec[b:sub(i + 1, i + 1)];
                local b3 = dec[b:sub(i + 2, i + 2)];
                local b4 = dec[b:sub(i + 3, i + 3)];
                count = count + 1;
                s[count] = char(
                    b1 * 0x04 + floor(b2 / 0x10),
                    (b2 % 0x10) * 0x10 + floor(b3 / 0x04),
                    (b3 % 0x04) * 0x40 + b4
                );
            end
            local result = table_concat(s);
            result = result:sub(1, -(p + 1));
            return result;
        end

        security.base64 = {
            encode = encode,
            decode = decode,
        }
    end

    do
        --------------------------------------------------------------------------------------------------------------------------
        --  Copyright (c) 2023, BernhardZat -- see LICENSE file                                                                 --
        --                                                                                                                      --
        --  X25519 elliptic-curve Diffie-Hellman key agreement implemented in pure Lua 5.1.                                     --
        --  Based on the original TweetNaCl library written in C. See https://tweetnacl.cr.yp.to/                               --
        --                                                                                                                      --
        --  Lua 5.1 doesn't have a 64 bit signed integer type and no bitwise operations.                                        --
        --  This implementation emulates bitwise operations arithmetically on 64 bit double precision floating point numbers.   --
        --  Note that double precision floating point numbers are only exact in the integer range of [-2^53, 2^53].             --
        --  This works for our purposes because values will not be outside the range of about [-2^43, 2^44].                    --
        --------------------------------------------------------------------------------------------------------------------------

        local carry = function(out)
            for i = 0, 15 do
                out[i] = out[i] + 0x10000;
                local c = out[i] / 0x10000 - (out[i] / 0x10000) % 1;
                if i < 15 then
                    out[i + 1] = out[i + 1] + c - 1;
                else
                    out[0] = out[0] + 38 * (c - 1);
                end
                out[i] = out[i] - c * 0x10000;
            end
        end

        local swap = function(a, b, bit)
            for i = 0, 15 do
                a[i], b[i] =
                    a[i] * ((bit - 1) % 2) + b[i] * bit,
                    b[i] * ((bit - 1) % 2) + a[i] * bit;
            end
        end

        local unpack = function(out, a)
            for i = 0, 15 do
                out[i] = a[2 * i] + a[2 * i + 1] * 0x100;
            end
            out[15] = out[15] % 0x8000;
        end

        local pack = function(out, a)
            local t, m = {}, {};
            for i = 0, 15 do
                t[i] = a[i];
            end
            carry(t);
            carry(t);
            carry(t);
            local prime = { [0] = 0xffed, [15] = 0x7fff };
            for i = 1, 14 do
                prime[i] = 0xffff;
            end
            for _ = 0, 1 do
                m[0] = t[0] - prime[0];
                for i = 1, 15 do
                    m[i] = t[i] - prime[i] - ((m[i - 1] / 0x10000 - (m[i - 1] / 0x10000) % 1) % 2);
                    m[i - 1] = (m[i - 1] + 0x10000) % 0x10000;
                end
                local c = (m[15] / 0x10000 - (m[15] / 0x10000) % 1) % 2;
                swap(t, m, 1 - c);
            end
            for i = 0, 15 do
                out[2 * i] = t[i] % 0x100;
                out[2 * i + 1] = t[i] / 0x100 - (t[i] / 0x100) % 1;
            end
        end

        local add = function(out, a, b)
            for i = 0, 15 do
                out[i] = a[i] + b[i];
            end
        end

        local sub = function(out, a, b)
            for i = 0, 15 do
                out[i] = a[i] - b[i];
            end
        end

        local mul = function(out, a, b)
            local prod = {};
            for i = 0, 31 do
                prod[i] = 0;
            end
            for i = 0, 15 do
                for j = 0, 15 do
                    prod[i + j] = prod[i + j] + a[i] * b[j];
                end
            end
            for i = 0, 14 do
                prod[i] = prod[i] + 38 * prod[i + 16];
            end
            for i = 0, 15 do
                out[i] = prod[i];
            end
            carry(out);
            carry(out);
        end

        local inv = function(out, a)
            local c = {};
            for i = 0, 15 do
                c[i] = a[i];
            end
            for i = 253, 0, -1 do
                mul(c, c, c);
                if i ~= 2 and i ~= 4 then
                    mul(c, c, a);
                end
            end
            for i = 0, 15 do
                out[i] = c[i];
            end
        end

        local scalarmult = function(out, scalar, point)
            local a, b, c, d, e, f, x, clam = {}, {}, {}, {}, {}, {}, {}, {};
            unpack(x, point);
            for i = 0, 15 do
                a[i], b[i], c[i], d[i] = 0, x[i], 0, 0;
            end
            a[0], d[0] = 1, 1;
            for i = 0, 30 do
                clam[i] = scalar[i];
            end
            clam[0] = clam[0] - (clam[0] % 8);
            clam[31] = scalar[31] % 64 + 64;
            for i = 254, 0, -1 do
                local bit = (clam[i / 8 - (i / 8) % 1] / 2 ^ (i % 8) - (clam[i / 8 - (i / 8) % 1] / 2 ^ (i % 8)) % 1) % 2;
                swap(a, b, bit);
                swap(c, d, bit);
                add(e, a, c);
                sub(a, a, c);
                add(c, b, d);
                sub(b, b, d);
                mul(d, e, e);
                mul(f, a, a);
                mul(a, c, a);
                mul(c, b, e);
                add(e, a, c);
                sub(a, a, c);
                mul(b, a, a);
                sub(c, d, f);
                mul(a, c, { [0] = 0xdb41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
                add(a, a, d);
                mul(c, c, a);
                mul(a, d, f);
                mul(d, b, x);
                mul(b, e, e);
                swap(a, b, bit);
                swap(c, d, bit);
            end
            inv(c, c);
            mul(a, a, c);
            pack(out, a);
        end

        local math_random = math.random
        local generate_keypair = function(rng)
            rng = rng or function() return math_random(0, 0xFF) end;
            local sk, pk = {}, {};
            for i = 0, 31 do
                sk[i] = rng();
            end
            local base = { [0] = 9 };
            for i = 1, 31 do
                base[i] = 0;
            end
            scalarmult(pk, sk, base);
            return sk, pk;
        end

        local get_shared_key = function(sk, pk)
            local shared = {};
            scalarmult(shared, sk, pk);
            return shared;
        end

        security.x25519 = {
            generate_keypair = generate_keypair,
            get_shared_key = get_shared_key,
        }
    end

    do
        local function key_to_string(key)
            local bytes = {};
            local char = string.char;
            for i = 0, 31 do
                bytes[i + 1] = char(key[i] or 0);
            end
            return security.base64.encode(table.concat(bytes));
        end

        local function string_to_key(str)
            local decoded = security.base64.decode(str);
            local len = #decoded;
            if not decoded or len ~= 32 then
                error("Invalid key length or decoding error");
            end
            local key = {};
            local byte = string.byte;
            for i = 1, len do
                key[i - 1] = byte(decoded, i);
            end
            return key;
        end

        local string_char, math_random = string.char, math.random
        local function generate_nonce()
            local nonce = "";
            for i = 1, 12 do
                nonce = nonce .. string_char(math_random(0, 255));
            end
            return security.base64.encode(nonce);
        end

        local string_gsub, math_random, string_format = string.gsub, math.random, string.format
        local function uuid()
            local template = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx';
            return string_gsub(template, '[xy]', function(c)
                local v = (c == 'x') and math_random(0, 15) or math_random(8, 11);
                return string_format('%x', v);
            end)
        end

        local table_insert = table.insert
        local function split(str, sep)
            local result = {};
            for part in str:gmatch("[^" .. sep .. "]+") do
                table_insert(result, part);
            end
            return result;
        end

        security.utils = {
            key_to_string = key_to_string,
            string_to_key = string_to_key,
            generate_nonce = generate_nonce,
            uuid = uuid,
            split = split
        };
    end
end

return security
end

-- lunac/libs/udp_messages.lua
__lupack__["lunac.libs.udp_messages"] = function()
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

local string_gsub, math_random, math_ceil, tostring, tonumber, string_format, table_insert, table_remove =
    string.gsub, math.random, math.ceil, tostring, tonumber, string.format, table.insert, table.remove
local function create()
    local max_message_size = nil
    local connections = {}
    local message_status = {}
    local fragment_buffer = {}

    local message_timeout = 2
    local max_retries = 10
    local max_fragment_size = 1000
    local max_packets_per_tick = 63

    local function uuid()
        local template = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
        return string_gsub(template, '[xy]', function(c)
            local v = (c == 'x') and math_random(0, 15) or math_random(8, 11)
            return string_format('%x', v)
        end)
    end

    local function send_message(message, ip, port)
        message = tostring(message)
        local message_id = uuid()
        local message_bytes = #message
        local total_fragments = math_ceil(message_bytes / max_fragment_size)

        if message_status[message_id] then return end

        local status = {
            ip = ip,
            port = port,
            fragments = {},
            fragments_to_send = {},
            total_fragments = total_fragments,
            acknowledged_count = 0,
            time_since_sent = 0,
            retries = 0
        }

        for i = 1, total_fragments do
            local start = (i - 1) * max_fragment_size + 1
            local fragment_data = message:sub(start, start + max_fragment_size - 1)
            local packet = string_format("MSG:%s:%d:%d:%s", message_id, i, total_fragments, fragment_data)

            local fragment_info = {
                packet = packet,
                acknowledged = false,
                fragment_num = i
            }

            status.fragments[i] = fragment_info
            table_insert(status.fragments_to_send, fragment_info)
        end

        message_status[message_id] = status
        return message_id
    end

    local function receive_message(socket)
        local completed_messages = {}
        while true do
            local data, ip, port = socket:receivefrom()
            if not data then break end

            if data:match("^ACK:") then
                local message_id, fragment_num_str = data:match("^ACK:(.-):(%d+)")
                local fragment_num = tonumber(fragment_num_str)

                local status = message_status[message_id]
                if status and status.fragments[fragment_num] and not status.fragments[fragment_num].acknowledged then
                    status.fragments[fragment_num].acknowledged = true
                    status.acknowledged_count = status.acknowledged_count + 1

                    if status.acknowledged_count == status.total_fragments then
                        message_status[message_id] = nil
                    end
                end

            elseif data:match("^MSG:") then
                local message_id, frag_num, total_frags, fragment = data:match("^MSG:(.-):(%d+):(%d+):(.*)")
                frag_num = tonumber(frag_num)
                total_frags = tonumber(total_frags)

                if message_id and frag_num and total_frags and fragment then
                    socket:sendto(string_format("ACK:%s:%d", message_id, frag_num), ip, port)

                    local client_key = ip .. ":" .. port
                    fragment_buffer[client_key] = fragment_buffer[client_key] or {}

                    local msg_buffer = fragment_buffer[client_key][message_id]
                    if not msg_buffer then
                        msg_buffer = { fragments = {}, received_count = 0, total_fragments = total_frags, total_size = 0 }
                        fragment_buffer[client_key][message_id] = msg_buffer
                    end

                    if not msg_buffer.fragments[frag_num] then
                        local new_size = msg_buffer.total_size + #fragment
                        if max_message_size and new_size > max_message_size then
                            print("Message " .. message_id .. " from " .. client_key .. " exceeds max_message_size of " .. max_message_size .. " bytes. Discarding.")
                            fragment_buffer[client_key][message_id] = nil
                            return completed_messages
                        end

                        msg_buffer.fragments[frag_num] = fragment
                        msg_buffer.received_count = msg_buffer.received_count + 1
                        msg_buffer.total_size = new_size

                        if msg_buffer.received_count == msg_buffer.total_fragments then
                            local parts = {}
                            for i = 1, msg_buffer.total_fragments do
                                table_insert(parts, msg_buffer.fragments[i] or "")
                            end
                            local complete_message = table.concat(parts)
                            table_insert(completed_messages, { message = complete_message, ip = ip, port = port })
                            fragment_buffer[client_key][message_id] = nil
                        end
                    end
                end
            end
        end
        return completed_messages
    end

    local function update(socket, dt)
        local packets_sent_this_tick = 0
        for id, status in pairs(message_status) do
            while #status.fragments_to_send > 0 do
                if packets_sent_this_tick >= max_packets_per_tick then
                    break
                end

                local fragment_info = status.fragments_to_send[1]

                local bytes_sent, err = socket:sendto(fragment_info.packet, status.ip, status.port)

                if bytes_sent then
                    table_remove(status.fragments_to_send, 1)
                    packets_sent_this_tick = packets_sent_this_tick + 1
                    status.time_since_sent = 0
                else
                    break
                end
            end
            if packets_sent_this_tick >= max_packets_per_tick then
                break
            end
        end

        for id, status in pairs(message_status) do
            status.time_since_sent = status.time_since_sent + dt

            if status.time_since_sent > message_timeout then
                if status.retries < max_retries then
                    status.retries = status.retries + 1
                    status.time_since_sent = 0

                    for i = 1, status.total_fragments do
                        local frag_info = status.fragments[i]
                        if not frag_info.acknowledged then
                            local already_in_queue = false
                            for _, f in pairs(status.fragments_to_send) do
                                if f.fragment_num == i then
                                    already_in_queue = true
                                    break
                                end
                            end
                            if not already_in_queue then
                                table_insert(status.fragments_to_send, frag_info)
                            end
                        end
                    end
                else
                    print("Failed to deliver message " .. id .. " after " .. max_retries .. " retries.")
                    message_status[id] = nil
                end
            end
        end
    end

    local new_connect = function(socket, myip, myport)
        local client_key = myip .. ":" .. myport
        if connections[client_key] then
            connections[client_key]:close()
        end

        local connect = {
            socket = socket,
            ip = myip,
            port = myport,
            is_close = false,
        }
        connections[client_key] = connect

        function connect:send(message)
            return send_message(message, self.ip, self.port)
        end

        function connect:getpeername()
            return self.ip, self.port
        end

        function connect:close()
            pcall(function () self.socket:close() end)
            if connections[client_key] then
                fragment_buffer[client_key] = nil
                connections[client_key] = nil
            end
            connect.is_close = true
        end

        return connect
    end

    local function set_max_messages_size(new_max_messages_size)
        max_message_size = new_max_messages_size
    end

    local function set_max_retries(new_max_retries)
        max_retries = new_max_retries
    end

    local function set_message_timeout(new_message_timeout)
        message_timeout = new_message_timeout
    end

    return {
        new_connect = new_connect,
        send_message = send_message,
        receive_message = receive_message,
        connections = connections,
        update = update,
        set_max_messages_size = set_max_messages_size,
        set_max_retries = set_max_retries,
        set_message_timeout = set_message_timeout,
    }
end

return create
end

-- lunac/libs/web-serv.lua
__lupack__["lunac.libs.web-serv"] = function()
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

--[[
Copyright (c) 2012 by Gerhard Lipp <gelipp@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
]]

if not __lupack__ then _G.__lupack__ = {} end
local __lupack__ = __lupack__ or {}
local __orig_require__ = require
local require = function(path)
    if __lupack__[path] then
        return __lupack__[path]()
    elseif __lupack__[path .. ".init"] then
        return __lupack__[path .. ".init"]()
    end
    return __orig_require__(path)
end

__lupack__["webserv"] = function()
    local frame = require 'webserv.frame'

    return {
        server = require 'webserv.server_sync',
        client = require 'webserv.client_sync',
        CONTINUATION = frame.CONTINUATION,
        TEXT = frame.TEXT,
        BINARY = frame.BINARY,
        CLOSE = frame.CLOSE,
        PING = frame.PING,
        PONG = frame.PONG
    }
end

__lupack__["webserv.bit"] = function()
    local has_bit32, bit = pcall(require, 'bit32')
    if has_bit32 then
        bit.rol = bit.lrotate
        bit.ror = bit.rrotate
        return bit
    else
        local s, e = pcall(require, "bit")
        if not s then
            s, e = pcall(require, "plugin.bit")
            if not s then
                local M = { _TYPE = 'module', _NAME = 'bitop.funcs', _VERSION = '1.0-0' }

                local floor = math.floor

                local MOD = 2 ^ 32
                local MODM = MOD - 1

                local function memoize(f)
                    local mt = {}
                    local t = setmetatable({}, mt)

                    function mt:__index(k)
                        local v = f(k)
                        t[k] = v
                        return v
                    end

                    return t
                end

                local function make_bitop_uncached(t, m)
                    local function bitop(a, b)
                        local res, p = 0, 1
                        while a ~= 0 and b ~= 0 do
                            local am, bm = a % m, b % m
                            res = res + t[am][bm] * p
                            a = (a - am) / m
                            b = (b - bm) / m
                            p = p * m
                        end
                        res = res + (a + b) * p
                        return res
                    end
                    return bitop
                end

                local function make_bitop(t)
                    local op1 = make_bitop_uncached(t, 2 ^ 1)
                    local op2 = memoize(function(a)
                        return memoize(function(b)
                            return op1(a, b)
                        end)
                    end)
                    return make_bitop_uncached(op2, 2 ^ (t.n or 1))
                end

                function M.tobit(x)
                    return x % 2 ^ 32
                end

                M.bxor = make_bitop { [0] = { [0] = 0, [1] = 1 }, [1] = { [0] = 1, [1] = 0 }, n = 4 }
                local bxor = M.bxor

                function M.bnot(a) return MODM - a end

                local bnot = M.bnot

                function M.band(a, b) return ((a + b) - bxor(a, b)) / 2 end

                local band = M.band

                function M.bor(a, b) return MODM - band(MODM - a, MODM - b) end

                local bor = M.bor

                local lshift, rshift

                function M.rshift(a, disp)
                    if disp < 0 then return lshift(a, -disp) end
                    return floor(a % 2 ^ 32 / 2 ^ disp)
                end

                rshift = M.rshift

                function M.lshift(a, disp)
                    if disp < 0 then return rshift(a, -disp) end
                    return (a * 2 ^ disp) % 2 ^ 32
                end

                lshift = M.lshift

                function M.tohex(x, n)
                    n = n or 8
                    local up
                    if n <= 0 then
                        if n == 0 then return '' end
                        up = true
                        n = -n
                    end
                    x = band(x, 16 ^ n - 1)
                    return ('%0' .. n .. (up and 'X' or 'x')):format(x)
                end

                local tohex = M.tohex

                function M.extract(n, field, width)
                    width = width or 1
                    return band(rshift(n, field), 2 ^ width - 1)
                end

                local extract = M.extract

                function M.replace(n, v, field, width)
                    width = width or 1
                    local mask1 = 2 ^ width - 1
                    v = band(v, mask1)
                    local mask = bnot(lshift(mask1, field))
                    return band(n, mask) + lshift(v, field)
                end

                local replace = M.replace

                function M.bswap(x)
                    local a = band(x, 0xff); x = rshift(x, 8)
                    local b = band(x, 0xff); x = rshift(x, 8)
                    local c = band(x, 0xff); x = rshift(x, 8)
                    local d = band(x, 0xff)
                    return lshift(lshift(lshift(a, 8) + b, 8) + c, 8) + d
                end

                local bswap = M.bswap

                function M.rrotate(x, disp)
                    disp = disp % 32
                    local low = band(x, 2 ^ disp - 1)
                    return rshift(x, disp) + lshift(low, 32 - disp)
                end

                local rrotate = M.rrotate

                function M.lrotate(x, disp)
                    return rrotate(x, -disp)
                end

                local lrotate = M.lrotate

                M.rol = M.lrotate
                M.ror = M.rrotate


                function M.arshift(x, disp)
                    local z = rshift(x, disp)
                    if x >= 0x80000000 then z = z + lshift(2 ^ disp - 1, 32 - disp) end
                    return z
                end

                local arshift = M.arshift

                function M.btest(x, y)
                    return band(x, y) ~= 0
                end

                M.bit32 = {}


                local function bit32_bnot(x)
                    return (-1 - x) % MOD
                end
                M.bit32.bnot = bit32_bnot

                local function bit32_bxor(a, b, c, ...)
                    local z
                    if b then
                        a = a % MOD
                        b = b % MOD
                        z = bxor(a, b)
                        if c then
                            z = bit32_bxor(z, c, ...)
                        end
                        return z
                    elseif a then
                        return a % MOD
                    else
                        return 0
                    end
                end
                M.bit32.bxor = bit32_bxor

                local function bit32_band(a, b, c, ...)
                    local z
                    if b then
                        a = a % MOD
                        b = b % MOD
                        z = ((a + b) - bxor(a, b)) / 2
                        if c then
                            z = bit32_band(z, c, ...)
                        end
                        return z
                    elseif a then
                        return a % MOD
                    else
                        return MODM
                    end
                end
                M.bit32.band = bit32_band

                local function bit32_bor(a, b, c, ...)
                    local z
                    if b then
                        a = a % MOD
                        b = b % MOD
                        z = MODM - band(MODM - a, MODM - b)
                        if c then
                            z = bit32_bor(z, c, ...)
                        end
                        return z
                    elseif a then
                        return a % MOD
                    else
                        return 0
                    end
                end
                M.bit32.bor = bit32_bor

                function M.bit32.btest(...)
                    return bit32_band(...) ~= 0
                end

                function M.bit32.lrotate(x, disp)
                    return lrotate(x % MOD, disp)
                end

                function M.bit32.rrotate(x, disp)
                    return rrotate(x % MOD, disp)
                end

                function M.bit32.lshift(x, disp)
                    if disp > 31 or disp < -31 then return 0 end
                    return lshift(x % MOD, disp)
                end

                function M.bit32.rshift(x, disp)
                    if disp > 31 or disp < -31 then return 0 end
                    return rshift(x % MOD, disp)
                end

                function M.bit32.arshift(x, disp)
                    x = x % MOD
                    if disp >= 0 then
                        if disp > 31 then
                            return (x >= 0x80000000) and MODM or 0
                        else
                            local z = rshift(x, disp)
                            if x >= 0x80000000 then z = z + lshift(2 ^ disp - 1, 32 - disp) end
                            return z
                        end
                    else
                        return lshift(x, -disp)
                    end
                end

                function M.bit32.extract(x, field, ...)
                    local width = ... or 1
                    if field < 0 or field > 31 or width < 0 or field + width > 32 then error 'out of range' end
                    x = x % MOD
                    return extract(x, field, ...)
                end

                function M.bit32.replace(x, v, field, ...)
                    local width = ... or 1
                    if field < 0 or field > 31 or width < 0 or field + width > 32 then error 'out of range' end
                    x = x % MOD
                    v = v % MOD
                    return replace(x, v, field, ...)
                end

                M.bit = {}

                function M.bit.tobit(x)
                    x = x % MOD
                    if x >= 0x80000000 then x = x - MOD end
                    return x
                end

                local bit_tobit = M.bit.tobit

                function M.bit.tohex(x, ...)
                    return tohex(x % MOD, ...)
                end

                function M.bit.bnot(x)
                    return bit_tobit(bnot(x % MOD))
                end

                local function bit_bor(a, b, c, ...)
                    if c then
                        return bit_bor(bit_bor(a, b), c, ...)
                    elseif b then
                        return bit_tobit(bor(a % MOD, b % MOD))
                    else
                        return bit_tobit(a)
                    end
                end
                M.bit.bor = bit_bor

                local function bit_band(a, b, c, ...)
                    if c then
                        return bit_band(bit_band(a, b), c, ...)
                    elseif b then
                        return bit_tobit(band(a % MOD, b % MOD))
                    else
                        return bit_tobit(a)
                    end
                end
                M.bit.band = bit_band

                local function bit_bxor(a, b, c, ...)
                    if c then
                        return bit_bxor(bit_bxor(a, b), c, ...)
                    elseif b then
                        return bit_tobit(bxor(a % MOD, b % MOD))
                    else
                        return bit_tobit(a)
                    end
                end
                M.bit.bxor = bit_bxor

                function M.bit.lshift(x, n)
                    return bit_tobit(lshift(x % MOD, n % 32))
                end

                function M.bit.rshift(x, n)
                    return bit_tobit(rshift(x % MOD, n % 32))
                end

                function M.bit.arshift(x, n)
                    return bit_tobit(arshift(x % MOD, n % 32))
                end

                function M.bit.rol(x, n)
                    return bit_tobit(lrotate(x % MOD, n % 32))
                end

                function M.bit.ror(x, n)
                    return bit_tobit(rrotate(x % MOD, n % 32))
                end

                function M.bit.bswap(x)
                    return bit_tobit(bswap(x % MOD))
                end

                return M
            end
            return e
        end
        return e
    end
end

__lupack__["webserv.frame"] = function()
    local bit, tools = require 'webserv.bit', require 'webserv.tools'
    local bxor, bor, band, rshift = bit.bxor, bit.bor, bit.band, bit.rshift
    local ssub, sbyte, schar = string.sub, string.byte, string.char
    local tinsert, tconcat = table.insert, table.concat
    local mmin, mfloor, mrandom = math.min, math.floor, math.random
    local unpack = unpack or table.unpack
    local write_int8, write_int16, write_int32 = tools.write_int8, tools.write_int16, tools.write_int32
    local read_int8, read_int16, read_int32 = tools.read_int8, tools.read_int16, tools.read_int32

    local bit_7, bit_0_3, bit_0_6
    do
        local bits = function(...)
            local n = 0
            for _, bitn in pairs { ... } do
                n = n + 2 ^ bitn
            end
            return n
        end

        bit_7, bit_0_3, bit_0_6 = bits(7), bits(0, 1, 2, 3), bits(0, 1, 2, 3, 4, 5, 6)
    end

    local xor_mask = function(encoded, mask, payload)
        local transformed, transformed_arr = {}, {}
        for p = 1, payload, 2000 do
            local last = mmin(p + 1999, payload)
            local original = { sbyte(encoded, p, last) }
            for i = 1, #original do
                local j = (i - 1) % 4 + 1
                transformed[i] = bxor(original[i], mask[j])
            end
            local xored = schar(unpack(transformed, 1, #original))
            tinsert(transformed_arr, xored)
        end
        return tconcat(transformed_arr)
    end

    local encode_header_small = function(header, payload)
        return schar(header, payload)
    end

    local encode_header_medium = function(header, payload, len)
        return schar(header, payload, band(rshift(len, 8), 0xFF), band(len, 0xFF))
    end

    local encode_header_big = function(header, payload, high, low)
        return schar(header, payload) .. write_int32(high) .. write_int32(low)
    end

    local encode = function(data, opcode, masked, fin)
        local header = opcode or 1
        if fin == nil or fin == true then
            header = bor(header, bit_7)
        end
        local payload = 0
        if masked then
            payload = bor(payload, bit_7)
        end
        local len = #data
        local chunks = {}
        if len < 126 then
            payload = bor(payload, len)
            tinsert(chunks, encode_header_small(header, payload))
        elseif len <= 0xffff then
            payload = bor(payload, 126)
            tinsert(chunks, encode_header_medium(header, payload, len))
        elseif len < 2 ^ 53 then
            local high = mfloor(len / 2 ^ 32)
            local low = len - high * 2 ^ 32
            payload = bor(payload, 127)
            tinsert(chunks, encode_header_big(header, payload, high, low))
        end
        if not masked then
            tinsert(chunks, data)
        else
            local m1 = mrandom(0, 0xff)
            local m2 = mrandom(0, 0xff)
            local m3 = mrandom(0, 0xff)
            local m4 = mrandom(0, 0xff)
            local mask = { m1, m2, m3, m4 }
            tinsert(chunks, write_int8(m1, m2, m3, m4))
            tinsert(chunks, xor_mask(data, mask, #data))
        end
        return tconcat(chunks)
    end

    local decode = function(encoded)
        local encoded_bak = encoded
        if #encoded < 2 then
            return nil, 2 - #encoded
        end
        local pos, header, payload
        pos, header = read_int8(encoded, 1)
        pos, payload = read_int8(encoded, pos)
        local high, low
        encoded = ssub(encoded, pos)
        local bytes, fin, opcode, mask, payload = 2, band(header, bit_7) > 0, band(header, bit_0_3), band(payload, bit_7) > 0, band(payload, bit_0_6)
        if payload > 125 then
            if payload == 126 then
                if #encoded < 2 then
                    return nil, 2 - #encoded
                end
                pos, payload = read_int16(encoded, 1)
            elseif payload == 127 then
                if #encoded < 8 then
                    return nil, 8 - #encoded
                end
                pos, high = read_int32(encoded, 1)
                pos, low = read_int32(encoded, pos)
                payload = high * 2 ^ 32 + low
                if payload < 0xffff or payload > 2 ^ 53 then
                    assert(false, 'INVALID PAYLOAD ' .. payload)
                end
            else
                assert(false, 'INVALID PAYLOAD ' .. payload)
            end
            encoded = ssub(encoded, pos)
            bytes = bytes + pos - 1
        end
        local decoded
        if mask then
            local bytes_short = payload + 4 - #encoded
            if bytes_short > 0 then
                return nil, bytes_short
            end
            local m1, m2, m3, m4
            pos, m1 = read_int8(encoded, 1)
            pos, m2 = read_int8(encoded, pos)
            pos, m3 = read_int8(encoded, pos)
            pos, m4 = read_int8(encoded, pos)
            encoded = ssub(encoded, pos)
            local mask = {
                m1, m2, m3, m4
            }
            decoded = xor_mask(encoded, mask, payload)
            bytes = bytes + 4 + payload
        else
            local bytes_short = payload - #encoded
            if bytes_short > 0 then
                return nil, bytes_short
            end
            if #encoded > payload then
                decoded = ssub(encoded, 1, payload)
            else
                decoded = encoded
            end
            bytes = bytes + payload
        end
        return decoded, fin, opcode, encoded_bak:sub(bytes + 1), mask
    end

    local encode_close = function(code, reason)
        if code then
            local data = write_int16(code)
            if reason then
                data = data .. tostring(reason)
            end
            return data
        end
        return ''
    end

    local decode_close = function(data)
        local _, code, reason
        if data then
            local len = #data
            if len > 1 then
                _, code = read_int16(data, 1)
            end
            if len > 2 then
                reason = data:sub(3)
            end
        end
        return code, reason
    end

    return {
        encode = encode,
        decode = decode,
        encode_close = encode_close,
        decode_close = decode_close,
        encode_header_small = encode_header_small,
        encode_header_medium = encode_header_medium,
        encode_header_big = encode_header_big,
        CONTINUATION = 0,
        TEXT = 1,
        BINARY = 2,
        CLOSE = 8,
        PING = 9,
        PONG = 10
    }
end

__lupack__["webserv.handshake"] = function()
    local sha1, base64, tinsert, guid, table_concat, string_format =
        require 'webserv.tools'.sha1,
        require 'webserv.tools'.base64,
        table.insert,
        "258EAFA5-E914-47DA-95CA-C5AB0DC85B11",
        table.concat,
        string.format

    local sec_websocket_accept = function(sec_websocket_key)
        local a = sec_websocket_key .. guid
        local sha1 = sha1(a)
        assert((#sha1 % 2) == 0)
        return base64.encode(sha1)
    end

    local http_headers = function(request)
        local headers = {}
        if not request:match('.*HTTP/1%.1') then
            return headers
        end
        request = request:match('[^\r\n]+\r\n(.*)')
        for line in request:gmatch('[^\r\n]*\r\n') do
            local name, val = line:match('([^%s]+)%s*:%s*([^\r\n]+)')
            if name and val then
                name = name:lower()
                if not name:match('sec%-websocket') then
                    val = val:lower()
                end
                if not headers[name] then
                    headers[name] = val
                else
                    headers[name] = headers[name] .. ',' .. val
                end
            else
                assert(false, line .. '(' .. #line .. ')')
            end
        end
        return headers, request:match('\r\n\r\n(.*)')
    end

    local upgrade_request = function(req)
        local format = string_format
        local lines = {
            format('GET %s HTTP/1.1', req.uri or ''),
            format('Host: %s', req.host),
            'Upgrade: websocket',
            'Connection: Upgrade',
            format('Sec-WebSocket-Key: %s', req.key),
            format('Sec-WebSocket-Protocol: %s', table_concat(req.protocols, ', ')),
            'Sec-WebSocket-Version: 13',
        }
        if req.origin then
            tinsert(lines, format('Origin: %s', req.origin))
        end
        if req.port and req.port ~= 80 then
            lines[2] = format('Host: %s:%d', req.host, req.port)
        end
        tinsert(lines, '\r\n')
        return table_concat(lines, '\r\n')
    end

    local accept_upgrade = function(request, protocols)
        local headers = http_headers(request)
        if headers['upgrade'] ~= 'websocket' or
            not headers['connection'] or
            not headers['connection']:match('upgrade') or
            headers['sec-websocket-key'] == nil or
            headers['sec-websocket-version'] ~= '13' then
            return nil, 'HTTP/1.1 400 Bad Request\r\n\r\n'
        end
        local prot
        if headers['sec-websocket-protocol'] then
            for protocol in headers['sec-websocket-protocol']:gmatch('([^,%s]+)%s?,?') do
                for _, supported in ipairs(protocols) do
                    if supported == protocol then
                        prot = protocol
                        break
                    end
                end
                if prot then
                    break
                end
            end
        end
        local lines = {
            'HTTP/1.1 101 Switching Protocols',
            'Upgrade: websocket',
            'Connection: ' .. headers['connection'],
            string_format('Sec-WebSocket-Accept: %s', sec_websocket_accept(headers['sec-websocket-key'])),
        }
        if prot then
            tinsert(lines, string_format('Sec-WebSocket-Protocol: %s', prot))
        end
        tinsert(lines, '\r\n')
        return table_concat(lines, '\r\n'), prot
    end

    return {
        sec_websocket_accept = sec_websocket_accept,
        http_headers = http_headers,
        accept_upgrade = accept_upgrade,
        upgrade_request = upgrade_request,
    }
end

__lupack__["webserv.server_sync"] = function()
    local pairs, ipairs, tostring, pcall, error, assert,
          table, math, coroutine =
        pairs, ipairs, tostring, pcall, error, assert,
        table, math, coroutine

    local ssl
    local socket, handshake, sync,
    tconcat, tinsert, table_remove,
    math_min,
    coroutine_yield, coroutine_status, coroutine_resume, coroutine_create
    =
        require 'socket', require 'webserv.handshake', require 'webserv.sync',
        table.concat, table.insert, table.remove,
        math.min,
        coroutine.yield, coroutine.status, coroutine.resume, coroutine.create

    local function process_sockets(read_sockets, write_sockets, batch_size, timeout)
        timeout = timeout or 0
        local readable, writable = {}, {}

        local len_r = #read_sockets
        for i = 1, len_r, batch_size do
            local batch = {}
            for j = i, math_min(i + batch_size - 1, len_r) do
                tinsert(batch, read_sockets[j])
            end

            local r, _, err = socket.select(batch, nil, timeout)
            if err and err ~= "timeout" then
                return nil, nil, err
            end

            for _, sock in ipairs(r or {}) do
                tinsert(readable, sock)
            end
        end

        local len_w = #write_sockets
        for i = 1, len_w, batch_size do
            local batch = {}
            for j = i, math_min(i + batch_size - 1, len_w) do
                tinsert(batch, write_sockets[j])
            end

            local _, w, err = socket.select(nil, batch, timeout)
            if err and err ~= "timeout" then
                return nil, nil, err
            end

            for _, sock in ipairs(w or {}) do
                tinsert(writable, sock)
            end
        end

        return readable, writable
    end

    local client = function(sock, raw_sock, protocol, clients)
        local self = {}

        self.state = 'OPEN'
        self.is_server = true
        self.sock = sock
        self.raw_sock = raw_sock or sock

        self.getpeername = function(self)
            local ip, port, err
            if self.raw_sock and self.raw_sock.getpeername then
                ip, port, err = self.raw_sock:getpeername()
                if ip and port then
                    return ip, port
                end
            end

            if self.sock and self.sock.getpeername and self.sock ~= self.raw_sock then
                ip, port, err = self.sock:getpeername()
                if ip and port then
                    return ip, port
                end
            end

            return "unknown", 0
        end

        self.sock_send = function(self, data)
            local index = 1
            while index <= #data do
                local sent, err, last = self.sock:send(data, index)
                if sent then
                    index = index + sent
                else
                    if err == "timeout" or err == "wantwrite" then
                        index = last + 1
                    else
                        return nil, err
                    end
                    coroutine_yield("wantwrite")
                end
            end
            return #data
        end

        self.sock_receive = function(self, pattern, prefix)
            local s, err, p = self.sock:receive(pattern, prefix or "")
            if s then
                return s
            end
            if err == "timeout" or err == "wantread" then
                coroutine_yield("wantread")
                return self:sock_receive(pattern, p)
            end
            return nil, err
        end

        self.sock_close = function(self)
            clients[protocol][self] = nil
            if self.sock.shutdown then
                self.sock:shutdown()
            end
            self.sock:close()
            if self.raw_sock and self.raw_sock ~= self.sock then
                if self.raw_sock.shutdown then
                    self.raw_sock:shutdown()
                end
                self.raw_sock:close()
            end
        end

        self = sync.extend(self)

        self.on_close = function(self) end

        self.broadcast = function(self, data, opcode)
            for client in pairs(clients[protocol]) do
                client:send(data, opcode)
            end
        end

        return self
    end

    local listen = function(opts)
        opts.protocols = opts.protocols or {}
        assert(opts and (opts.protocols or opts.protocols.default))
        local on_error = opts.on_error or function(s) print(s) end

        local raw_listener, err = socket.bind(opts.host or '*', opts.port or 80)
        if err then
            error(err)
        end
        raw_listener:settimeout(0)
        pcall(function()
            raw_listener:listen(1024)
        end)

        local clients = {}
        local protocols = {}
        if opts.protocols then
            for protocol in pairs(opts.protocols) do
                clients[protocol] = {}
                tinsert(protocols, protocol)
            end
        end
        clients[true] = {}
        local pendings = {}

        local ssl_ctx
        if opts.ssl then
            if not ssl then
                ssl = require("ssl")
            end
            ssl_ctx = ssl.newcontext(opts.ssl)
        end

        local self = {}
        self.update = function()
            local read_socks = { raw_listener }
            local write_socks = {}

            for _, p in ipairs(pendings) do
                tinsert(read_socks, p.sock)
            end

            for protocol_index, clts in pairs(clients) do
                for cl in pairs(clts) do
                    if cl.co and coroutine_status(cl.co) ~= "dead" then
                        if cl.waiting_for == "read" then
                            tinsert(read_socks, cl.sock)
                        elseif cl.waiting_for == "write" then
                            tinsert(write_socks, cl.sock)
                        end
                    end
                end
            end

            local readable, writable, select_err = process_sockets(read_socks, write_socks, 60, 0)
            if select_err == "timeout" then
                return
            end

            for _, skt in ipairs(readable or {}) do
                if skt == raw_listener then
                    local newsock, accept_err = raw_listener:accept()
                    if newsock then
                        newsock:settimeout(0)
                        newsock:setoption('tcp-nodelay', true)

                        if ssl_ctx then
                            local ssl_sock, ssl_err = ssl.wrap(newsock, ssl_ctx)
                            if not ssl_sock then
                                newsock:close()
                                if on_error then
                                    on_error("SSL wrap failed: " .. tostring(ssl_err))
                                end
                            else
                                ssl_sock:settimeout(0)
                                local pending = {
                                    sock = ssl_sock,
                                    raw_sock = newsock,
                                    buffer = "",
                                    request = {},
                                    ssl_handshake_done = false
                                }
                                tinsert(pendings, pending)
                            end
                        else
                            local pending = {
                                sock = newsock,
                                raw_sock = newsock,
                                buffer = "",
                                request = {},
                                ssl_handshake_done = true
                            }
                            tinsert(pendings, pending)
                        end
                    elseif accept_err ~= "timeout" then
                        if on_error then
                            on_error(accept_err)
                        end
                    end
                else
                    local handled = false
                    for i = #pendings, 1, -1 do
                        local p = pendings[i]
                        if p.sock == skt then
                            handled = true

                            if ssl_ctx and not p.ssl_handshake_done then
                                local success, handshake_err = p.sock:dohandshake()
                                if success then
                                    p.ssl_handshake_done = true
                                elseif handshake_err == "wantread" or handshake_err == "wantwrite" then
                                    break
                                else
                                    p.sock:close()
                                    p.raw_sock:close()
                                    table_remove(pendings, i)
                                    if on_error then
                                        on_error('SSL handshake failed: ' .. tostring(handshake_err))
                                    end
                                    break
                                end
                            end

                            if not ssl_ctx or p.ssl_handshake_done then
                                local line, r_err, partial = p.sock:receive('*l', p.buffer)
                                if line then
                                    p.buffer = ""
                                    tinsert(p.request, line)
                                    if line == '' then
                                        local upgrade_request = tconcat(p.request, '\r\n')
                                        local response, protocol = handshake.accept_upgrade(upgrade_request, protocols)
                                        if not response then
                                            p.sock:send(protocol)
                                            p.sock:close()
                                            p.raw_sock:close()
                                            table_remove(pendings, i)
                                            if on_error then
                                                on_error('invalid request')
                                            end
                                            break
                                        end

                                        local resp_data = response
                                        local resp_index = 1
                                        while resp_index <= #resp_data do
                                            local sent, s_err, s_last = p.sock:send(resp_data, resp_index)
                                            if sent then
                                                resp_index = resp_index + sent
                                            else
                                                if s_err == "timeout" then
                                                    resp_index = s_last + 1
                                                else
                                                    p.sock:close()
                                                    p.raw_sock:close()
                                                    table_remove(pendings, i)
                                                    if on_error then
                                                        on_error(s_err)
                                                    end
                                                    break
                                                end
                                            end
                                        end

                                        local protocol_index
                                        local handler
                                        if protocol and opts.protocols[protocol] then
                                            protocol_index = protocol
                                            handler = opts.protocols[protocol]
                                        elseif opts.protocols.default then
                                            protocol_index = true
                                            handler = opts.protocols.default
                                        else
                                            p.sock:close()
                                            p.raw_sock:close()
                                            if on_error then
                                                on_error('bad protocol')
                                            end
                                            table_remove(pendings, i)
                                            break
                                        end

                                        local new_client = client(p.sock, p.raw_sock, protocol_index, clients)
                                        clients[protocol_index][new_client] = true
                                        new_client.waiting_for = nil
                                        new_client.co = coroutine_create(function()
                                            handler(new_client)
                                        end)
                                        local ok, res = coroutine_resume(new_client.co)
                                        if not ok then
                                            if on_error then
                                                on_error(res)
                                            end
                                            new_client:close()
                                        elseif coroutine_status(new_client.co) == "dead" then
                                            new_client:close()
                                        else
                                            new_client.waiting_for = res == "wantread" and "read" or
                                                (res == "wantwrite" and "write" or nil)
                                        end
                                        table_remove(pendings, i)
                                    end
                                elseif r_err == "timeout" or r_err == "wantread" or r_err == "wantwrite" then
                                    p.buffer = partial
                                else
                                    p.sock:close()
                                    p.raw_sock:close()
                                    table_remove(pendings, i)
                                    if on_error then
                                        on_error(r_err)
                                    end
                                end
                            end
                            break
                        end
                    end

                    if not handled then
                        for protocol_index, clts in pairs(clients) do
                            for cl in pairs(clts) do
                                if cl.sock == skt then
                                    local ok, res = coroutine_resume(cl.co)
                                    if not ok then
                                        if on_error then
                                            on_error(res)
                                        end
                                        cl:close()
                                    elseif coroutine_status(cl.co) == "dead" then
                                        cl:close()
                                    else
                                        cl.waiting_for = res == "wantread" and "read" or
                                            (res == "wantwrite" and "write" or nil)
                                    end
                                    break
                                end
                            end
                        end
                    end
                end
            end

            for _, skt in ipairs(writable or {}) do
                for protocol_index, clts in pairs(clients) do
                    for cl in pairs(clts) do
                        if cl.sock == skt then
                            local ok, res = coroutine_resume(cl.co)
                            if not ok then
                                if on_error then
                                    on_error(res)
                                end
                                cl:close()
                            elseif coroutine_status(cl.co) == "dead" then
                                cl:close()
                            else
                                cl.waiting_for = res == "wantread" and "read" or (res == "wantwrite" and "write" or nil)
                            end
                            break
                        end
                    end
                end
            end
        end

        self.close = function(_, keep_clients)
            if raw_listener then
                raw_listener:close()
                raw_listener = nil
            end
            for i = #pendings, 1, -1 do
                pendings[i].sock:close()
                if pendings[i].raw_sock ~= pendings[i].sock then
                    pendings[i].raw_sock:close()
                end
                table_remove(pendings, i)
            end
            if not keep_clients then
                for protocol, clts in pairs(clients) do
                    for cl in pairs(clts) do
                        cl:close()
                    end
                end
            end
        end

        return self
    end

    return {
        listen = listen
    }
end

__lupack__["webserv.sync"] = function()
    local ssl
    local frame, handshake, tools = require 'webserv.frame', require 'webserv.handshake', require 'webserv.tools'
    local tinsert, tconcat, type = table.insert, table.concat, type

    local receive = function(self)
        if self.state ~= 'OPEN' and not self.is_closing then
            return nil, nil, false, 1006, 'wrong state'
        end
        local first_opcode
        local frames
        local bytes = 3
        local encoded = ''
        local clean = function(was_clean, code, reason)
            self.state = 'CLOSED'
            self:sock_close()
            if self.on_close then
                self:on_close()
            end
            return nil, nil, was_clean, code, reason or 'closed'
        end
        while true do
            local chunk, err = self:sock_receive(bytes)
            if err then
                return clean(false, 1006, err)
            end
            encoded = encoded .. chunk
            local decoded, fin, opcode, _, masked = frame.decode(encoded)
            if not self.is_server and masked then
                return clean(false, 1006, 'Websocket receive failed: frame was not masked')
            end
            if decoded then
                if opcode == frame.CLOSE then
                    if not self.is_closing then
                        local code, reason = frame.decode_close(decoded)
                        local msg = frame.encode_close(code)
                        local encoded = frame.encode(msg, frame.CLOSE, not self.is_server)
                        local n, err = self:sock_send(encoded)
                        if n == #encoded then
                            return clean(true, code, reason)
                        else
                            return clean(false, code, err)
                        end
                    else
                        return decoded, opcode
                    end
                end
                if not first_opcode then
                    first_opcode = opcode
                end
                if not fin then
                    if not frames then
                        frames = {}
                    elseif opcode ~= frame.CONTINUATION then
                        return clean(false, 1002, 'protocol error')
                    end
                    bytes = 3
                    encoded = ''
                    tinsert(frames, decoded)
                elseif not frames then
                    return decoded, first_opcode
                else
                    tinsert(frames, decoded)
                    return tconcat(frames), first_opcode
                end
            else
                assert(type(fin) == 'number' and fin > 0)
                bytes = fin
            end
        end
    end

    local send = function(self, data, opcode)
        if self.state ~= 'OPEN' then
            return nil, false, 1006, 'wrong state'
        end
        local encoded = frame.encode(data, opcode or frame.TEXT, not self.is_server)
        local n, err = self:sock_send(encoded)
        if n ~= #encoded then
            return nil, self:close(1006, err)
        end
        return true
    end

    local close = function(self, code, reason)
        if self.state ~= 'OPEN' then
            return false, 1006, 'wrong state'
        end
        if self.state == 'CLOSED' then
            return false, 1006, 'wrong state'
        end
        local msg = frame.encode_close(code or 1000, reason)
        local encoded = frame.encode(msg, frame.CLOSE, not self.is_server)
        local n, err = self:sock_send(encoded)
        local was_clean = false
        local code = 1005
        local reason = ''
        if n == #encoded then
            self.is_closing = true
            local rmsg, opcode = self:receive()
            if rmsg and opcode == frame.CLOSE then
                code, reason = frame.decode_close(rmsg)
                was_clean = true
            end
        else
            reason = err
        end
        self:sock_close()
        if self.on_close then
            self:on_close()
        end
        self.state = 'CLOSED'
        return was_clean, code, reason or ''
    end

    local connect = function(self, ws_url, ws_protocol, ssl_params)
        if self.state ~= 'CLOSED' then
            return nil, 'wrong state', nil
        end
        local protocol, host, port, uri = tools.parse_url(ws_url)
        local _, err = self:sock_connect(host, port)
        if err then
            return nil, err, nil
        end

        self.raw_sock = self.sock

        if protocol == 'wss' then
            if not ssl then
                ssl = require("ssl")
            end
            self.sock = ssl.wrap(self.sock, ssl_params)
            self.sock:dohandshake()
        elseif protocol ~= "ws" then
            return nil, 'bad protocol'
        end

        local ws_protocols_tbl = { '' }
        if type(ws_protocol) == 'string' then
            ws_protocols_tbl = { ws_protocol }
        elseif type(ws_protocol) == 'table' then
            ws_protocols_tbl = ws_protocol
        end
        local key = tools.generate_key()
        local req = handshake.upgrade_request
            {
                key = key,
                host = host,
                port = port,
                protocols = ws_protocols_tbl,
                uri = uri
            }
        local n, err = self:sock_send(req)
        if n ~= #req then
            return nil, err, nil
        end
        local resp = {}
        repeat
            local line, err = self:sock_receive('*l')
            resp[#resp + 1] = line
            if err then
                return nil, err, nil
            end
        until line == ''
        local response = tconcat(resp, '\r\n')
        local headers = handshake.http_headers(response)
        local expected_accept = handshake.sec_websocket_accept(key)
        if headers['sec-websocket-accept'] ~= expected_accept then
            local msg = 'Websocket Handshake failed: Invalid Sec-Websocket-Accept (expected %s got %s)'
            return nil, msg:format(expected_accept, headers['sec-websocket-accept'] or 'nil'), headers
        end
        self.state = 'OPEN'
        return true, headers['sec-websocket-protocol'], headers
    end

    local extend = function(obj)
        assert(obj.sock_send)
        assert(obj.sock_receive)
        assert(obj.sock_close)

        assert(obj.is_closing == nil)
        assert(obj.receive == nil)
        assert(obj.send == nil)
        assert(obj.close == nil)
        assert(obj.connect == nil)

        if not obj.is_server then
            assert(obj.sock_connect)
        end

        if not obj.state then
            obj.state = 'CLOSED'
        end

        obj.receive = receive
        obj.send = send
        obj.close = close
        obj.connect = connect

        return obj
    end

    return {
        extend = extend
    }
end

__lupack__["webserv.tools"] = function()
    local bit = require 'webserv.bit'
    local mime, rol, bxor, bor, band, bnot, lshift, rshift,
    srep, schar, tinsert, mrandom, string_byte
    =
        require 'mime', bit.rol, bit.bxor, bit.bor, bit.band, bit.bnot, bit.lshift, bit.rshift,
        string.rep, string.char, table.insert, math.random, string.byte

    local read_n_bytes = function(str, pos, n)
        pos = pos or 1
        return pos + n, string_byte(str, pos, pos + n - 1)
    end

    local read_int8 = function(str, pos)
        return read_n_bytes(str, pos, 1)
    end

    local read_int16 = function(str, pos)
        local new_pos, a, b = read_n_bytes(str, pos, 2)
        return new_pos, lshift(a, 8) + b
    end

    local read_int32 = function(str, pos)
        local new_pos, a, b, c, d = read_n_bytes(str, pos, 4)
        return new_pos,
            lshift(a, 24) +
            lshift(b, 16) +
            lshift(c, 8) +
            d
    end

    local pack_bytes = schar
    local write_int8 = pack_bytes
    local write_int16 = function(v)
        return pack_bytes(rshift(v, 8), band(v, 0xFF))
    end
    local write_int32 = function(v)
        return pack_bytes(
            band(rshift(v, 24), 0xFF),
            band(rshift(v, 16), 0xFF),
            band(rshift(v, 8), 0xFF),
            band(v, 0xFF)
        )
    end

    math.randomseed(os.time())

    local sha1_wiki = function(msg)
        local h0, h1, h2, h3, h4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0

        local bits = #msg * 8
        msg = msg .. schar(0x80)

        local bytes = #msg + 8

        local fill_bytes = 64 - (bytes % 64)
        if fill_bytes ~= 64 then
            msg = msg .. srep(schar(0), fill_bytes)
        end

        local high = math.floor(bits / 2 ^ 32)
        local low = bits - high * 2 ^ 32
        msg = msg .. write_int32(high) .. write_int32(low)

        assert(#msg % 64 == 0, #msg % 64)

        for j = 1, #msg, 64 do
            local chunk = msg:sub(j, j + 63)
            assert(#chunk == 64, #chunk)
            local words = {}
            local next = 1
            local word
            repeat
                next, word = read_int32(chunk, next)
                tinsert(words, word)
            until next > 64
            assert(#words == 16)
            for i = 17, 80 do
                words[i] = bxor(words[i - 3], words[i - 8], words[i - 14], words[i - 16])
                words[i] = rol(words[i], 1)
            end
            local a = h0
            local b = h1
            local c = h2
            local d = h3
            local e = h4

            for i = 1, 80 do
                local k, f
                if i > 0 and i < 21 then
                    f = bor(band(b, c), band(bnot(b), d))
                    k = 0x5A827999
                elseif i > 20 and i < 41 then
                    f = bxor(b, c, d)
                    k = 0x6ED9EBA1
                elseif i > 40 and i < 61 then
                    f = bor(band(b, c), band(b, d), band(c, d))
                    k = 0x8F1BBCDC
                elseif i > 60 and i < 81 then
                    f = bxor(b, c, d)
                    k = 0xCA62C1D6
                end

                local temp = rol(a, 5) + f + e + k + words[i]
                e = d
                d = c
                c = rol(b, 30)
                b = a
                a = temp
            end

            h0 = h0 + a
            h1 = h1 + b
            h2 = h2 + c
            h3 = h3 + d
            h4 = h4 + e
        end

        h0 = band(h0, 0xffffffff)
        h1 = band(h1, 0xffffffff)
        h2 = band(h2, 0xffffffff)
        h3 = band(h3, 0xffffffff)
        h4 = band(h4, 0xffffffff)

        return write_int32(h0) .. write_int32(h1) .. write_int32(h2) .. write_int32(h3) .. write_int32(h4)
    end

    local base64_encode = function(data)
        return (mime.b64(data))
    end

    local DEFAULT_PORTS = { ws = 80, wss = 443 }

    local parse_url = function(url)
        local protocol, address, uri = url:match('^(%w+)://([^/]+)(.*)$')
        if not protocol then error('Invalid URL:' .. url) end
        protocol = protocol:lower()
        local host, port = address:match("^(.+):(%d+)$")
        if not host then
            host = address
            port = DEFAULT_PORTS[protocol]
        end
        if not uri or uri == '' then uri = '/' end
        return protocol, host, tonumber(port), uri
    end

    local generate_key = function()
        local r1 = mrandom(0, 0xfffffff)
        local r2 = mrandom(0, 0xfffffff)
        local r3 = mrandom(0, 0xfffffff)
        local r4 = mrandom(0, 0xfffffff)
        local key = write_int32(r1) .. write_int32(r2) .. write_int32(r3) .. write_int32(r4)
        assert(#key == 16, #key)
        return base64_encode(key)
    end

    return {
        sha1 = sha1_wiki,
        base64 = {
            encode = base64_encode
        },
        parse_url = parse_url,
        generate_key = generate_key,
        read_int8 = read_int8,
        read_int16 = read_int16,
        read_int32 = read_int32,
        write_int8 = write_int8,
        write_int16 = write_int16,
        write_int32 = write_int32,
    }
end

__lupack__["webserv.client_sync"] = function()
    local socket, sync,
    tinsert,
    math_min,
    coroutine_yield, coroutine_status, coroutine_resume, coroutine_create
    =
        require 'socket', require 'webserv.sync',
        table.insert,
        math.min,
        coroutine.yield, coroutine.status, coroutine.resume, coroutine.create

    local function process_sockets(read_sockets, write_sockets, batch_size, timeout)
        timeout = timeout or 0
        local readable, writable = {}, {}

        local len_r = #read_sockets
        for i = 1, len_r, batch_size do
            local batch = {}
            for j = i, math_min(i + batch_size - 1, len_r) do
                tinsert(batch, read_sockets[j])
            end

            local r, _, err = socket.select(batch, nil, timeout)
            if err and err ~= "timeout" then
                return nil, nil, err
            end

            for _, sock in ipairs(r or {}) do
                tinsert(readable, sock)
            end
        end

        local len_w = #write_sockets
        for i = 1, len_w, batch_size do
            local batch = {}
            for j = i, math_min(i + batch_size - 1, len_w) do
                tinsert(batch, write_sockets[j])
            end

            local _, w, err = socket.select(nil, batch, timeout)
            if err and err ~= "timeout" then
                return nil, nil, err
            end

            for _, sock in ipairs(w or {}) do
                tinsert(writable, sock)
            end
        end

        return readable, writable
    end

    local client = function()
        local self = { 
            state = 'CLOSED',
            co = nil,
            waiting_for = nil
        }
        local sock = socket.tcp()
        sock:settimeout(0)

        self.sock = sock
        self.raw_sock = sock

        self.sock_connect = function(self, host, port)
            local success, err = self.sock:connect(host, port)

            if not success then
                if err == "timeout" then
                    while true do
                        local _, writeable, select_err = socket.select(nil, {self.sock}, 0)
                        if select_err and select_err ~= "timeout" then
                            return nil, select_err
                        end

                        if writeable and #writeable > 0 then
                            local check_success, check_err = self.sock:getpeername()
                            if check_success then
                                self.state = 'CONNECTED'
                                return true
                            else
                                return nil, check_err or "connection failed"
                            end
                        else
                            coroutine_yield("wantwrite")
                        end
                    end
                else
                    return nil, err
                end
            else
                self.state = 'CONNECTED'
                return true
            end
        end

        self.sock_send = function(self, data)
            local index = 1
            local len = #data
            while index <= len do
                local sent, err, last = self.sock:send(data, index)
                if sent then
                    index = index + sent
                else
                    if err == "timeout" then
                        if last then
                            index = last
                        end
                        coroutine_yield("wantwrite")
                    else
                        return nil, err
                    end
                end
            end
            return len
        end

        self.sock_receive = function(self, pattern, prefix)
            local s, err, partial = self.sock:receive(pattern, prefix or "")
            if s then
                return s
            end
            if err == "timeout" then
                coroutine_yield("wantread")
                return self:sock_receive(pattern, partial)
            end
            return nil, err
        end

        self.sock_close = function(self)
            self.state = 'CLOSED'
            if self.sock.shutdown then
                self.sock:shutdown()
            end
            self.sock:close()
        end

        self.update = function(self)
            if not self.co or coroutine_status(self.co) == "dead" then
                return
            end

            local read_socks = {}
            local write_socks = {}

            if self.waiting_for == "read" then
                tinsert(read_socks, self.sock)
            elseif self.waiting_for == "write" then
                tinsert(write_socks, self.sock)
            end

            local readable, writable, select_err = process_sockets(read_socks, write_socks, 60, 0)
            if select_err == "timeout" then
                return
            end

            local should_resume = false
            if self.waiting_for == "read" and #(readable or {}) > 0 then
                should_resume = true
            elseif self.waiting_for == "write" and #(writable or {}) > 0 then
                should_resume = true
            end

            if should_resume then
                local ok, res = coroutine_resume(self.co)
                if not ok then
                    if self.on_error then
                        self:on_error(res)
                    end
                    self:close()
                elseif coroutine_status(self.co) == "dead" then
                    self:close()
                else
                    self.waiting_for = res == "wantread" and "read" or 
                                      (res == "wantwrite" and "write" or nil)
                end
            end
        end

        self.start = function(self, handler)
            if self.co then
                error("Client already started")
            end
            self.co = coroutine_create(function()
                handler(self)
            end)
            local ok, res = coroutine_resume(self.co)
            if not ok then
                if self.on_error then
                    self:on_error(res)
                end
                self:close()
            elseif coroutine_status(self.co) == "dead" then
                self:close()
            else
                self.waiting_for = res == "wantread" and "read" or
                                  (res == "wantwrite" and "write" or nil)
            end
        end

        return sync.extend(self)
    end

    return {
        new = client
    }
end

return require("webserv")
end

-- Starting the main file
return require("lunac")