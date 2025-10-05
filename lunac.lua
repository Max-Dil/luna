-- Lupack: Packed code
-- Entry file: lunac
-- Generated: 05.10.2025, 19:46:55

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
        client_token = client_token:match("^(.-)%z*$") or client_token
        client_token = security.base64.encode(client_token)
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

        app_data.client_connect = app_data.socket.new_connect(app_data.client, app_data.host, app_data.port)
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
                            if app_data.client_connect then
                                app_data.client_connect:close()
                            else
                                pcall(function () app_data.client:close() end)
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

    local client_token_private = security.x25519.generate_keypair()
    local client_token = security.base64.encode(security.utils.key_to_string(client_token_private))
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
                            if app_data.client_connect then
                                app_data.client_connect:close()
                            else
                                pcall(function () app_data.client:close() end)
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
        if app_data.client_connect then
            app_data.client_connect:close()
        else
            pcall(function () app_data.client:close() end)
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

app.close_all = function ()
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
                local ok, err = async_req.h:receive09body(status, async_req.nreqt.sink, async_req.nreqt.step)
                if not ok then
                    async_req.state = STATE_ERROR
                    async_req.error = "Receive body failed: " .. (err or "unknown error")
                    break
                end
                async_req.result = 1
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
                local ok, err = async_req.h:receivebody(async_req.headers, async_req.nreqt.sink, async_req.nreqt.step)
                if not ok then
                    async_req.state = STATE_ERROR
                    async_req.error = "Receive body failed: " .. (err or "unknown error")
                    break
                end
            end

            if async_req.h then
                async_req.h:close()
            end
            async_req.result = 1
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

local function tredirect(reqt, location)
    local result, code, headers, status = _M.request {
        url = url.absolute(reqt.url, location),
        source = reqt.source,
        sink = reqt.sink,
        headers = reqt.headers,
        proxy = reqt.proxy,
        nredirects = (reqt.nredirects or 0) + 1,
        create = reqt.create,
        timeout = reqt.timeout,
    }
    headers = headers or {}
    headers.location = headers.location or location
    return result, code, headers, status
end

_M.request = socket.protect(function(reqt, body)
    if base.type(reqt) == "string" then
        local parsed_reqt = _M.parseRequest(reqt, body)
        local ok, code, headers, status = _M.request(parsed_reqt)

        if ok then
            return table.concat(parsed_reqt.target), code, headers, status
        else
            return nil, code
        end
    else
        if type(reqt.timeout) == "table" then
            local allowed = { connect = true, send = true, receive = true }
            for k in pairs(reqt.timeout) do
                assert(allowed[k],
                    "'" .. tostring(k) .. "' is not a valid timeout option. Valid: 'connect', 'send', 'receive'")
            end
        end
        reqt.create = reqt.create or _M.getcreatefunc(reqt)

        local nreqt = adjustrequest(reqt)
        local h = _M.open(nreqt)
        h:connect(nreqt.host, nreqt.port)
        h:sendrequestline(nreqt.method, nreqt.uri)
        h:sendheaders(nreqt.headers)

        if nreqt.source then
            h:sendbody(nreqt.headers, nreqt.source, nreqt.step)
        end

        local code, status = h:receivestatusline()

        if not code then
            h:receive09body(status, nreqt.sink, nreqt.step)
            return 1, 200
        end

        local headers
        while code == 100 do
            h:receiveheaders()
            code, status = h:receivestatusline()
        end

        headers = h:receiveheaders()

        if shouldredirect(nreqt, code, headers) and not nreqt.source then
            h:close()
            return tredirect(reqt, headers.location)
        end

        if shouldreceivebody(nreqt, code) then
            h:receivebody(headers, nreqt.sink, nreqt.step)
        end

        h:close()
        return 1, code, headers, status
    end
end)

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

_M.parseRequest = function(u, b)
    local reqt = {
        url = u,
        target = {},
    }
    reqt.sink = ltn12.sink.table(reqt.target)
    if b then
        reqt.source = ltn12.source.string(b)
        reqt.headers = {
            ["content-length"] = string.len(b),
            ["content-type"] = "application/x-www-form-urlencoded"
        }
        reqt.method = "POST"
    end
    return reqt
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
                local ok, err = async_req.h:receive09body(status, async_req.nreqt.sink, async_req.nreqt.step)
                if not ok then
                    async_req.state = STATE_ERROR
                    async_req.error = "Receive body failed: " .. (err or "unknown error")
                    break
                end
                async_req.result = 1
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
                local ok, err = async_req.h:receivebody(async_req.headers, async_req.nreqt.sink, async_req.nreqt.step)
                if not ok then
                    async_req.state = STATE_ERROR
                    async_req.error = "Receive body failed: " .. (err or "unknown error")
                    break
                end
            end

            if async_req.h then
                async_req.h:close()
            end
            async_req.result = 1
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

local function tredirect(reqt, location)
    local result, code, headers, status = _M.request {
        url = url.absolute(reqt.url, location),
        source = reqt.source,
        sink = reqt.sink,
        headers = reqt.headers,
        proxy = reqt.proxy,
        nredirects = (reqt.nredirects or 0) + 1,
        create = reqt.create,
        timeout = reqt.timeout,
    }
    headers = headers or {}
    headers.location = headers.location or location
    return result, code, headers, status
end

_M.request = socket.protect(function(reqt, body)
    if base.type(reqt) == "string" then
        local parsed_reqt = _M.parseRequest(reqt, body)
        local ok, code, headers, status = _M.request(parsed_reqt)

        if ok then
            return table.concat(parsed_reqt.target), code, headers, status
        else
            return nil, code
        end
    else
        if type(reqt.timeout) == "table" then
            local allowed = { connect = true, send = true, receive = true }
            for k in pairs(reqt.timeout) do
                assert(allowed[k],
                    "'" .. tostring(k) .. "' is not a valid timeout option. Valid: 'connect', 'send', 'receive'")
            end
        end
        reqt.create = reqt.create or _M.getcreatefunc(reqt)

        local nreqt = adjustrequest(reqt)
        local h = _M.open(nreqt)
        h:sendrequestline(nreqt.method, nreqt.uri)
        h:sendheaders(nreqt.headers)

        if nreqt.source then
            h:sendbody(nreqt.headers, nreqt.source, nreqt.step)
        end

        local code, status = h:receivestatusline()

        if not code then
            h:receive09body(status, nreqt.sink, nreqt.step)
            return 1, 200
        end

        local headers
        while code == 100 do
            h:receiveheaders()
            code, status = h:receivestatusline()
        end

        headers = h:receiveheaders()

        if shouldredirect(nreqt, code, headers) and not nreqt.source then
            h:close()
            return tredirect(reqt, headers.location)
        end

        if shouldreceivebody(nreqt, code) then
            h:receivebody(headers, nreqt.sink, nreqt.step)
        end

        h:close()
        return 1, code, headers, status
    end
end)

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

            -- Create proxy to handle methods
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

_M.parseRequest = function(u, b)
    local reqt = {
        url = u,
        target = {},
    }
    reqt.sink = ltn12.sink.table(reqt.target)
    if b then
        reqt.source = ltn12.source.string(b)
        reqt.headers = {
            ["content-length"] = string.len(b),
            ["content-type"] = "application/x-www-form-urlencoded"
        }
        reqt.method = "POST"
    end
    return reqt
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

return result

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
end

lunac.close = function ()
    if core[2].app_close then
        print(pcall(core[2].app_close))
    end
    if core[2].http_close then
        print(pcall(core[2].http_close))
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
    --[[
MIT License

Copyright (c) 2023 BernhardZat

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

    do
        local matrix = {};
        matrix.__index = matrix;

        local new = function(n, m, init, zero, one)
            local attrs = {
                n = n,
                m = m or n,
                init = init or 0,
                zero = zero or 0,
                one = one or 1,
                data = {},
            };
            return setmetatable(attrs, matrix);
        end

        local identity = function(size, zero, one)
            zero = zero or 0;
            one = one or 1;
            local id = new(size, size, zero, zero, one);
            for i = 0, size - 1 do
                id:set(i, i, one);
            end
            return id;
        end

        matrix.set = function(self, i, j, v)
            self.data[i * self.m + j] = v;
        end

        matrix.get = function(self, i, j)
            return self.data[i * self.m + j] or self.init;
        end

        matrix.set_sub = function(self, sub, i, j)
            for k = 0, sub.n - 1 do
                for l = 0, sub.m - 1 do
                    self:set(i + k, j + l, sub:get(k, l));
                end
            end
        end

        matrix.get_sub = function(self, i, j, n, m)
            local sub = new(n, m);
            for k = 0, n - 1 do
                for l = 0, m - 1 do
                    sub:set(k, l, self:get(i + k, j + l));
                end
            end
            return sub;
        end

        matrix.set_row = function(self, row, i)
            self:set_sub(row, i, 0);
        end

        matrix.get_row = function(self, i)
            return self:get_sub(i, 0, 1, self.m);
        end

        matrix.set_col = function(self, column, j)
            self:set_sub(column, 0, j);
        end

        matrix.get_col = function(self, j)
            return self:get_sub(0, j, self.n, 1);
        end

        matrix.__add = function(a, b)
            local c = new(a.n, a.m);
            for i = 0, a.n - 1 do
                for j = 0, a.m - 1 do
                    c:set(i, j, a:get(i, j) + b:get(i, j));
                end
            end
            return c;
        end

        matrix.__sub = function(a, b)
            local c = new(a.n, a.m);
            for i = 0, a.n - 1 do
                for j = 0, a.m - 1 do
                    c:set(i, j, a:get(i, j) - b:get(i, j));
                end
            end
            return c;
        end

        matrix.__mul = function(a, b)
            local c = new(a.n, b.m);
            for i = 0, a.n - 1 do
                for j = 0, b.m - 1 do
                    local sum = 0;
                    for k = 0, a.m - 1 do
                        sum = sum + a:get(i, k) * b:get(k, j);
                    end
                    c:set(i, j, sum);
                end
            end
            return c;
        end

        matrix.__tostring = function(self)
            local s = "";
            for i = 0, self.n - 1 do
                for j = 0, self.m - 1 do
                    s = s .. tostring(self:get(i, j)) .. " ";
                end
                s = s .. "\n";
            end
            return s;
        end

        security.matrix = {
            new = new,
            identity = identity,
            set = matrix.set,
            get = matrix.get,
            set_sub = matrix.set_sub,
            get_sub = matrix.get_sub,
            set_row = matrix.set_row,
            get_row = matrix.get_row,
            set_col = matrix.set_col,
            get_col = matrix.get_col,
        };
    end

    do
        local Matrix = security.matrix
        local M = Matrix.new;

        local u8_and_table = M(256);
        for i = 0, 7 do
            local m1 = u8_and_table:get_sub(0, 0, 2 ^ i, 2 ^ i);
            local m2 = M(2 ^ i, 2 ^ i, 2 ^ i);
            u8_and_table:set_sub(m1, 2 ^ i, 0);
            u8_and_table:set_sub(m1, 0, 2 ^ i);
            u8_and_table:set_sub(m1 + m2, 2 ^ i, 2 ^ i);
        end

        local u8_lsh = function(a, n)
            return a * 2 ^ n % 0x100;
        end

        local u8_rsh = function(a, n)
            return a / 2 ^ n - (a / 2 ^ n) % 1;
        end

        local u8_lrot = function(a, n)
            n = n % 8;
            return u8_lsh(a, n) + u8_rsh(a, 8 - n);
        end

        local u8_rrot = function(a, n)
            n = n % 8;
            return u8_rsh(a, n) + u8_lsh(a, 8 - n);
        end

        local u8_not = function(a)
            return 0xFF - a;
        end

        local u8_and = function(a, b)
            return u8_and_table:get(a, b);
        end

        local u8_xor = function(a, b)
            return u8_not(u8_and(a, b)) - u8_and(u8_not(a), u8_not(b));
        end

        local u8_or = function(a, b)
            return u8_and(a, b) + u8_xor(a, b);
        end

        local u16_lsh = function(a, n)
            return a * 2 ^ n % 0x10000;
        end

        local u16_rsh = function(a, n)
            return a / 2 ^ n - (a / 2 ^ n) % 1;
        end

        local u16_lrot = function(a, n)
            n = n % 16;
            return u16_lsh(a, n) + u16_rsh(a, 16 - n);
        end

        local u16_rrot = function(a, n)
            n = n % 16;
            return u16_rsh(a, n) + u16_lsh(a, 16 - n);
        end

        local u16_not = function(a)
            return 0xFFFF - a;
        end

        local u16_and = function(a, b)
            local a1, a2 = u16_rsh(a, 8), a % 0x100;
            local b1, b2 = u16_rsh(b, 8), b % 0x100;
            local r1, r2 = u8_and(a1, b1), u8_and(a2, b2);
            return u16_lsh(r1, 8) + r2;
        end

        local u16_xor = function(a, b)
            local a1, a2 = u16_rsh(a, 8), a % 0x100;
            local b1, b2 = u16_rsh(b, 8), b % 0x100;
            local r1, r2 = u8_xor(a1, b1), u8_xor(a2, b2);
            return u16_lsh(r1, 8) + r2;
        end

        local u16_or = function(a, b)
            local a1, a2 = u16_rsh(a, 8), a % 0x100;
            local b1, b2 = u16_rsh(b, 8), b % 0x100;
            local r1, r2 = u8_or(a1, b1), u8_or(a2, b2);
            return u16_lsh(r1, 8) + r2;
        end

        local u32_lsh = function(a, n)
            return a * 2 ^ n % 0x100000000;
        end

        local u32_rsh = function(a, n)
            return a / 2 ^ n - (a / 2 ^ n) % 1;
        end

        local u32_lrot = function(a, n)
            n = n % 32;
            return u32_lsh(a, n) + u32_rsh(a, 32 - n);
        end

        local u32_rrot = function(a, n)
            n = n % 32;
            return u32_rsh(a, n) + u32_lsh(a, 32 - n);
        end

        local u32_not = function(a)
            return 0xFFFFFFFF - a;
        end

        local u32_and = function(a, b)
            local a1, a2 = u32_rsh(a, 16), a % 0x10000;
            local b1, b2 = u32_rsh(b, 16), b % 0x10000;
            local r1, r2 = u16_and(a1, b1), u16_and(a2, b2);
            return u32_lsh(r1, 16) + r2;
        end

        local u32_xor = function(a, b)
            local a1, a2 = u32_rsh(a, 16), a % 0x10000;
            local b1, b2 = u32_rsh(b, 16), b % 0x10000;
            local r1, r2 = u16_xor(a1, b1), u16_xor(a2, b2);
            return u32_lsh(r1, 16) + r2;
        end

        local u32_or = function(a, b)
            local a1, a2 = u32_rsh(a, 16), a % 0x10000;
            local b1, b2 = u32_rsh(b, 16), b % 0x10000;
            local r1, r2 = u16_or(a1, b1), u16_or(a2, b2);
            return u32_lsh(r1, 16) + r2;
        end

        security.bitops = {
            u8_lsh = u8_lsh,
            u8_rsh = u8_rsh,
            u8_lrot = u8_lrot,
            u8_rrot = u8_rrot,
            u8_not = u8_not,
            u8_and = u8_and,
            u8_xor = u8_xor,
            u8_or = u8_or,
            u16_lsh = u16_lsh,
            u16_rsh = u16_rsh,
            u16_lrot = u16_lrot,
            u16_rrot = u16_rrot,
            u16_not = u16_not,
            u16_and = u16_and,
            u16_xor = u16_xor,
            u16_or = u16_or,
            u32_lsh = u32_lsh,
            u32_rsh = u32_rsh,
            u32_lrot = u32_lrot,
            u32_rrot = u32_rrot,
            u32_not = u32_not,
            u32_and = u32_and,
            u32_xor = u32_xor,
            u32_or = u32_or,
        };
    end

    do
        local number_to_bytestring = function(num, n)
            n = n or math.floor(math.log(num) / math.log(0x100) + 1);
            n = n > 0 and n or 1;
            local string_char = string.char;
            local t = {};
            for i = 1, n do
                t[n - i + 1] = string_char((num % 0x100 ^ i - num % 0x100 ^ (i - 1)) / 0x100 ^ (i - 1));
            end
            local s = table.concat(t);
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

        local bytetable_to_bytestring = function(t)
            local s = t[0] and string.char(t[0]) or "";
            for i = 1, #t do
                s = s .. string.char(t[i]);
            end
            return s;
        end

        local bytestring_to_bytetable = function(s, zero_based)
            local t = {};
            local j = zero_based and 1 or 0;
            for i = 1, s:len() do
                t[i - j] = s:byte(i);
            end
            return t;
        end

        local bytetable_to_number = function(t)
            local num = 0;
            for i = 0, #t - (t[0] and 0 or 1) do
                num = num + t[#t - i] * 0x100 ^ i;
            end
            return num;
        end

        security.util = {
            number_to_bytestring = number_to_bytestring,
            bytestring_to_number = bytestring_to_number,
            bytetable_to_bytestring = bytetable_to_bytestring,
            bytestring_to_bytetable = bytestring_to_bytetable,
            bytetable_to_number = bytetable_to_number,
        }
    end

    do
        local Bitops = security.bitops;
        local Util = security.util;

        local XOR, LROT = Bitops.u32_xor, Bitops.u32_lrot;
        local num_to_bytes, num_from_bytes = Util.number_to_bytestring, Util.bytestring_to_number;

        local MOD = 0x100000000;

        local is_luajit = type(jit) == 'table';
        if is_luajit then
            local bit = require('bit');
            XOR = bit.bxor;
            LROT = bit.rol;
        else
            XOR = Bitops.u32_xor;
            LROT = Bitops.u32_lrot;
        end

        local function unpack(s, len)
            local array = {};
            local count = 0;
            local char = string.char;
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

        local function pack(a, len)
            local t = {};
            local array_len = #a;
            local remaining = len or (array_len * 4);
            local min = math.min;
            for i = 1, array_len do
                local bytes = num_to_bytes(a[i], 4);
                local take = min(4, remaining - (i - 1) * 4);
                t[i] = bytes:sub(1, take);
            end
            return table.concat(t);
        end

        local function quarter_round(s, a, b, c, d)
            s[a] = (s[a] + s[b]) % MOD; s[d] = LROT(XOR(s[d], s[a]), 16);
            s[c] = (s[c] + s[d]) % MOD; s[b] = LROT(XOR(s[b], s[c]), 12);
            s[a] = (s[a] + s[b]) % MOD; s[d] = LROT(XOR(s[d], s[a]), 8);
            s[c] = (s[c] + s[d]) % MOD; s[b] = LROT(XOR(s[b], s[c]), 7);
        end

        local CONSTANTS = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
        local block = function(key, nonce, counter)
            local init = {
                CONSTANTS[1], CONSTANTS[2], CONSTANTS[3], CONSTANTS[4],
                key[1], key[2], key[3], key[4],
                key[5], key[6], key[7], key[8],
                counter, nonce[1], nonce[2], nonce[3],
            }
            local state = {};
            for i = 1, 16 do
                state[i] = init[i];
            end
            for _ = 1, 10 do
                quarter_round(state, 1, 5, 9, 13);
                quarter_round(state, 2, 6, 10, 14);
                quarter_round(state, 3, 7, 11, 15);
                quarter_round(state, 4, 8, 12, 16);
                quarter_round(state, 1, 6, 11, 16);
                quarter_round(state, 2, 7, 12, 13);
                quarter_round(state, 3, 8, 9, 14);
                quarter_round(state, 4, 5, 10, 15);
            end
            for i = 1, 16 do
                state[i] = (state[i] + init[i]) % 0x100000000;
            end
            return state;
        end

        local encrypt = function(plain, key, nonce)
            local unpack, pack, floor, ceil = unpack, pack, math.floor, math.ceil;

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
            return table.concat(cipher);
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

        local encode = function(s)
            local r = s:len() % 3;
            s = r == 0 and s or s .. ("\0"):rep(3 - r);
            local b64 = {};
            local count = 0;
            local len = s:len();
            local floor = math.floor;
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
            return table.concat(b64);
        end

        local decode = function(b64)
            local b, p = b64:gsub("=", "");
            local s = {};
            local count = 0;
            local len = b:len();
            local char, floor = string.char, math.floor;
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
            local result = table.concat(s);
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

        local generate_keypair = function(rng)
            rng = rng or function() return math.random(0, 0xFF) end;
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

        local function generate_nonce()
            local nonce = "";
            for i = 1, 12 do
                nonce = nonce .. string.char(math.random(0, 255));
            end
            return security.base64.encode(nonce);
        end

        local function uuid()
            local template = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx';
            return string.gsub(template, '[xy]', function(c)
                local v = (c == 'x') and math.random(0, 15) or math.random(8, 11);
                return string.format('%x', v);
            end)
        end

        local function split(str, sep)
            local result = {};
            for part in str:gmatch("[^" .. sep .. "]+") do
                table.insert(result, part);
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

local string_gsub = string.gsub
local math_random = math.random
local math_ceil = math.ceil
local tostring = tostring
local tonumber = tonumber
local string_format = string.format
local table_insert = table.insert
local table_remove = table.remove
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

-- Starting the main file
return require("lunac")