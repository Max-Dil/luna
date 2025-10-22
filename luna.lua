-- Lupack: Packed code
-- Entry file: luna
-- Generated: 22.10.2025, 21:38:44

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


-- luna/core/default/app.lua
__lupack__["luna.core.default.app"] = function()
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

local type, pairs, pcall, error, setmetatable, tostring, tonumber, security_chacha20_encrypt,
    security_base64_encode, security_base64_decode, table_insert, coroutine_resume, table_concat,
    string_format, json_encode, os_time, string_sub, string_len, security_utils_split,
    security_utils_uuid, security_utils_generate_nonce, security_utils_key_to_string,
    security_x25519_generate_keypair, security_utils_string_to_key, security_x25519_get_shared_key,
    print =
        type, pairs, pcall, error, setmetatable, tostring, tonumber, security.chacha20.encrypt,
        security.base64.encode, security.base64.decode, table.insert, coroutine.resume, table.concat,
        string.format, json.encode, os.time, string.sub, string.len, security.utils.split, security.utils.uuid,
        security.utils.generate_nonce, security.utils.key_to_string, security.x25519.generate_keypair,
        security.utils.string_to_key, security.x25519.get_shared_key, print

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
        server_private, server_public = security_x25519_generate_keypair()
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
                table_insert(clients, value)
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
    for key, app_data in pairs(apps) do
        for coro, data in pairs(app_data.running_funs) do
            local request_handler, request, client, request_result = data[1], data[2], data[3], nil

            local ok, ok2, result = pcall(coroutine_resume, coro, request.args, client)
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
                        local expected_str = table_concat(request_handler.response_validate, " or ")
                        local actual_type = type(result)
                        local err_msg = string_format("Response expected to be %s, got %s (%s)",
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
                            client:send(json_encode(response))
                        end)
                        if not ok then
                            print("Error in async request: " .. send_err .. "  id:" ..
                                response.id .. "  path:" .. response.request)
                        end
                    end
                    app_data.running_funs[coro] = nil
                end
            end
        end

        app_data.socket.update(app_data.server, dt)

        local messages = app_data.socket.receive_message(app_data.server)
        local currentTime = os_time()
        for _, msg in pairs(messages) do
            local data, ip, port = msg.message, msg.ip, msg.port
            local client_key = ip .. ":" .. port
            local client = app_data.clients[client_key]

            if not client then
                if not ip:match("^%d+%.%d+%.%d+%.%d+$") then
                    handle_error(app_data, "The client's IP address is invalid", 2)
                end
                app_data.ip_counts[ip] = (app_data.ip_counts[ip] or 0) + 1
                if app_data.ip_counts[ip] <= app_data.max_ip_connected then
                    client = app_data.socket.new_connect(app_data.server, ip, port)
                    app_data.clients[client_key] = client
                    client.lastActive = currentTime

                    if app_data.encryption then
                        client.auth_token = security_utils_uuid()
                        local nonce = security_base64_encode(security_utils_generate_nonce())
                        client.nonce = security_base64_decode(nonce)

                        client.__send = client.send
                        client.send = function(self, data)
                            local success, message = encrypt_message(client, data)
                            if success then
                                pcall(self.__send, self, message)
                            end
                        end

                        local ok, send_err = pcall(function()
                            client:__send(json_encode({
                                __luna = true,
                                request = "handshake",
                                response = json_encode({
                                    pub = security_utils_key_to_string(app_data.server_public),
                                    token = client.auth_token,
                                    nonce = nonce
                                }),
                                id = "handshake",
                                time = 0,
                                __noawait = true,
                            }))
                        end)

                        if not ok then
                            handle_error(app_data, "Error sending handshake: " .. send_err)
                        end
                    end

                    client.__close = client.close
                    client.close = function(self)
                        pcall(self.send, self, "__luna__close")
                        self.__close()
                        if self.is_close then
                            if app_data.debug then
                                print("app: " .. app_data.name, "Client disconnected ip: " .. self.ip ..
                                    ":" .. self.port)
                            end
                            app_data.ip_counts[self.ip] = (app_data.ip_counts[self.ip] or 1) - 1
                            if app_data.ip_counts[self.ip] <= 0 then
                                app_data.ip_counts[self.ip] = nil
                            end
                            if app_data.close_client then
                                local ok, cb_err = pcall(app_data.close_client, self)
                                if not ok then
                                    handle_error(app_data, "Error in close_client callback: " .. cb_err)
                                end
                            end
                            app_data.clients[self.ip .. ":" .. self.port] = nil
                            self = nil
                        end
                    end
                    if app_data.debug then
                        print("app: " .. app_data.name, "New client connected ip: " .. ip .. ", port: " .. port)
                    end
                    if app_data.new_client then
                        local ok, cb_err = pcall(app_data.new_client, client)
                        if not ok then
                            handle_error(app_data, "Error in new_client callback: " .. cb_err)
                        end
                    end
                else
                    print("Rejected connection from " ..
                        ip .. ":" .. port .. ": max connections (" .. app_data.max_ip_connected .. ") reached")
                    app_data.ip_counts[ip] = app_data.ip_counts[ip] - 1
                    local success, message
                    if app_data.encryption then
                        success, message = encrypt_message(client,
                        json_encode({ error = "Max connections reached", __luna = true }))
                    else
                        success, message = true, json_encode({ error = "Max connections reached", __luna = true })
                    end
                    if success then
                        app_data.socket.send_message(message, ip, port)
                    end
                end
            end

            if client then
                client.lastActive = currentTime
                if client.auth_token then
                    local name = string_sub(data, 1, 10)
                    local params = string_sub(data, 11, string_len(data))

                    if name and params then
                        if name == "client_pub" then
                            local args = security_utils_split(params, "|")
                            local client_pub, auth_token = args[1], args[2]

                            if auth_token == client.auth_token then
                                client_pub = security_utils_string_to_key(client_pub)
                                client.shared_secret = security_utils_key_to_string(security_x25519_get_shared_key(
                                app_data.server_private, client_pub))
                                local ok, send_err = pcall(function()
                                    client:__send(json_encode({
                                        __luna = true,
                                        request = "connect",
                                        response = true,
                                        id = "connect",
                                        time = 0,
                                        __noawait = true,
                                    }))
                                end)
                                if not ok then
                                    handle_error(app_data, "Error sending connect: " .. send_err)
                                end
                            end
                        elseif name == "client_tok" then
                            if client.shared_secret and client.nonce then
                                local success, decrypted = decrypt_message(client, params)
                                if success and decrypted then
                                    client.auth_token = nil
                                    client.token = decrypted

                                    local ok, send_err = pcall(function()
                                        client:__send(json_encode({
                                            __luna = true,
                                            request = "connect",
                                            response = true,
                                            id = "connect",
                                            time = 0,
                                            __noawait = true,
                                        }))
                                    end)
                                    if not ok then
                                        handle_error(app_data, "Error sending token connect: " .. send_err)
                                    end
                                end
                            end
                        end
                    end
                else
                    local success, err
                    if app_data.encryption then
                        success, err = decrypt_message(client, data)
                    else
                        success, err = true, data
                    end
                    if success and err then
                        data = err
                        if app_data.debug then
                            print("app: " .. app_data.name, client_key, data)
                        end

                        if app_data.request_listener then
                            app_data.request_listener(data, client)
                        end

                        if not client.is_close then
                            local response
                            for _, router_data in pairs(app_data.routers) do
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
                                        client:send(json_encode(response_to_send))
                                    end)
                                    if not ok then
                                        handle_error(app_data, "Error sending data to client " .. client_key .. ": " .. send_err)
                                    end
                                end
                            end
                        else
                            handle_error(app_data,
                                "Error sending data to client " .. client_key .. ": " .. (err or "unknown decrypt error"))
                        end
                    end
                end
            end
        end

        for client_key, client in pairs(app_data.clients) do
            if currentTime - client.lastActive > app_data.disconnect_time then
                if app_data.timeout_client then
                    local r = app_data.timeout_client(client, currentTime - client.lastActive, app_data.disconnect_time)
                    if r or r == nil then
                        if app_data.debug then
                            print("app: " .. app_data.name, "Client disconnected ip: " .. client.ip ..
                                ":" .. client.port .. " <due to timeout>", "Time: " .. currentTime - client.lastActive,
                                "disconnect_time: " .. app_data.disconnect_time, "currentTime: " .. currentTime)
                        end
                        app_data.clients[client_key]:close()
                    else
                        client.lastActive = currentTime
                    end
                else
                    if app_data.debug then
                        print("app: " .. app_data.name, "Client disconnected ip: " .. client.ip ..
                            ":" .. client.port .. " <due to timeout>", "Time: " .. currentTime - client.lastActive,
                            "disconnect_time: " .. app_data.disconnect_time, "currentTime: " .. currentTime)
                    end
                    app_data.clients[client_key]:close()
                end
            end
        end
    end
end

return app

end

-- luna/core/default/requests.lua
__lupack__["luna.core.default.requests"] = function()
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

local req = {}
local json = require("luna.libs.json")

local table_insert, json_decode, pairs, tonumber, type, table_concat, string_format, tostring, print, pcall, os_time, coroutine_create =
    table.insert, json.decode, pairs, tonumber, type, table.concat, string.format, tostring, print, pcall, os.time, coroutine.create

req.new = function(router, config)
    local req_data
    req_data = {
        prefix = config.prefix,
        fun = config.fun,
        no_errors = config.no_errors,
        validate = config.validate,
        response_validate = config.response_validate,
        error_handler = config.error_handler or function(message) 
            print("Error in request prefix: "..req_data.prefix.." error: "..message) 
        end,
        async = config.async,
        router = router,
        max_message_size = config.max_message_size,
        message_penalty = config.message_penalty or "timeout",
        timeout_duration = config.timeout_duration,
        middlewares = config.middlewares or {},
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
        table_insert(result, part)
    end
    return result
end

local function parse_request(data)
    data = data:gsub("^%s*(.-)%s*$", "%1")

    local path, args_str = data:match("^(%S+)%s*(.*)$")
    if not path then
        return nil, "Invalid request format"
    end

    local max_iterations, iteration, args = 300, 0, {}
    while args_str and args_str ~= "" do
        iteration = iteration + 1
        local key, value, remaining
        local matched = false

        -- JSON: key=<json='["test",550]'>
        key, value, remaining = args_str:match("^(%S+)=<json='([^']*)'>%s*(.*)$")
        if key then
            local success, decoded = pcall(json_decode, value)
            if success then
                args[key] = decoded
                args_str = remaining
                matched = true
            else
                return nil, "Invalid JSON in parameter '"..key.."': "..decoded
            end
        end

        if not matched then
            -- String: key='value'
            key, value, remaining = args_str:match("^(%S+)='([^']*)'%s*(.*)$")
            if key then
                args[key] = value
                args_str = remaining
                matched = true
            end
        end

        if not matched then
            -- Boolean: key=True or key=False
            key, remaining = args_str:match("^(%S+)=True%s*(.*)$")
            if key then
                args[key] = true
                args_str = remaining
                matched = true
            end
        end

        if not matched then
            key, remaining = args_str:match("^(%S+)=False%s*(.*)$")
            if key then
                args[key] = false
                args_str = remaining
                matched = true
            end
        end

        if not matched then
            -- Number: key=100 or key=-100
            key, value, remaining = args_str:match("^(%S+)=([%-%d%.]+)%s*(.*)$")
            if key then
                value = tonumber(value)
                if value then
                    args[key] = value
                    args_str = remaining
                    matched = true
                else
                    return nil, "Invalid number in parameter '"..key.."': "..tostring(value)
                end
            end
        end

        if not matched then
            if args_str:match("%S") then
                key, remaining = args_str:match("^(%S+)%s*(.*)$")
                if key then
                    args[key] = true
                    args_str = remaining
                    matched = true
                else
                    break
                end
            else
                break
            end
        end

        if iteration > max_iterations then
            -- print("Request processing limit exceeded (300)")
            break
        end
    end

    return {
        path = path,
        args = args
    }
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

local function validate_args(validate_config, args)
    for key, expected_types in pairs(validate_config) do
        local value = args[key]

        if not validate_value(value, expected_types) then
            local expected_str, actual_type = table_concat(expected_types, " or "), type(value)
            return false, string_format("Argument '%s' expected to be %s, got %s (%s)",
                key, expected_str, actual_type, tostring(value))
        end
    end

    return true
end

local function apply_penalty(app, client_data, penalty, timeout_duration, error_msg)
    if penalty == "closed" then
        app.ip_counts[client_data.ip] = (app.ip_counts[client_data.ip] or 1) - 1
        if app.ip_counts[client_data.ip] <= 0 then
            app.ip_counts[client_data.ip] = nil
        end
        if app.debug then
            print("app: "..app.name, "Client disconnected ip: "..client_data.ip..":"..client_data.port.." due to penalty")
        end
        app.clients[client_data.ip..":"..client_data.port] = nil
        if app.close_client then
            local ok, cb_err = pcall(app.close_client, client_data)
            if not ok then
                print("Error in close_client callback: "..cb_err)
            end
        end
        return {error = error_msg, __luna = true}
    elseif penalty == "timeout" then
        app.blocked_ips = app.blocked_ips or {}
        app.blocked_ips[client_data.ip] = os_time() + timeout_duration
        if app.debug then
            print("app: "..app.name, "Client timed out ip: "..client_data.ip..":"..client_data.port.." for "..timeout_duration.." seconds")
        end
        return {error = error_msg.." Timed out for "..timeout_duration.." seconds", __luna = true}
    end
    return {error = error_msg, __luna = true}
end

req.process = function(router, client_data, data)
    router.app.blocked_ips = router.app.blocked_ips or {}
    if router.app.blocked_ips[client_data.ip] then
        if os_time() < router.app.blocked_ips[client_data.ip] then
            return {error = "Client IP "..client_data.ip.." is temporarily blocked", __luna = true}
        else
            router.app.blocked_ips[client_data.ip] = nil
        end
    end

    local request_handler
    local path_parts = split(data:match("^(%S+)") or "", "/")
    if #path_parts >= 2 then
        local router_data = router.app.routers[path_parts[1]]
        if router_data then
            request_handler = router_data.requests[path_parts[2]]
        end
    end

    if request_handler and request_handler.max_message_size then
        if #data > request_handler.max_message_size then
            local error_msg = "Message size exceeds limit of "..request_handler.max_message_size.." bytes"
            return apply_penalty(router.app, client_data, request_handler.message_penalty, request_handler.timeout_duration, error_msg)
        end
    end

    local request, err = parse_request(data)
    if not request then
        return nil, err
    end

    if #path_parts < 2 then
        return nil, "Invalid path format"
    end

    local router_prefix = path_parts[1]

    local router_data = router.app.routers[router_prefix]
    if not router_data then
        return nil, "No router found for prefix: "..router_prefix
    end

    request_handler = router_data.requests[path_parts[2]]
    if not request_handler or not request_handler.fun then
        return nil, "No handler found for path: "..request.path
    end

    local context = { request = request, client = client_data, stop = false, ip = client_data.ip, port = client_data.port }
    for _, middleware in pairs(request_handler.middlewares) do
        local ok, result = pcall(middleware, context, true)
        if not ok then
            if request_handler.error_handler then
                request_handler.error_handler("Middleware error: "..result)
            end
            return {request = request.path, error = "Middleware error: "..result, time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil}
        end
        if context.stop then
            return result or {request = request.path, error = "Request stopped by middleware", time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil}
        end
    end

    if request_handler.validate then
        local valid, err_msg = validate_args(request_handler.validate, request.args)
        if not valid then
            if request_handler.error_handler then
                request_handler.error_handler(err_msg)
            end
            return {request = request.path, error = err_msg, time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil}
        end
    end

    if router.app.encryption and request.args.__client_token ~= client_data.token then
        return {request = request.path, error = "Couldn't confirm the client's token", time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil}
    end

    local result
    if request_handler.async then
        local coro = coroutine_create(request_handler.fun)
        router.app.running_funs[coro] = {request_handler, request, client_data}
        result = {request = request.path, time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil, no_response = true}
    else
        local ok, handler_result = pcall(request_handler.fun, request.args, client_data)
        if not ok then
            if request_handler.error_handler then
                request_handler.error_handler(handler_result)
            end
            return {request = request.path, error = handler_result, time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil}
        end
        result = {request = request.path, response = handler_result, time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil}
    end

    context.response = result
    for _, middleware in pairs(request_handler.middlewares) do
        local ok, mw_result = pcall(middleware, context, false)
        if not ok then
            if request_handler.error_handler then
                request_handler.error_handler("Middleware error: "..mw_result)
            end
            return {request = request.path, error = "Middleware error: "..mw_result, time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil}
        end
        if mw_result then
            result = mw_result
        end
        if context.stop then
            return result or {request = request.path, error = "Request stopped by middleware", time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil}
        end
    end

    if not request_handler.async and request_handler.response_validate then
        if not validate_value(result.response, request_handler.response_validate) then
            local expected_str = table_concat(request_handler.response_validate, " or ")
            local actual_type = type(result.response)
            local err_msg = string_format("Response expected to be %s, got %s (%s)",
                expected_str, actual_type, tostring(result.response))
            if request_handler.error_handler then
                request_handler.error_handler(err_msg)
            end
            return {request = request.path, error = err_msg, time = request.args.__time or 0, id = (request.args.__id or "unknown id"), __luna = true, __noawait = request.args.__noawait or nil}
        end
    end

    return result
end

return req
end

-- luna/core/default/router.lua
__lupack__["luna.core.default.router"] = function()
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

local req = require("luna.core.default.requests")
local router, print, type = {}, print, type

router.new_router = function(app, config)
    if app.routers[config.prefix] then
        router.remove_router(app, config.prefix)
    end
    local router_data
    router_data = setmetatable({
        prefix = config.prefix,
        no_errors = config.no_errors,
        error_handler = config.error_handler or function(message) 
            print("Error in router prefix: "..router_data.prefix.." error: "..message) 
        end,
        requests = {},
        app = app,
    }, {__index = req})

    app.routers[router_data.prefix] = router_data
    return router_data
end

router.remove_router = function(app, router_data)
    if type(router_data) == "string" then
        router_data = app.routers[router_data]
    end

    app.routers[router_data.prefix] = nil
end

return router
end

-- luna/core/http/http_app.lua
__lupack__["luna.core.http.http_app"] = function()
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

local httpserv, socket = require("luna.libs.httpserv"), require("socket")

local type, pairs, ipairs, pcall, error, tostring, print, table_concat, table_insert, 
      math_max, math_ceil, math_random, os_time, os_date, string_format, socket_gettime,
      json_decode, util_parseQueryString =
    type, pairs, ipairs, pcall, error, tostring, print, table.concat, table.insert,
    math.max, math.ceil, math.random, os.time, os.date, string.format, (socket and socket.gettime) or (function() return os.time end)(),
    (function() local json = require("luna.libs.httpserv.json") return json.decode end)(),
    (function() local util = require("luna.libs.httpserv.util") return util.parseQueryString end)()

local function handle_error(app_data, message, err_level)
    if app_data.no_errors then
        if app_data.error_handler then
            app_data.error_handler(message)
        end
    else
        error(message, err_level or 2)
    end
end

local http_app, apps = {}, {}

--[[
config:
str name
fun error_handler
boolean no_errors
boolean debug
func new_client(ip, client_data)
func close_client(ip, client_data, reason)
func timeout_client(ip, client_data, inactive_time)
func error_client(ip, client_data, error_msg)
]]
http_app.new_app = function(config)
    local app_data
    app_data = {
        name = config.name or "unknown name",

        error_handler = config.error_handler or function(message)
            print("Error in app '" .. app_data.name .. "': " .. message)
        end,
        no_errors = config.no_errors,

        debug = config.debug == nil and true or config.debug,

        new_client = config.new_client,
        close_client = config.close_client,
        timeout_client = config.timeout_client,
        error_client = config.error_client,

        STATUS_CODES = httpserv.constants.STATUS_CODES,
        MIME_TYPES = httpserv.constants.MIME_TYPES,

        templates = {
            static = httpserv.static.server, -- app.use(app.templates.static("directory"))
            cors = function(options)
                options = options or {}
                local allowed_origins = options.origins or { "*" }
                local allowed_methods = options.methods or { "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD" }
                local allowed_headers = options.headers or { "Content-Type", "Authorization", "X-Requested-With" }
                local allow_credentials = options.credentials or false
                local max_age = options.max_age or 86400

                local trim = function(str)
                    return str:gsub("^%s+", ""):gsub("%s+$", "")
                end

                local origins_lookup = {}
                for _, origin in ipairs(allowed_origins) do
                    origins_lookup[origin] = true
                end

                local methods_lookup = {}
                for _, method in ipairs(allowed_methods) do
                    methods_lookup[method] = true
                end

                return function(req, res, next)
                    local origin = req.headers.origin

                    local current_origin = "*"

                    if origin then
                        if origins_lookup[origin] then
                            current_origin = origin
                        elseif origins_lookup["*"] then
                            current_origin = "*"
                        else
                            current_origin = "null"
                        end
                    end

                    if allow_credentials and current_origin == "*" then
                        current_origin = origin or "null"
                    end

                    res:setHeader("Access-Control-Allow-Origin", current_origin)
                    res:setHeader("Access-Control-Allow-Methods", table_concat(allowed_methods, ", "))
                    res:setHeader("Access-Control-Allow-Headers", table_concat(allowed_headers, ", "))

                    if allow_credentials and current_origin ~= "*" then
                        res:setHeader("Access-Control-Allow-Credentials", "true")
                    end

                    if max_age then
                        res:setHeader("Access-Control-Max-Age", tostring(max_age))
                    end

                    if req.method == "OPTIONS" then
                        local requested_method = req.headers["access-control-request-method"]
                        if requested_method and not methods_lookup[requested_method] then
                            res:status(405):json({ error = "Method not allowed by CORS policy" })
                            return
                        end

                        local requested_headers = req.headers["access-control-request-headers"]
                        if requested_headers then
                            local headers = {}
                            for header in requested_headers:gmatch("[^,]+") do
                                header = trim(header)
                                table_insert(headers, header)
                            end

                            for _, header in ipairs(headers) do
                                local allowed = false
                                for _, allowed_header in ipairs(allowed_headers) do
                                    if header:lower() == allowed_header:lower() then
                                        allowed = true
                                        break
                                    end
                                end
                                if not allowed then
                                    res:status(400):json({ error = "Header not allowed by CORS policy: " .. header })
                                    return
                                end
                            end
                        end

                        res:status(204):send("true")
                        return
                    end

                    if not methods_lookup[req.method] then
                        res:status(405):json({ error = "Method not allowed by CORS policy" })
                        return
                    end

                    next()
                end
            end,
            rate_limited = function(options)
                local function table_count(t)
                    local count = 0
                    for _ in pairs(t) do count = count + 1 end
                    return count
                end

                options = options or {}
                local window_ms = options.window_ms or 60000
                local max_requests = options.max_requests or 100
                local skip = options.skip or function(req) return false end
                local key_generator = options.key_generator or
                    function(req) return req.headers["x-forwarded-for"] or req.client_data.ip:match("([^:]+):") or "unknown" end
                local message = options.message or "Too many requests"
                local status_code = options.status_code or 429

                local requests = {}
                local last_cleanup = os_time() * 1000
                local cleanup_interval = 60000
                local function cleanup(force)
                    local now = socket_gettime() * 1000 or os_time() * 1000

                    if force or now - last_cleanup > cleanup_interval then
                        for key, data in pairs(requests) do
                            if now - data.start_time > window_ms then
                                requests[key] = nil
                            end
                        end
                        last_cleanup = now
                    end
                end

                return function(req, res, next)
                    if skip(req) then
                        return next()
                    end

                    local key = key_generator(req)
                    local now = socket_gettime() * 1000 or os_time() * 1000

                    if not requests[key] or now - requests[key].start_time > window_ms then
                        requests[key] = {
                            count = 0,
                            start_time = now
                        }
                    end

                    requests[key].count = requests[key].count + 1

                    local remaining = math_max(0, max_requests - requests[key].count)
                    local reset_time = math_ceil((requests[key].start_time + window_ms) / 1000)

                    res:setHeader("X-RateLimit-Limit", tostring(max_requests))
                    res:setHeader("X-RateLimit-Remaining", tostring(remaining))
                    res:setHeader("X-RateLimit-Reset", tostring(reset_time))

                    if requests[key].count > max_requests then
                        res:setHeader("Retry-After", tostring(math_ceil((reset_time - now / 1000))))
                        res:status(status_code):json({ error = message })
                        return
                    end

                    if math_random(100) == 1 or (next(requests) and table_count(requests) > 1000 and math_random(10) == 1) then
                        cleanup(true)
                    end

                    next()
                end
            end,
            body_parser = function()
                return function(req, res, next)
                    local content_type = req.headers["content-type"] or ""

                    if req.body and req.body ~= "" then
                        if content_type == "application/json" or content_type:find("application/json") then
                            local success, parsed = pcall(json_decode, req.body)
                            if success then
                                req.body = parsed
                            end
                        elseif content_type == "application/x-www-form-urlencoded" or content_type:find("application/x-www-form-urlencoded") then
                            req.body = util_parseQueryString(req.body)
                        end
                    end

                    next()
                end
            end,
            logger = function(options)
                options = options or {}
                local format = options.format or ":method :url :status :response-time ms"
                local stream = options.stream or { write = function(msg) print(msg) end }
                local skip = options.skip or function(req) return false end

                return function(req, res, next)
                    if skip(req) then
                        return next()
                    end

                    local start_time = socket_gettime() * 1000 or os_time() * 1000

                    local original_send = res.send
                    res.send = function(self, data)
                        local result = original_send(self, data)

                        local end_time = socket_gettime() * 1000 or os_time() * 1000
                        local response_time = end_time - start_time

                        local log_message = format
                            :gsub(":method", req.method)
                            :gsub(":url", req.path)
                            :gsub(":status", tostring(self.statusCode))
                            :gsub(":response-time", string_format("%.2f", response_time))
                            :gsub(":remote-addr", req.client:getpeername() or "unknown")
                            :gsub(":user-agent", req.headers["user-agent"] or "-")
                            :gsub(":content-length", self.headers["Content-Length"] or "-")

                        stream.write(log_message)

                        return result
                    end

                    next()
                end
            end
        }
    }

    local s, e = pcall(function()
        local app = httpserv.server.create()
        app_data.server = app

        function app_data.get(self, path, handler) app.router:get(path, handler) end
        function app_data.post(self, path, handler) app.router:post(path, handler) end
        function app_data.put(self, path, handler) app.router:put(path, handler) end
        function app_data.delete(self, path, handler) app.router:delete(path, handler) end
        function app_data.patch(self, path, handler) app.router:patch(path, handler) end
        function app_data.head(self, path, handler) app.router:head(path, handler) end
        function app_data.options(self, path, handler) app.router:options(path, handler) end

        local create_group
        create_group = function(parent, prefix)
            if not type(prefix) == "string" then
                handle_error(app_data, "app.group(prefix) prefix not string", 2)
                return
            end
            local group = parent:group(prefix)
            return {
                get = function(self, path, handler) group:addRoute("GET", path, handler) end,
                post = function(self, path, handler) group:addRoute("POST", path, handler) end,
                put = function(self, path, handler) group:addRoute("PUT", path, handler) end,
                delete = function(self, path, handler) group:addRoute("DELETE", path, handler) end,
                patch = function(self, path, handler) group:addRoute("PATCH", path, handler) end,
                head = function(self, path, handler) group:addRoute("HEAD", path, handler) end,
                options = function(self, path, handler) group:addRoute("OPTIONS", path, handler) end,
                group = function(self, prefix)
                    return create_group(group, prefix)
                end
            }
        end

        app_data.group = function(self, prefix)
            return create_group(app, prefix)
        end

        app_data.listen = function(self, port, host, protocol, ssl_config)
            if not type(host) == "string" then
                handle_error(app_data, "app.listen(port, host, protocol, ssl_config) host not string", 2)
                return
            end
            if not type(port) == "number" then
                handle_error(app_data, "app.listen(port, host, protocol, ssl_config) port not number", 2)
                return
            end
            if protocol and not type(protocol) == "string" then
                handle_error(app_data, "app.listen(port, host, protocol, ssl_config) protocol not string", 2)
                return
            end
            if ssl_config and not type(ssl_config) == "table" then
                handle_error(app_data, "app.listen(port, host, protocol, ssl_config) ssl_config not table", 2)
                return
            end
            if ssl_config and (not ssl_config["key"] or not ssl_config["cert"]) then
                handle_error(app_data, "app.listen(port, host, protocol, ssl_config) ssl_config no key or cert found", 2)
                return
            end
            if protocol == "https" then
                if not app:checkSSL() then
                    handle_error(app_data, "SSL not found", 2)
                    return
                end
            end
            local s, e = pcall(app.listen, app, port, host, protocol, ssl_config)
            if not s then
                handle_error(app_data, e, 2)
                return
            end
            app_data.is_listen = true
            if app_data.debug then
                print(string_format("Server listening on " .. (protocol or "http") .. "://" .. host .. ":" .. port))
            end
        end
        app_data.stop = function(self)
            if app_data.debug then
                print("HTTP server stopped name: " .. app_data.name)
            end
            app_data.is_listen = false
            app:stop()
        end

        app_data.is_running = function(self)
            return app:isRunning()
        end
        app_data.get_client_count = function(self)
            return app:getClientCount()
        end

        app_data.set_default_timeout = function(self, timeout)
            app:setDefaultTimeout(timeout)
        end
        app_data.set_default_max_header_size = function(self, size)
            app:setDefaultMaxHeaderSize(size)
        end
        app_data.set_default_max_body_size = function(self, size)
            app:setDefaultMaxBodySize(size)
        end

        app_data.use = function(self, middlewareFn)
            if middlewareFn and not type(middlewareFn) == "table" then
                handle_error(app_data, "app.use(middlewareFn) middlewareFn not function", 2)
                return
            end
            app:use(middlewareFn)
        end

        app:on("new_client", function(ip, client_data)
            if app_data.new_client then
                app_data.new_client(ip, client_data)
            end
        end)
        app:on("close_client", function(ip, client_data, reason)
            if app_data.close_client then
                app_data.close_client(ip, client_data, reason)
            end
        end)
        app:on("timeout", function(ip, client_data, inactive_time)
            if app_data.timeout_client then
                app_data.timeout_client(ip, client_data, inactive_time)
            end
        end)
        app:on("error", function(ip, client_data, error_msg)
            if app_data.error_client then
                app_data.error_client(ip, client_data, error_msg)
            end
        end)

        if app_data.debug then
            app:use(function(req, res, next)
                print(string_format("[%s] %s %s", os_date("%H:%M:%S"), req.method, req.path))
                next()
            end)
        end
    end)

    if not s then
        handle_error(app_data, e, 2)
        return
    end

    if apps[app_data.name] then
        handle_error(app_data, "An application with that name already exists.", 2)
        return
    end
    apps[app_data.name] = app_data

    return app_data
end

http_app.update = function()
    for name, app_data in pairs(apps) do
        if app_data.is_listen then
            local s, e = pcall(app_data.server.update, app_data.server)
            if not s then
                handle_error(app_data, e, 2)
            end
        end
    end
end

http_app.remove = function(app_data_or_name)
    if type(app_data_or_name) == "string" then
        app_data_or_name = apps[app_data_or_name]
        if not app_data_or_name then
            return false, "Http-App not found"
        end
    end

    local name = app_data_or_name["name"]
    apps[name] = nil

    if app_data_or_name.debug then
        print("Http-App '" .. app_data_or_name.name .. "' close.")
    end
    app_data_or_name.server:stop()
end

http_app.close = function()
    for name, app_data in pairs(apps) do
        http_app.remove(app_data)
    end
end

return http_app
end

-- luna/core/init.lua
__lupack__["luna.core.init"] = function()
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

local luna = {}
local result = { luna, {} }

local s, e = pcall(function()
    local app = require("luna.core.default.app")
    luna.new_app = function(config)
        return app.new_app(config)
    end

    luna.remove_app = function(app_data_or_name)
        app.remove(app_data_or_name)
    end
    result[2].app_update = app.update
    result[2].app_close = app.close
end)
if not s then
    print("Luna error init default apps: " .. e)
end

s, e = pcall(function()
    if not _G["python"] then
        local web_app = require("luna.core.web.web_app")
        luna.new_web_app = function(config)
            return web_app.new_app(config)
        end

        luna.remove_web_app = function(app_data_or_name)
            web_app.remove(app_data_or_name)
        end

        result[2].web_app_update = web_app.update
        result[2].web_app_close = web_app.close
    end
end)
if not s then
    print("Luna error init web apps: " .. e)
end

s, e = pcall(function()
    if not _G["python"] then
        local http_app = require("luna.core.http.http_app")
        luna.new_http_app = function(config)
            return http_app.new_app(config)
        end

        luna.remove_http_app = function(app_data_or_name)
            http_app.remove(app_data_or_name)
        end

        result[2].http_app_update = http_app.update
        result[2].http_app_close = http_app.close
    end
end)
if not s then
    print("Luna error init http apps: " .. e)
end

return result

end

-- luna/core/web/web_app.lua
__lupack__["luna.core.web.web_app"] = function()
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

local webserv = require("luna.libs.web-serv")

local type, pairs, pcall, error, print =
    type, pairs, pcall, error, print

local function handle_error(app_data, message, err_level)
    if app_data.no_errors then
        if app_data.error_handler then
            app_data.error_handler(message)
        end
    else
        error(message, err_level or 2)
    end
end

local web_app, apps = {}, {}

--[[
config:
str name

str host
int port

boolean debug

func error_handler(error_message)
boolean no_errors

tbl protocols

tbl ssl
]]
web_app.new_app = function(config)
    local app_data
    app_data = {
        name = config.name or "unknown name",

        host = config.host or "*",
        port = config.port or 80,

        ssl = config.ssl,

        error_handler = config.error_handler or function(message)
            print("Error in web-app '" .. app_data.name .. "': " .. message)
        end,
        no_errors = config.no_errors,

        debug = config.debug == nil and true or config.debug,

        protocols = config.protocols or {},

        opcodes = {
            CLOSE = webserv.CLOSE,
            TEXT = webserv.TEXT,
            BINARY = webserv.BINARY,
            PING = webserv.PING,
            PONG = webserv.PONG,
            CONTINUATION = webserv.CONTINUATION,
        }
    }

    local ok, err = pcall(function()
        app_data.server = webserv.server.listen({
            host = app_data.host,
            port = app_data.port,

            on_error = function (message)
                handle_error(app_data, message, 2)
            end,

            protocols = app_data.protocols,
            ssl = app_data.ssl
        })
    end)

    if not ok then
        handle_error(app_data, "Failed to start web-app on " .. app_data.host .. ":" .. app_data.port .. ": " .. err)
        return nil, err
    else
        if app_data.debug then
            print("Web-App '" .. app_data.name .. "' started on " .. app_data.host .. ":" .. app_data.port)
        end
        if apps[app_data.name] then
            handle_error(app_data, "An application with that name already exists.", 2)
            return
        end
        apps[app_data.name] = app_data
    end

    return app_data
end

web_app.update = function(dt)
    for name, app_data in pairs(apps) do
        local s, e = pcall(app_data.server.update, app_data.server)
        if not s then
            handle_error(app_data, e, 2)
        end
    end
end

web_app.remove = function(app_data_or_name)
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
    app_data_or_name.server:close()
end

web_app.close = function()
    for name, app_data in pairs(apps) do
        web_app.remove(app_data)
    end
end

return web_app
end

-- luna/init.lua
__lupack__["luna.init"] = function()
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

local core = require("luna.core.init")

local luna = {}

for key, value in pairs(core[1]) do
    luna[key] = value
end

luna.update = function (dt)
    if core[2].app_update then
        core[2].app_update(dt)
    end
    if core[2].web_app_update then
        core[2].web_app_update(dt)
    end
    if core[2].http_app_update then
        core[2].http_app_update()
    end
end

luna.close = function ()
    if core[2].app_close then
        print(pcall(core[2].app_close))
    end
    if core[2].web_app_close then
        print(pcall(core[2].web_app_close))
    end
    if core[2].http_app_update then
        print(pcall(core[2].http_app_close))
    end
end

return luna
end

-- luna/libs/httpserv.lua
__lupack__["luna.libs.httpserv"] = function()
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

local httpserv = {
    server = require("luna.libs.httpserv.server"),
    constants = require("luna.libs.httpserv.constants"),
    util = require("luna.libs.httpserv.util"),
    static = require("luna.libs.httpserv.static")
}

return httpserv
end

-- luna/libs/httpserv/constants.lua
__lupack__["luna.libs.httpserv.constants"] = function()
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

local constants = {}

constants.METHODS = {
    GET = "GET",
    POST = "POST",
    PUT = "PUT",
    DELETE = "DELETE",
    PATCH = "PATCH",
    HEAD = "HEAD",
    OPTIONS = "OPTIONS"
}

constants.STATUS_CODES = {
    [100] = "Continue",
    [101] = "Switching Protocols",
    [200] = "OK",
    [201] = "Created",
    [204] = "No Content",
    [301] = "Moved Permanently",
    [302] = "Found",
    [304] = "Not Modified",
    [400] = "Bad Request",
    [401] = "Unauthorized",
    [403] = "Forbidden",
    [404] = "Not Found",
    [405] = "Method Not Allowed",
    [500] = "Internal Server Error",
    [502] = "Bad Gateway",
    [503] = "Service Unavailable",
    [202] = "Accepted",
    [206] = "Partial Content",
    [307] = "Temporary Redirect",
    [429] = "Too Many Requests",
    [504] = "Gateway Timeout",
}

constants.MIME_TYPES = {
    -- Text
    ["html"] = "text/html",
    ["htm"] = "text/html",
    ["css"] = "text/css",
    ["js"] = "application/javascript",
    ["json"] = "application/json",
    ["txt"] = "text/plain",
    ["md"] = "text/markdown",
    ["xml"] = "application/xml",

    -- Images
    ["png"] = "image/png",
    ["jpg"] = "image/jpeg",
    ["jpeg"] = "image/jpeg",
    ["gif"] = "image/gif",
    ["svg"] = "image/svg+xml",
    ["ico"] = "image/x-icon",
    ["bmp"] = "image/bmp",
    ["webp"] = "image/webp",

    -- Sounds
    ["mp3"] = "audio/mpeg",
    ["mp4"] = "video/mp4",
    ["csv"] = "text/csv",
    ["bin"] = "application/octet-stream",

    -- Fonts
    ["woff"] = "font/woff",
    ["woff2"] = "font/woff2",
    ["ttf"] = "font/ttf",
    ["eot"] = "application/vnd.ms-fontobject",

    -- Application
    ["pdf"] = "application/pdf",
    ["zip"] = "application/zip",
    ["tar"] = "application/x-tar",
    ["gz"] = "application/gzip"
}

return constants
end

-- luna/libs/httpserv/json.lua
__lupack__["luna.libs.httpserv.json"] = function()
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
local pairs, error, rawget, next, type, tostring, math_huge, select, tonumber, string_format, table_insert,
    table_concat, math_floor, string_char =
        pairs, error, rawget, next, type, tostring, math.huge, select, tonumber, string.format, table.insert,
        table.concat, math.floor, string.char

local escape_char_map = {
    ["\\"] = "\\",
    ["\""] = "\"",
    ["\b"] = "b",
    ["\f"] = "f",
    ["\n"] = "n",
    ["\r"] = "r",
    ["\t"] = "t",
}

local escape_char_map_inv = { ["/"] = "/" }
for k, v in pairs(escape_char_map) do
    escape_char_map_inv[v] = k
end


local function escape_char(c)
    return "\\" .. (escape_char_map[c] or string_format("u%04x", c:byte()))
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
            table_insert(res, encode(v, stack))
        end
        stack[val] = nil
        return "[" .. table_concat(res, ",") .. "]"
    else
        -- Treat as an object
        for k, v in pairs(val) do
            if type(k) ~= "string" then
                error("invalid table: mixed or invalid key types")
            end
            table_insert(res, encode(k, stack) .. ":" .. encode(v, stack))
        end
        stack[val] = nil
        return "{" .. table_concat(res, ",") .. "}"
    end
end


local function encode_string(val)
    return '"' .. val:gsub('[%z\1-\31\\"]', escape_char) .. '"'
end


local function encode_number(val)
    -- Check for NaN, -inf and inf
    if val ~= val or val <= -math_huge or val >= math_huge then
        error("unexpected number value '" .. tostring(val) .. "'")
    end
    return string_format("%.14g", val)
end


local type_func_map = {
    ["nil"] = encode_nil,
    ["table"] = encode_table,
    ["string"] = encode_string,
    ["number"] = encode_number,
    ["boolean"] = tostring,
    ["function"] = function() return '"no support functions"' end
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
    return encode(val)
end

-------------------------------------------------------------------------------
-- Decode
-------------------------------------------------------------------------------

local parse
local function create_set(...)
    local res = {}
    for i = 1, select("#", ...) do
        res[select(i, ...)] = true
    end
    return res
end

local space_chars  = create_set(" ", "\t", "\r", "\n")
local delim_chars  = create_set(" ", "\t", "\r", "\n", "]", "}", ",")
local escape_chars = create_set("\\", "/", '"', "b", "f", "n", "r", "t", "u")
local literals     = create_set("true", "false", "null")

local literal_map  = {
    ["true"] = true,
    ["false"] = false,
    ["null"] = nil,
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
    error(string_format("%s at line %d col %d", msg, line_count, col_count))
end


local function codepoint_to_utf8(n)
    -- http://scripts.sil.org/cms/scripts/page.php?site_id=nrsi&id=iws-appendixa
    local f = math_floor
    if n <= 0x7f then
        return string_char(n)
    elseif n <= 0x7ff then
        return string_char(f(n / 64) + 192, n % 64 + 128)
    elseif n <= 0xffff then
        return string_char(f(n / 4096) + 224, f(n % 4096 / 64) + 128, n % 64 + 128)
    elseif n <= 0x10ffff then
        return string_char(f(n / 262144) + 240, f(n % 262144 / 4096) + 128,
            f(n % 4096 / 64) + 128, n % 64 + 128)
    end
    error(string_format("invalid unicode codepoint '%x'", n))
end


local function parse_unicode_escape(s)
    local n1 = tonumber(s:sub(1, 4), 16)
    local n2 = tonumber(s:sub(7, 10), 16)
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
    ['"'] = parse_string,
    ["0"] = parse_number,
    ["1"] = parse_number,
    ["2"] = parse_number,
    ["3"] = parse_number,
    ["4"] = parse_number,
    ["5"] = parse_number,
    ["6"] = parse_number,
    ["7"] = parse_number,
    ["8"] = parse_number,
    ["9"] = parse_number,
    ["-"] = parse_number,
    ["t"] = parse_literal,
    ["f"] = parse_literal,
    ["n"] = parse_literal,
    ["["] = parse_array,
    ["{"] = parse_object,
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

-- luna/libs/httpserv/middleware.lua
__lupack__["luna.libs.httpserv.middleware"] = function()
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

local middleware = {}

local Middleware = {}
Middleware.__index = Middleware

function Middleware:new()
    local obj = {
        stack = {}
    }
    setmetatable(obj, self)
    return obj
end

local table_insert = table.insert
function Middleware:use(fn)
    table_insert(self.stack, fn)
end

local pcall = pcall
function Middleware:run(req, res)
    local index = 1

    local function next()
        local middlewareFn = self.stack[index]
        if not middlewareFn then
            return true
        end

        index = index + 1

        local called = false
        local function nextWrapper()
            if not called then
                called = true
                next()
            end
        end

        local success, result = pcall(middlewareFn, req, res, nextWrapper)

        if not success then
            print("Middleware error: " .. result)
            return false
        end

        return true
    end

    return next()
end

function middleware.create()
    return Middleware:new()
end

return middleware
end

-- luna/libs/httpserv/request.lua
__lupack__["luna.libs.httpserv.request"] = function()
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

local util = require("luna.libs.httpserv.util")
local request = {}

local string_gmatch, table_insert, table_concat = string.gmatch, table.insert, table.concat

function request.parse(rawRequest, client, client_data)
    local req = {
        method = "",
        path = "",
        query = {},
        headers = {},
        body = "",
        client = client,
        client_data = client_data,
        raw = rawRequest
    }

    local headerEnd = rawRequest:find("\r\n\r\n") or rawRequest:find("\n\n")
    if not headerEnd then
        return nil, "Incomplete request"
    end

    local headersPart, bodyPart = rawRequest:match("^(.-)\r\n\r\n(.*)$")
    if not headersPart then
        headersPart, bodyPart = rawRequest:match("^(.-)\n\n(.*)$")
    end

    if not headersPart then
        return nil, "Invalid request format"
    end

    req.body = bodyPart or ""

    local lines = {}
    for line in string_gmatch(headersPart, "[^\r\n]+") do
        table_insert(lines, line)
    end

    if #lines == 0 then return nil, "Empty request" end

    local requestLine = lines[1]
    local method, path = requestLine:match("^(%u+)%s+(.-)%s+HTTP/[%d%.]+$")

    if not method or not path then
        return nil, "Invalid request line"
    end

    req.method = method

    local queryString = ""
    local questionMark = path:find("?")
    if questionMark then
        queryString = path:sub(questionMark + 1)
        path = path:sub(1, questionMark - 1)
    end

    req.path = path
    req.query = util.parseQueryString(queryString)

    for i = 2, #lines do
        local header = lines[i]
        local key, value = header:match("^([^:]+):%s*(.+)$")
        if key and value then
            req.headers[key:lower()] = util.trim(value)
        end
    end

    return req
end

return request
end

-- luna/libs/httpserv/response.lua
__lupack__["luna.libs.httpserv.response"] = function()
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

local constants, json, util =
    require("luna.libs.httpserv.constants"),
    require("luna.libs.httpserv.json"),
    require("luna.libs.httpserv.util")

local response = {}

local Response = {}
Response.__index = Response

local setmetatable = setmetatable
function Response:new()
    local obj = {
        statusCode = 200,
        headers = {
            ["Content-Type"] = "text/html",
            ["Connection"] = "close"
        },
        body = ""
    }
    setmetatable(obj, self)
    return obj
end

function Response:status(code)
    self.statusCode = code
    return self
end

function Response:setHeader(key, value)
    self.headers[key] = value
    return self
end

local string_format, table_insert, type, table_concat, tostring =
    string.format, table.insert, type, table.concat, tostring
function Response:send(data)
    if data then
        self.body = data
    end

    if type(self.body) == "string" and not self.headers["Content-Type"] then
        self.headers["Content-Type"] = "text/html"
    end

    return self
end

function Response:sendFile(filePath, mimeType)
    if not util.fileExists(filePath) then
        self:status(404):send("File not found")
        return self
    end

    local file = io.open(filePath, "rb")
    if not file then
        self:status(500):send("Unable to read file")
        return self
    end

    local content = file:read("*a")
    file:close()

    local ext = util.getFileExtension(filePath)
    mimeType = mimeType or constants.MIME_TYPES[ext and ext:sub(2)] or "application/octet-stream"

    self:setHeader("Content-Type", mimeType)
    self.body = content

    return self
end

function Response:json(data)
    self:setHeader("Content-Type", "application/json")
    self.body = (type(data) == "string" and data) or type(data) == "table" and json.encode(data) or "{}"
    return self
end

function Response:build()
    local statusLine = string_format("HTTP/1.1 %d %s",
        self.statusCode,
        constants.STATUS_CODES[self.statusCode] or "Unknown")

    local headers = { statusLine }

    local bodyLength = 0
    if self.body then
        if type(self.body) == "string" then
            bodyLength = #self.body
        else
            bodyLength = tostring(self.body):len()
        end
    end
    self:setHeader("Content-Length", tostring(bodyLength))

    for key, value in pairs(self.headers) do
        table_insert(headers, string_format("%s: %s", key, value))
    end

    table_insert(headers, "")
    table_insert(headers, "")

    local headerPart = table_concat(headers, "\r\n")

    return headerPart .. (self.body or "")
end

function response.create()
    return Response:new()
end

return response
end

-- luna/libs/httpserv/router.lua
__lupack__["luna.libs.httpserv.router"] = function()
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

local router = {}

local Router = {}
Router.__index = Router

function Router:new()
    local obj = {
        routes = {
            GET = {},
            POST = {},
            PUT = {},
            DELETE = {},
            PATCH = {},
            HEAD = {},
            OPTIONS = {}
        },
        groups = {}
    }
    setmetatable(obj, self)
    return obj
end

function Router:addRoute(method, path, handler)
    if not self.routes[method] then
        error("Unsupported HTTP method: " .. method)
    end

    self.routes[method][path] = handler
end

function Router:get(path, handler) self:addRoute("GET", path, handler) end
function Router:post(path, handler) self:addRoute("POST", path, handler) end
function Router:put(path, handler) self:addRoute("PUT", path, handler) end
function Router:delete(path, handler) self:addRoute("DELETE", path, handler) end
function Router:patch(path, handler) self:addRoute("PATCH", path, handler) end
function Router:head(path, handler) self:addRoute("HEAD", path, handler) end
function Router:options(path, handler) self:addRoute("OPTIONS", path, handler) end

function Router:findRoute(method, path)
    if not self.routes[method] then
        return nil
    end

    return self.routes[method][path]
end

function Router:group(prefix)
    local groupRouter = router.create()

    local function addGroupRoutes()
        for method, routes in pairs(groupRouter.routes) do
            for path, handler in pairs(routes) do
                local fullPath = prefix .. path
                if fullPath:sub(-1) == "/" and fullPath ~= "/" then
                    fullPath = fullPath:sub(1, -2)
                end
                self:addRoute(method, fullPath, handler)
            end
        end

        for _, nestedGroup in pairs(groupRouter.groups) do
            nestedGroup()
        end
    end

    table.insert(self.groups, addGroupRoutes)

    return groupRouter
end

function router.create()
    return Router:new()
end

return router
end

-- luna/libs/httpserv/server.lua
__lupack__["luna.libs.httpserv.server"] = function()
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

local socket, request, response, router, middleware =
    require("socket"),
    require("luna.libs.httpserv.request"),
    require("luna.libs.httpserv.response"),
    require("luna.libs.httpserv.router"),
    require("luna.libs.httpserv.middleware")

local ipairs, pcall, error, print, table_insert, table_remove, setmetatable, tonumber =
    ipairs, pcall, error, print, table.insert, table.remove, setmetatable, tonumber

local Server = {}
Server.__index = Server

function Server:new()
    local obj = {
        host = "localhost",
        port = 8080,
        protocol = "http",
        ssl_config = nil,
        router = router.create(),
        middleware = middleware.create(),
        running = false,
        server_socket = nil,
        clients = {},
        timeout = 0.001,
        ssl_available = nil,

        default_client_timeout = 30,
        default_max_header_size = 1024 * 1024 * 5,
        default_max_body_size = 1024 * 1024 * 10,

        events = {
            new_client = {},
            close_client = {},
            timeout = {},
            error = {}
        }
    }
    setmetatable(obj, self)
    return obj
end

function Server:on(event, callback)
    if self.events[event] then
        table_insert(self.events[event], callback)
    end
    return self
end

function Server:emit(event, ...)
    if self.events[event] then
        for _, callback in ipairs(self.events[event]) do
            local success, err = pcall(callback, ...)
            if not success then
                print("Event handler error (" .. event .. "): " .. err)
            end
        end
    end
end

function Server:use(middlewareFn)
    self.middleware:use(middlewareFn)
end

function Server:get(path, handler) self.router:get(path, handler) end
function Server:post(path, handler) self.router:post(path, handler) end
function Server:put(path, handler) self.router:put(path, handler) end
function Server:delete(path, handler) self.router:delete(path, handler) end
function Server:patch(path, handler) self.router:patch(path, handler) end
function Server:head(path, handler) self.router:head(path, handler) end
function Server:options(path, handler) self.router:options(path, handler) end

function Server:group(prefix)
    return self.router:group(prefix)
end

function Server:setDefaultTimeout(timeout)
    self.default_client_timeout = timeout
    return self
end

function Server:setDefaultMaxHeaderSize(size)
    self.default_max_header_size = size
    return self
end

function Server:setDefaultMaxBodySize(size)
    self.default_max_body_size = size
    return self
end

function Server:checkSSL()
    if self.ssl_available == nil then
        local success, ssl_module = pcall(require, "ssl")
        self.ssl_available = success and ssl_module or false
    end
    return self.ssl_available
end

function Server:createSSLContext(ssl_config)
    if not self:checkSSL() then
        return nil, "SSL not available"
    end

    local ssl = require("ssl")

    local cfg = {
        mode = "server",
        protocol = "any",
        options = {"all", "no_sslv2", "no_sslv3"},
        verify = "none",
        key = ssl_config.key,
        certificate = ssl_config.cert
    }

    return ssl.newcontext(cfg)
end

function Server:listen(port, host, protocol, ssl_config)
    self.port = port or self.port
    self.host = host or self.host
    self.protocol = protocol or "http"
    self.ssl_config = ssl_config

    if self.protocol == "https" then
        if not self:checkSSL() then
            error("HTTPS requested but SSL module is not available")
        end

        if not ssl_config or not ssl_config.cert or not ssl_config.key then
            error("HTTPS requires certificate and key files")
        end

        local ctx, err = self:createSSLContext(ssl_config)
        if not ctx then
            error("Failed to create SSL context: " .. err)
        end
        self.ssl_context = ctx
    end

    self.server_socket = socket.tcp()
    self.server_socket:setoption("reuseaddr", true)
    self.server_socket:settimeout(0)

    local success, err = self.server_socket:bind(self.host, self.port)
    if not success then
        error("Failed to bind to " .. self.host .. ":" .. self.port .. " - " .. err)
    end

    self.server_socket:listen(32)

    self.running = true

    for _, groupFunc in ipairs(self.router.groups) do
        groupFunc()
    end

    return self
end

function Server:wrapSSL(client_socket)
    if self.protocol ~= "https" or not self.ssl_context then
        return nil, nil, client_socket
    end

    local ssl = require("ssl")
    local ssl_socket, err = ssl.wrap(client_socket, self.ssl_context)
    if not ssl_socket then
        return nil, err, client_socket
    end

    ssl_socket:settimeout(0)
    local success, err = ssl_socket:dohandshake()
    if not success and err ~= "timeout" and err ~= "wantread" and err ~= "wantwrite" then
        return nil, err, client_socket
    end

    return ssl_socket, nil, client_socket
end

function Server:createClientData(client, is_ssl, raw_socket)
    local client_ip = "unknown"

    if is_ssl and raw_socket then
        local ip, port = raw_socket:getpeername()
        if ip then
            client_ip = ip .. ":" .. port
        end
    else
        local ip, port = client:getpeername()
        if ip then
            client_ip = ip .. ":" .. port
        end
    end

    local client_data = {
        socket = client,
        raw_socket = raw_socket or client,
        buffer = "",
        request = nil,
        response = nil,
        headers_received = false,
        is_ssl = is_ssl or false,
        connect_time = socket.gettime(),
        last_activity = socket.gettime(),
        ip = client_ip,

        set_timeout = function (self, timeout)
            self.timeout = timeout
        end,

        set_max_header_size = function (self, max_header_size)
            self.max_header_size = max_header_size
        end,

        set_max_body_size = function (self, max_body_size)
            self.max_body_size = max_body_size
        end,

        timeout = self.default_client_timeout,
        max_header_size = self.default_max_header_size,
        max_body_size = self.default_max_body_size
    }

    self:emit("new_client", client_data.ip, client_data)

    return client_data
end

function Server:closeClient(client_data, reason)
    if client_data.socket then
        client_data.socket:close()
    end

    self:emit("close_client", client_data.ip, client_data, reason)
end

function Server:checkClientTimeout(client_data)
    local now = socket.gettime()
    local inactive_time = now - client_data.last_activity

    if inactive_time > client_data.timeout then
        self:emit("timeout", client_data.ip, client_data, inactive_time)
        return true
    end

    return false
end

function Server:checkBufferSize(client_data)
    if #client_data.buffer > client_data.max_header_size then
        self:emit("error", client_data.ip, client_data, "Header too large")
        return true
    end

    if client_data.request and client_data.request.headers then
        local content_length = tonumber(client_data.request.headers["content-length"]) or 0
        if content_length > client_data.max_body_size then
            self:emit("error", client_data.ip, client_data, "Body too large")
            return true
        end
    end

    return false
end

function Server:update()
    if not self.running or not self.server_socket then
        return
    end

    local client = self.server_socket:accept()
    if client then
        client:settimeout(0)

        local ssl_client, ssl_err, raw_socket = self:wrapSSL(client)
        if ssl_err then
            print("SSL handshake failed: " .. ssl_err)
            client:close()
        else
            local is_ssl = ssl_client ~= nil
            local client_data = self:createClientData(
                ssl_client or client, 
                is_ssl, 
                is_ssl and raw_socket or client
            )
            table_insert(self.clients, client_data)
        end
    end

    local i = 1
    while i <= #self.clients do
        local client_data = self.clients[i]
        local client = client_data.socket
        local remove_client = false

        if self:checkClientTimeout(client_data) then
            self:closeClient(client_data, "timeout")
            remove_client = true
        end

        if not remove_client and self:checkBufferSize(client_data) then
            self:sendError(client, 413, "Request too large")
            self:closeClient(client_data, "buffer_overflow")
            remove_client = true
        end

        if not remove_client and client_data.is_ssl and not client_data.ssl_handshake_done then
            local success, err = client:dohandshake()
            if success then
                client_data.ssl_handshake_done = true
                client_data.last_activity = socket.gettime()
            elseif err and err ~= "timeout" and err ~= "wantread" and err ~= "wantwrite" then
                print("SSL handshake error: " .. err)
                self:closeClient(client_data, "ssl_error")
                remove_client = true
            end
        end

        if not remove_client and (not client_data.is_ssl or client_data.ssl_handshake_done) then
            local data, err, partial = client:receive(1024)
            if data then
                client_data.buffer = client_data.buffer .. data
                client_data.last_activity = socket.gettime()
            elseif partial and partial ~= "" then
                client_data.buffer = client_data.buffer .. partial
                client_data.last_activity = socket.gettime()
            end

            if not client_data.headers_received and client_data.buffer:find("\r\n\r\n") then
                client_data.headers_received = true
            end

            if client_data.buffer ~= "" and not client_data.request then
                client_data.request, err = request.parse(client_data.buffer, client, client_data)
                if client_data.request then
                    client_data.response = response.create()
                    self:processRequest(client_data.request, client_data.response, client_data)
                elseif err and err ~= "Incomplete request" then
                    self:sendError(client, 400, err)
                    self:closeClient(client_data, "parse_error")
                    remove_client = true
                end
            end

            if err == "closed" then
                self:closeClient(client_data, "client_closed")
                remove_client = true
            elseif err and err ~= "timeout" and err ~= "wantread" and err ~= "wantwrite" then
                print("Client error: " .. err)
                self:closeClient(client_data, "socket_error")
                remove_client = true
            end

            if not remove_client and client_data.request and client_data.response and client_data.response.body ~= "" then
                local responseData = client_data.response:build()
                local sent, send_err = client:send(responseData)
                if sent then
                    self:closeClient(client_data, "response_sent")
                    remove_client = true
                elseif send_err and send_err ~= "timeout" then
                    print("Send error: " .. send_err)
                    self:closeClient(client_data, "send_error")
                    remove_client = true
                else
                    client_data.last_activity = socket.gettime()
                end
            end
        end

        if remove_client then
            table_remove(self.clients, i)
        else
            i = i + 1
        end
    end
end

function Server:processRequest(req, res, client_data)
    local middlewareSuccess = self.middleware:run(req, res)

    if not middlewareSuccess then
        res:status(500):send("Middleware Error")
        return
    end

    if res.body == "" then
        local routeHandler = self.router:findRoute(req.method, req.path)

        if routeHandler then
            local success, handlerErr = pcall(routeHandler, req, res, client_data)
            if not success then
                print("Route handler error: " .. handlerErr)
                res:status(500):send("Internal Server Error")
            end
        else
            res:status(404):send("Not Found: " .. req.path)
        end
    end
end

function Server:sendError(client, statusCode, message)
    local res = response.create()
    res:status(statusCode)
    res:send("<h1>" .. statusCode .. " - " .. (message or "Error") .. "</h1>")
    client:send(res:build())
end

function Server:stop()
    self.running = false

    for _, client_data in ipairs(self.clients) do
        self:closeClient(client_data, "server_stopped")
    end
    self.clients = {}

    if self.server_socket then
        self.server_socket:close()
        self.server_socket = nil
    end
end

function Server:isRunning()
    return self.running
end

function Server:getClientCount()
    return #self.clients
end

function Server:getClientInfo()
    local info = {}
    for _, client in ipairs(self.clients) do
        table_insert(info, {
            ip = client.ip,
            connect_time = client.connect_time,
            last_activity = client.last_activity,
            inactive_time = socket.gettime() - client.last_activity,
            buffer_size = #client.buffer,
            headers_received = client.headers_received,
            has_request = client.request ~= nil,
            timeout = client.timeout,
            max_header_size = client.max_header_size,
            max_body_size = client.max_body_size
        })
    end
    return info
end

local server = {}

function server.create()
    return Server:new()
end

return server
end

-- luna/libs/httpserv/static.lua
__lupack__["luna.libs.httpserv.static"] = function()
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

local io_open = io.open
local util, constants =
    require("luna.libs.httpserv.util"),
    require("luna.libs.httpserv.constants")
local static = {}

function static.server(directory)
    return function(req, res, next)
        if req.method ~= "GET" then
            return next()
        end

        local safePath = req.path:gsub("%.%./", ""):gsub("//", "/")
        if safePath == "/" then
            safePath = "/index.html"
        end

        local filePath = directory .. safePath

        if util.fileExists(filePath) then
            local file = io_open(filePath, "rb")
            if file then
                local content = file:read("*a")
                file:close()

                local ext = util.getFileExtension(filePath)
                local mimeType = constants.MIME_TYPES[ext and ext:sub(2)] or "application/octet-stream"

                res:setHeader("Content-Type", mimeType)
                res:status(200):send(content)
                return
            end
        end

        next()
    end
end

return static
end

-- luna/libs/httpserv/util.lua
__lupack__["luna.libs.httpserv.util"] = function()
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

local util = {}
local string_gsub, string_char, tonumber, string_gmatch, string_match, io_open =
    string.gsub, string.char, tonumber, string.gmatch, string.match, io.open

function util.urlDecode(str)
    return string_gsub(str, "%%(%x%x)", function(hex)
        return string_char(tonumber(hex, 16))
    end)
end

function util.parseQueryString(query)
    local params = {}
    if not query or query == "" then return params end

    for key, value in string_gmatch(query, "([^&=]+)=([^&=]*)") do
        key = util.urlDecode(key)
        value = util.urlDecode(value)
        params[key] = value
    end

    return params
end

function util.trim(str)
    return string_match(str, "^%s*(.-)%s*$") or str
end

function util.getFileExtension(filename)
    return filename:match("^.+(%..+)$")
end

function util.fileExists(path)
    local file = io_open(path, "r")
    if file then
        file:close()
        return true
    end
    return false
end

return util
end

-- luna/libs/json.lua
__lupack__["luna.libs.json"] = function()
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
local pairs, error, rawget, next, type, tostring, math_huge, select, tonumber, string_format, table_insert,
table_concat, math_floor, string_char =
    pairs, error, rawget, next, type, tostring, math.huge, select, tonumber, string.format, table.insert,
    table.concat, math.floor, string.char

local escape_char_map = {
    ["\\"] = "\\",
    ["\""] = "\"",
    ["\b"] = "b",
    ["\f"] = "f",
    ["\n"] = "n",
    ["\r"] = "r",
    ["\t"] = "t",
}

local escape_char_map_inv = { ["/"] = "/" }
for k, v in pairs(escape_char_map) do
    escape_char_map_inv[v] = k
end


local function escape_char(c)
    return "\\" .. (escape_char_map[c] or string_format("u%04x", c:byte()))
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
            table_insert(res, encode(v, stack))
        end
        stack[val] = nil
        return "[" .. table_concat(res, ",") .. "]"
    else
        -- Treat as an object
        for k, v in pairs(val) do
            if type(k) ~= "string" then
                error("invalid table: mixed or invalid key types")
            end
            table_insert(res, encode(k, stack) .. ":" .. encode(v, stack))
        end
        stack[val] = nil
        return "{" .. table_concat(res, ",") .. "}"
    end
end


local function encode_string(val)
    return '"' .. val:gsub('[%z\1-\31\\"]', escape_char) .. '"'
end


local function encode_number(val)
    -- Check for NaN, -inf and inf
    if val ~= val or val <= -math_huge or val >= math_huge then
        error("unexpected number value '" .. tostring(val) .. "'")
    end
    return string_format("%.14g", val)
end


local type_func_map = {
    ["nil"] = encode_nil,
    ["table"] = encode_table,
    ["string"] = encode_string,
    ["number"] = encode_number,
    ["boolean"] = tostring,
    ["function"] = function() return '"no support functions"' end
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
    return encode(val)
end

-------------------------------------------------------------------------------
-- Decode
-------------------------------------------------------------------------------

local parse
local function create_set(...)
    local res = {}
    for i = 1, select("#", ...) do
        res[select(i, ...)] = true
    end
    return res
end

local space_chars  = create_set(" ", "\t", "\r", "\n")
local delim_chars  = create_set(" ", "\t", "\r", "\n", "]", "}", ",")
local escape_chars = create_set("\\", "/", '"', "b", "f", "n", "r", "t", "u")
local literals     = create_set("true", "false", "null")

local literal_map  = {
    ["true"] = true,
    ["false"] = false,
    ["null"] = nil,
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
    error(string_format("%s at line %d col %d", msg, line_count, col_count))
end


local function codepoint_to_utf8(n)
    -- http://scripts.sil.org/cms/scripts/page.php?site_id=nrsi&id=iws-appendixa
    local f = math_floor
    if n <= 0x7f then
        return string_char(n)
    elseif n <= 0x7ff then
        return string_char(f(n / 64) + 192, n % 64 + 128)
    elseif n <= 0xffff then
        return string_char(f(n / 4096) + 224, f(n % 4096 / 64) + 128, n % 64 + 128)
    elseif n <= 0x10ffff then
        return string_char(f(n / 262144) + 240, f(n % 262144 / 4096) + 128,
            f(n % 4096 / 64) + 128, n % 64 + 128)
    end
    error(string_format("invalid unicode codepoint '%x'", n))
end


local function parse_unicode_escape(s)
    local n1 = tonumber(s:sub(1, 4), 16)
    local n2 = tonumber(s:sub(7, 10), 16)
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
    ['"'] = parse_string,
    ["0"] = parse_number,
    ["1"] = parse_number,
    ["2"] = parse_number,
    ["3"] = parse_number,
    ["4"] = parse_number,
    ["5"] = parse_number,
    ["6"] = parse_number,
    ["7"] = parse_number,
    ["8"] = parse_number,
    ["9"] = parse_number,
    ["-"] = parse_number,
    ["t"] = parse_literal,
    ["f"] = parse_literal,
    ["n"] = parse_literal,
    ["["] = parse_array,
    ["{"] = parse_object,
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

-- luna/libs/security.lua
__lupack__["luna.libs.security"] = function()
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

-- luna/libs/udp_messages.lua
__lupack__["luna.libs.udp_messages"] = function()
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

-- luna/libs/web-serv.lua
__lupack__["luna.libs.web-serv"] = function()
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
return require("luna")