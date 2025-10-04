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

local request = require("luna.libs.httpserv.request")
local response = require("luna.libs.httpserv.response")
local router = require("luna.libs.httpserv.router")
local middleware = require("luna.libs.httpserv.middleware")

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
        table.insert(self.events[event], callback)
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
            table.insert(self.clients, client_data)
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
            table.remove(self.clients, i)
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
            local success, handlerErr = pcall(routeHandler, req, res)
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
        table.insert(info, {
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