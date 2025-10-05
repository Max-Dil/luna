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