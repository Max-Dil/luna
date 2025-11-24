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
    coroutine_yield, coroutine_status, coroutine_resume, coroutine_create, os_time
    =
        require 'socket', require 'webserv.handshake', require 'webserv.sync',
        table.concat, table.insert, table.remove,
        math.min,
        coroutine.yield, coroutine.status, coroutine.resume, coroutine.create, os.time

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

    local client = function(p, protocol, clients)
        local sock, raw_sock = p.sock, p.raw_sock
        local self = {}

        self.state = 'OPEN'
        self.is_server = true
        self.sock = sock
        self.raw_sock = raw_sock or sock

        self.getpeername = function(self)
            local ip, port, err
            if p.ip and p.port then
                return p.ip, p.port
            end

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
            local now = os_time()
            for i = #pendings, 1, -1 do
                local p = pendings[i]
                if now - p.created_at > 10 then
                    p.sock:close()
                    if p.raw_sock ~= p.sock then p.raw_sock:close() end
                    table_remove(pendings, i)
                end
            end

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

                        local ip, port = newsock:getpeername()
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
                                    ssl_handshake_done = false,
                                    ip = ip,
                                    port = port,
                                    created_at = os_time()
                                }
                                tinsert(pendings, pending)
                            end
                        else
                            local pending = {
                                sock = newsock,
                                raw_sock = newsock,
                                buffer = "",
                                request = {},
                                ssl_handshake_done = true,
                                ip = ip,
                                port = port,
                                created_at = os_time()
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
                                    if handshake_err ~= "closed" and handshake_err ~= "unexpected eof while reading" then
                                        if on_error then
                                            on_error('SSL handshake failed: ' .. tostring(handshake_err))
                                        end
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

                                        local new_client = client(p, protocol_index, clients)
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
                                    if r_err ~= "closed" and on_error then
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
    local frame, handshake, tools, socket = require 'webserv.frame', require 'webserv.handshake', require 'webserv.tools', require 'socket'
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

    local close = function(self, code, reason, wait_receive, timeout)
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
        code = 1005
        reason = ''

        if n == #encoded then
            self.is_closing = true
            if wait_receive then
                timeout = timeout or 5
                local coro = coroutine.create(function ()
                    local rmsg, opcode = self:receive()
                    if rmsg and opcode == frame.CLOSE then
                        code, reason = frame.decode_close(rmsg)
                        was_clean = true
                    end
                end)

                local start = socket.gettime()
                while start - socket.gettime() < timeout do
                    coroutine.resume(coro)
                    if coroutine.status(coro) == "dead" then
                        break
                    end
                    coroutine.yield("wantread")
                end
            else
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