------------------------------------------------------------------------------
-- LuaSec 0.5+
-- Copyright (C) 2006-2011 Bruno Silvestre
------------------------------------------------------------------------------

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

local core = require("ssl.core")
local context = require("ssl.context")
local x509 = require("ssl.x509")

local M = {}
M._COPYRIGHT = core.copyright()

M.loadcertificate = x509.load

local registry = setmetatable({}, { __mode = "k" })

local function optexec(func, param, ctx)
    if not param then
        return true
    end

    if type(param) == "table" then
        return func(ctx, unpack(param))
    else
        return func(ctx, param)
    end
end

local function extractConnectionInfo(ssl, field)
    local compression, err = core.compression(ssl)
    if err then
        return compression, err
    end

    if field == "compression" then
        return compression
    end

    local connectionInfo = {
        compression = compression
    }

    local str, bits, algbits, protocol = core.info(ssl)
    if str then
        connectionInfo.cipher,
        connectionInfo.protocol,
        connectionInfo.key,
        connectionInfo.authentication,
        connectionInfo.encryption,
        connectionInfo.mac = string.match(str,
            "^(%S+)%s+(%S+)%s+Kx=(%S+)%s+Au=(%S+)%s+Enc=(%S+)%s+Mac=(%S+)")
        connectionInfo.export = (string.match(str, "%sexport%s*$") ~= nil)
        connectionInfo.bits = bits
        connectionInfo.algbits = algbits
    end

    if protocol then
        connectionInfo.protocol = protocol
    end

    if field then
        return connectionInfo[field]
    end

    return next(connectionInfo) and connectionInfo or nil
end

local function createContext(protocol)
    if context.new then
        return context.new(protocol)
    elseif context.create then
        return context.create(protocol)
    else
        return nil, "no context creation function available"
    end
end

function M.newcontext(cfg)
    local ctx, msg = createContext(cfg.protocol)
    if not ctx then
        return nil, msg
    end

    local success, err = context.setmode(ctx, cfg.mode)
    if not success then
        return nil, err
    end

    if cfg.key then
        if cfg.password and type(cfg.password) ~= "function" and type(cfg.password) ~= "string" then
            return nil, "invalid password type"
        end

        success, err = context.loadkey(ctx, cfg.key, cfg.password)
        if not success then
            return nil, err
        end
    end

    if cfg.certificate then
        success, err = context.loadcert(ctx, cfg.certificate)
        if not success then
            return nil, err
        end
    end

    if cfg.cafile or cfg.capath then
        success, err = context.locations(ctx, cfg.cafile, cfg.capath)
        if not success then
            return nil, err
        end
    end

    if cfg.ciphers then
        success, err = context.setcipher(ctx, cfg.ciphers)
        if not success then
            return nil, err
        end
    end

    success, err = optexec(context.setverify, cfg.verify, ctx)
    if not success then
        return nil, err
    end

    success, err = optexec(context.setoptions, cfg.options, ctx)
    if not success then
        return nil, err
    end

    if cfg.depth then
        success, err = context.setdepth(ctx, cfg.depth)
        if not success then
            return nil, err
        end
    end

    if cfg.dhparam then
        if type(cfg.dhparam) ~= "function" then
            return nil, "invalid DH parameter type"
        end
        context.setdhparam(ctx, cfg.dhparam)
    end

    if cfg.curve then
        success, err = context.setcurve(ctx, cfg.curve)
        if not success then
            return nil, err
        end
    end

    if cfg.verifyext and context.setverifyext then
        success, err = optexec(context.setverifyext, cfg.verifyext, ctx)
        if not success then
            return nil, err
        end
    end

    if cfg.ciphersuites and context.setciphersuites then
        success, err = context.setciphersuites(ctx, cfg.ciphersuites)
        if not success then
            return nil, err
        end
    end

    if cfg.alpn and context.setalpn then
        success, err = context.setalpn(ctx, cfg.alpn)
        if not success then
            return nil, err
        end
    end

    return ctx
end

function M.wrap(sock, cfg)
    local ctx, msg

    if type(cfg) == "table" then
        ctx, msg = M.newcontext(cfg)
        if not ctx then
            return nil, msg
        end
    else
        ctx = cfg
    end

    local s, err = core.create(ctx)
    if not s then
        return nil, err
    end

    core.setfd(s, sock:getfd())
    sock:setfd(core.SOCKET_INVALID or -1)
    registry[s] = ctx

    return s
end

if not core.SOCKET_INVALID then
    core.SOCKET_INVALID = -1
end

core.setmethod("info", extractConnectionInfo)

return M