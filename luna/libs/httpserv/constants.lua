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
    [503] = "Service Unavailable"
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