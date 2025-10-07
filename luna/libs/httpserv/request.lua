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

    if not rawRequest:find("\r\n\r\n") and not rawRequest:find("\n\n") then
        return nil, "Incomplete request"
    end

    local lines = {}
    for line in string_gmatch(rawRequest, "[^\r\n]+") do
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

    local i = 2
    while i <= #lines and lines[i] ~= "" do
        local header = lines[i]
        local key, value = header:match("^([^:]+):%s*(.+)$")
        if key and value then
            req.headers[key:lower()] = util.trim(value)
        end
        i = i + 1
    end

    if i < #lines then
        req.body = table_concat(lines, "\r\n", i + 1)
    end

    return req
end

return request