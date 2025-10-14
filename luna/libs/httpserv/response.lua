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