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
local constants = require("luna.libs.httpserv.constants")

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
            local file = io.open(filePath, "rb")
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