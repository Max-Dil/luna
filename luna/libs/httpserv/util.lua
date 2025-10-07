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