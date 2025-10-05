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

local core = {}
local result = { core, {} }

local s, e = pcall(function()
    local app = require("lunac.core.default.app")
    core.connect_to_app = function(config)
        return app.connect(config)
    end

    core.disconnect_to_app = function(app_reference)
        return app.close(app_reference)
    end

    result[2].app_update = app.update
    result[2].app_close = app.close_all
end)

if not s then
    print("Lunac error init default apps: " .. e)
end

s, e = pcall(function()
    if not _G["python"] then
        local http = require("lunac.core.http.http")
        core.http = http.http

        result[2].http_update = http.update
        result[2].http_close = http.http.close_all
    end
end)

if not s then
    print("Lunac error init http request: " .. e)
end

return result
