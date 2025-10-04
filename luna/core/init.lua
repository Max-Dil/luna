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

local luna = {}
local result = { luna, {} }

local s, e = pcall(function()
    local app = require("luna.core.default.app")
    luna.new_app = function(config)
        return app.new_app(config)
    end

    luna.remove_app = function(app_data_or_name)
        app.remove(app_data_or_name)
    end
    result[2].app_update = app.update
    result[2].app_close = app.close
end)
if not s then
    print("Luna error init default apps: " .. e)
end

s, e = pcall(function()
    if not _G["python"] then
        local web_app = require("luna.core.web.web_app")
        luna.new_web_app = function(config)
            return web_app.new_app(config)
        end

        luna.remove_web_app = function(app_data_or_name)
            web_app.remove(app_data_or_name)
        end

        result[2].web_app_update = web_app.update
        result[2].web_app_close = web_app.close
    end
end)
if not s then
    print("Luna error init web apps: " .. e)
end

s, e = pcall(function()
    if not _G["python"] then
        local http_app = require("luna.core.http.http_app")
        luna.new_http_app = function(config)
            return http_app.new_app(config)
        end

        luna.remove_http_app = function(app_data_or_name)
            http_app.remove(app_data_or_name)
        end

        result[2].http_app_update = http_app.update
        result[2].http_app_close = http_app.close
    end
end)
if not s then
    print("Luna error init http apps: " .. e)
end

return result
