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

local lunac = {}

local core = require("lunac.core.init")

for key, value in pairs(core[1]) do
    lunac[key] = value
end

lunac.update = function (dt)
    if core[2].app_update then
        core[2].app_update(dt)
    end
    if core[2].http_update then
        core[2].http_update()
    end
    if core[2].web_update then
        core[2].web_update()
    end
end

lunac.close = function ()
    if core[2].app_close then
        print(pcall(core[2].app_close))
    end
    if core[2].http_close then
        print(pcall(core[2].http_close))
    end
    if core[2].web_close then
        print(pcall(core[2].web_close))
    end
end

return lunac