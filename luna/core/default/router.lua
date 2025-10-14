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

local req = require("luna.core.default.requests")
local router, print, type = {}, print, type

router.new_router = function(app, config)
    if app.routers[config.prefix] then
        router.remove_router(app, config.prefix)
    end
    local router_data
    router_data = setmetatable({
        prefix = config.prefix,
        no_errors = config.no_errors,
        error_handler = config.error_handler or function(message) 
            print("Error in router prefix: "..router_data.prefix.." error: "..message) 
        end,
        requests = {},
        app = app,
    }, {__index = req})

    app.routers[router_data.prefix] = router_data
    return router_data
end

router.remove_router = function(app, router_data)
    if type(router_data) == "string" then
        router_data = app.routers[router_data]
    end

    app.routers[router_data.prefix] = nil
end

return router