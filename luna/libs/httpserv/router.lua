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

local router = {}

local Router = {}
Router.__index = Router

function Router:new()
    local obj = {
        routes = {
            GET = {},
            POST = {},
            PUT = {},
            DELETE = {},
            PATCH = {},
            HEAD = {},
            OPTIONS = {}
        },
        groups = {}
    }
    setmetatable(obj, self)
    return obj
end

function Router:addRoute(method, path, handler)
    if not self.routes[method] then
        error("Unsupported HTTP method: " .. method)
    end

    self.routes[method][path] = handler
end

function Router:get(path, handler) self:addRoute("GET", path, handler) end
function Router:post(path, handler) self:addRoute("POST", path, handler) end
function Router:put(path, handler) self:addRoute("PUT", path, handler) end
function Router:delete(path, handler) self:addRoute("DELETE", path, handler) end
function Router:patch(path, handler) self:addRoute("PATCH", path, handler) end
function Router:head(path, handler) self:addRoute("HEAD", path, handler) end
function Router:options(path, handler) self:addRoute("OPTIONS", path, handler) end

function Router:findRoute(method, path)
    if not self.routes[method] then
        return nil
    end

    return self.routes[method][path]
end

function Router:group(prefix)
    local groupRouter = router.create()

    local function addGroupRoutes()
        for method, routes in pairs(groupRouter.routes) do
            for path, handler in pairs(routes) do
                local fullPath = prefix .. path
                if fullPath:sub(-1) == "/" and fullPath ~= "/" then
                    fullPath = fullPath:sub(1, -2)
                end
                self:addRoute(method, fullPath, handler)
            end
        end

        for _, nestedGroup in pairs(groupRouter.groups) do
            nestedGroup()
        end
    end

    table.insert(self.groups, addGroupRoutes)

    return groupRouter
end

function router.create()
    return Router:new()
end

return router