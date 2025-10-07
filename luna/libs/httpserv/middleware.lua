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

local middleware = {}

local Middleware = {}
Middleware.__index = Middleware

function Middleware:new()
    local obj = {
        stack = {}
    }
    setmetatable(obj, self)
    return obj
end

local table_insert = table.insert
function Middleware:use(fn)
    table_insert(self.stack, fn)
end

local pcall = pcall
function Middleware:run(req, res)
    local index = 1

    local function next()
        local middlewareFn = self.stack[index]
        if not middlewareFn then
            return true
        end

        index = index + 1

        local called = false
        local function nextWrapper()
            if not called then
                called = true
                next()
            end
        end

        local success, result = pcall(middlewareFn, req, res, nextWrapper)

        if not success then
            print("Middleware error: " .. result)
            return false
        end

        return true
    end

    return next()
end

function middleware.create()
    return Middleware:new()
end

return middleware