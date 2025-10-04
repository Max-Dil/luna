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

local webserv = require("luna.libs.web-serv")

local function handle_error(app_data, message, err_level)
    if app_data.no_errors then
        if app_data.error_handler then
            app_data.error_handler(message)
        end
    else
        error(message, err_level or 2)
    end
end

local web_app = {}
local apps = {}

--[[
config:
str name

str host
int port

boolean debug

func error_handler(error_message)
boolean no_errors

tbl protocols

tbl ssl
]]
web_app.new_app = function(config)
    local app_data
    app_data = {
        name = config.name or "unknown name",

        host = config.host or "*",
        port = config.port or 80,

        ssl = config.ssl,

        error_handler = config.error_handler or function(message)
            print("Error in web-app '" .. app_data.name .. "': " .. message)
        end,
        no_errors = config.no_errors,

        debug = config.debug == nil and true or config.debug,

        protocols = config.protocols or {},

        opcodes = {
            CLOSE = webserv.CLOSE,
            TEXT = webserv.TEXT,
            BINARY = webserv.BINARY,
            PING = webserv.PING,
            PONG = webserv.PONG,
            CONTINUATION = webserv.CONTINUATION,
        }
    }

    local ok, err = pcall(function()
        app_data.server = webserv.server.listen({
            host = app_data.host,
            port = app_data.port,

            on_error = function (message)
                handle_error(app_data, message, 2)
            end,

            protocols = app_data.protocols,
            ssl = app_data.ssl
        })
    end)

    if not ok then
        handle_error(app_data, "Failed to start web-app on " .. app_data.host .. ":" .. app_data.port .. ": " .. err)
        return nil, err
    else
        if app_data.debug then
            print("Web-App '" .. app_data.name .. "' started on " .. app_data.host .. ":" .. app_data.port)
        end
        if apps[app_data.name] then
            handle_error(app_data, "An application with that name already exists.", 2)
            return
        end
        apps[app_data.name] = app_data
    end

    return app_data
end

web_app.update = function(dt)
    for name, app_data in pairs(apps) do
        app_data.server:update()
    end
end

web_app.remove = function(app_data_or_name)
    if type(app_data_or_name) == "string" then
        app_data_or_name = apps[app_data_or_name]
        if not app_data_or_name then
            return false, "Web-App not found"
        end
    end

    local name = app_data_or_name["name"]
    apps[name] = nil

    if app_data_or_name.debug then
        print("Web-App '" .. app_data_or_name.name .. "' close.")
    end
    app_data_or_name.server:close()
end

web_app.close = function()
    for name, app_data in pairs(apps) do
        web_app.remove(app_data)
    end
end

return web_app
