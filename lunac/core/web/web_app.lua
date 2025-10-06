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

local webserv = require("lunac.libs.web-serv")

local function handle_error(app_data, message, err_level)
    if app_data.no_errors then
        if app_data.error_handler then
            app_data.error_handler(message)
        end
    else
        error(message, err_level or 2)
    end
end

local apps = {}
local web_app = {}

--[[
config:
str name
str url

boolean debug

func error_handler(error_message)
boolean no_errors

str protocol

tbl ssl

func on_connect(self)
func on_message(self, message, opcode)
func on_close(self, code, reason)
]]
web_app.connect = function(config)
    local app_data
    app_data = {
        name = config.name or "unknown name",
        url = config.url or "ws://localhost:80",

        error_handler = config.error_handler or function(message)
            print("Error in web-app '" .. app_data.name .. "': " .. message)
        end,
        no_errors = config.no_errors,

        ssl = config.ssl,
        protocol = config.protocol,

        debug = config.debug == nil and true or config.debug,

        on_connect = config.on_connect,
        on_message = config.on_message,
        on_close = config.on_close,

        send = function(self, message, opcode)
            self.client:send(message, opcode)
        end,

        opcodes = {
            CLOSE = webserv.CLOSE,
            TEXT = webserv.TEXT,
            BINARY = webserv.BINARY,
            PING = webserv.PING,
            PONG = webserv.PONG,
            CONTINUATION = webserv.CONTINUATION,
        }
    }

    if apps[app_data.name] then
        handle_error(app_data, "An application with that name already exists.", 2)
        return
    end

    local ok, err = pcall(function()
        local client = webserv.client.new()
        app_data.client = client

        client:start(function(self)
            local success, protocol, headers = self:connect(app_data.url, app_data.protocol, app_data.ssl)
            if not success then
                handle_error(app_data, "Connection failed. Error: " .. tostring(protocol), 2)
                return
            end

            if app_data.on_connect then
                app_data.on_connect(app_data)
            end

            client.on_error = function(self, err)
                handle_error(app_data, err, 2)
            end

            if app_data.on_close then
                client.on_close = function(self, was_clean, code, reason)
                    app_data.on_close(app_data, code, reason)
                end
            end

            while self.state == 'OPEN' do
                local data, opcode, was_clean, code, reason = self:receive()
                if data then
                    if opcode == 8 then
                        local result
                        if app_data.on_close then
                            result = app_data.on_close(self, code, reason)
                        end
                        if result ~= false then
                            handle_error(app_data,
                                "Server closed connection. Code: " .. tostring(code) .. "   Reason: " .. tostring(reason),
                                2)
                            break
                        end
                    end
                    if app_data.on_message then
                        app_data.on_message(app_data, data, opcode)
                    end
                elseif not was_clean then
                    handle_error(app_data, "Receive error. Code: " .. tostring(code) .. "   Reason: " .. tostring(reason),
                        2)
                    break
                end
            end
        end)
    end)

    if not ok then
        handle_error(app_data, "Failed to start web-app on " .. app_data.url .. ": " .. err)
        return nil, err
    else
        if app_data.debug then
            print("Web-App '" .. app_data.name .. "' started on " .. app_data.url)
        end
        if apps[app_data.name] then
            handle_error(app_data, "An application with that name already exists.", 2)
            return
        end
        apps[app_data.name] = app_data
    end

    return app_data
end

web_app.update = function()
    for name, app_data in pairs(apps) do
        app_data.client:update()
    end
end

web_app.close = function(app_data_or_name)
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
    app_data_or_name.client:close(1000, "App closing")
end

web_app.close_all = function()
    for name, app_data in pairs(apps) do
        web_app.remove(app_data)
    end
end

return web_app
