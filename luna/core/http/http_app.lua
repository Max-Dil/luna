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

local httpserv, socket = require("luna.libs.httpserv"), require("socket")

local type, pairs, ipairs, pcall, error, tostring, print, table_concat, table_insert, 
      math_max, math_ceil, math_random, os_time, os_date, string_format, socket_gettime,
      json_decode, util_parseQueryString =
    type, pairs, ipairs, pcall, error, tostring, print, table.concat, table.insert,
    math.max, math.ceil, math.random, os.time, os.date, string.format, (socket and socket.gettime) or (function() return os.time end)(),
    (function() local json = require("luna.libs.httpserv.json") return json.decode end)(),
    (function() local util = require("luna.libs.httpserv.util") return util.parseQueryString end)()

local function handle_error(app_data, message, err_level)
    if app_data.no_errors then
        if app_data.error_handler then
            app_data.error_handler(message)
        end
    else
        error(message, err_level or 2)
    end
end

local http_app, apps = {}, {}

--[[
config:
str name
fun error_handler
boolean no_errors
boolean debug
func new_client(ip, client_data)
func close_client(ip, client_data, reason)
func timeout_client(ip, client_data, inactive_time)
func error_client(ip, client_data, error_msg)
]]
http_app.new_app = function(config)
    local app_data
    app_data = {
        name = config.name or "unknown name",

        error_handler = config.error_handler or function(message)
            print("Error in app '" .. app_data.name .. "': " .. message)
        end,
        no_errors = config.no_errors,

        debug = config.debug == nil and true or config.debug,

        new_client = config.new_client,
        close_client = config.close_client,
        timeout_client = config.timeout_client,
        error_client = config.error_client,

        STATUS_CODES = httpserv.constants.STATUS_CODES,
        MIME_TYPES = httpserv.constants.MIME_TYPES,

        templates = {
            static = httpserv.static.server, -- app.use(app.templates.static("directory"))
            cors = function(options)
                options = options or {}
                local allowed_origins = options.origins or { "*" }
                local allowed_methods = options.methods or { "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD" }
                local allowed_headers = options.headers or { "Content-Type", "Authorization", "X-Requested-With" }
                local allow_credentials = options.credentials or false
                local max_age = options.max_age or 86400

                local trim = function(str)
                    return str:gsub("^%s+", ""):gsub("%s+$", "")
                end

                local origins_lookup = {}
                for _, origin in ipairs(allowed_origins) do
                    origins_lookup[origin] = true
                end

                local methods_lookup = {}
                for _, method in ipairs(allowed_methods) do
                    methods_lookup[method] = true
                end

                return function(req, res, next)
                    local origin = req.headers.origin

                    local current_origin = "*"

                    if origin then
                        if origins_lookup[origin] then
                            current_origin = origin
                        elseif origins_lookup["*"] then
                            current_origin = "*"
                        else
                            current_origin = "null"
                        end
                    end

                    if allow_credentials and current_origin == "*" then
                        current_origin = origin or "null"
                    end

                    res:setHeader("Access-Control-Allow-Origin", current_origin)
                    res:setHeader("Access-Control-Allow-Methods", table_concat(allowed_methods, ", "))
                    res:setHeader("Access-Control-Allow-Headers", table_concat(allowed_headers, ", "))

                    if allow_credentials and current_origin ~= "*" then
                        res:setHeader("Access-Control-Allow-Credentials", "true")
                    end

                    if max_age then
                        res:setHeader("Access-Control-Max-Age", tostring(max_age))
                    end

                    if req.method == "OPTIONS" then
                        local requested_method = req.headers["access-control-request-method"]
                        if requested_method and not methods_lookup[requested_method] then
                            res:status(405):json({ error = "Method not allowed by CORS policy" })
                            return
                        end

                        local requested_headers = req.headers["access-control-request-headers"]
                        if requested_headers then
                            local headers = {}
                            for header in requested_headers:gmatch("[^,]+") do
                                header = trim(header)
                                table_insert(headers, header)
                            end

                            for _, header in ipairs(headers) do
                                local allowed = false
                                for _, allowed_header in ipairs(allowed_headers) do
                                    if header:lower() == allowed_header:lower() then
                                        allowed = true
                                        break
                                    end
                                end
                                if not allowed then
                                    res:status(400):json({ error = "Header not allowed by CORS policy: " .. header })
                                    return
                                end
                            end
                        end

                        res:status(204):send("true")
                        return
                    end

                    if not methods_lookup[req.method] then
                        res:status(405):json({ error = "Method not allowed by CORS policy" })
                        return
                    end

                    next()
                end
            end,
            rate_limited = function(options)
                local function table_count(t)
                    local count = 0
                    for _ in pairs(t) do count = count + 1 end
                    return count
                end

                options = options or {}
                local window_ms = options.window_ms or 60000
                local max_requests = options.max_requests or 100
                local skip = options.skip or function(req) return false end
                local key_generator = options.key_generator or
                    function(req) return req.headers["x-forwarded-for"] or req.client_data.ip:match("([^:]+):") or "unknown" end
                local message = options.message or "Too many requests"
                local status_code = options.status_code or 429

                local requests = {}
                local last_cleanup = os_time() * 1000
                local cleanup_interval = 60000
                local function cleanup(force)
                    local now = socket_gettime() * 1000 or os_time() * 1000

                    if force or now - last_cleanup > cleanup_interval then
                        for key, data in pairs(requests) do
                            if now - data.start_time > window_ms then
                                requests[key] = nil
                            end
                        end
                        last_cleanup = now
                    end
                end

                return function(req, res, next)
                    if skip(req) then
                        return next()
                    end

                    local key = key_generator(req)
                    local now = socket_gettime() * 1000 or os_time() * 1000

                    if not requests[key] or now - requests[key].start_time > window_ms then
                        requests[key] = {
                            count = 0,
                            start_time = now
                        }
                    end

                    requests[key].count = requests[key].count + 1

                    local remaining = math_max(0, max_requests - requests[key].count)
                    local reset_time = math_ceil((requests[key].start_time + window_ms) / 1000)

                    res:setHeader("X-RateLimit-Limit", tostring(max_requests))
                    res:setHeader("X-RateLimit-Remaining", tostring(remaining))
                    res:setHeader("X-RateLimit-Reset", tostring(reset_time))

                    if requests[key].count > max_requests then
                        res:setHeader("Retry-After", tostring(math_ceil((reset_time - now / 1000))))
                        res:status(status_code):json({ error = message })
                        return
                    end

                    if math_random(100) == 1 or (next(requests) and table_count(requests) > 1000 and math_random(10) == 1) then
                        cleanup(true)
                    end

                    next()
                end
            end,
            body_parser = function()
                return function(req, res, next)
                    local content_type = req.headers["content-type"] or ""

                    if req.body and req.body ~= "" then
                        if content_type == "application/json" or content_type:find("application/json") then
                            local success, parsed = pcall(json_decode, req.body)
                            if success then
                                req.body = parsed
                            end
                        elseif content_type == "application/x-www-form-urlencoded" or content_type:find("application/x-www-form-urlencoded") then
                            req.body = util_parseQueryString(req.body)
                        end
                    end

                    next()
                end
            end,
            logger = function(options)
                options = options or {}
                local format = options.format or ":method :url :status :response-time ms"
                local stream = options.stream or { write = function(msg) print(msg) end }
                local skip = options.skip or function(req) return false end

                return function(req, res, next)
                    if skip(req) then
                        return next()
                    end

                    local start_time = socket_gettime() * 1000 or os_time() * 1000

                    local original_send = res.send
                    res.send = function(self, data)
                        local result = original_send(self, data)

                        local end_time = socket_gettime() * 1000 or os_time() * 1000
                        local response_time = end_time - start_time

                        local log_message = format
                            :gsub(":method", req.method)
                            :gsub(":url", req.path)
                            :gsub(":status", tostring(self.statusCode))
                            :gsub(":response-time", string_format("%.2f", response_time))
                            :gsub(":remote-addr", req.client:getpeername() or "unknown")
                            :gsub(":user-agent", req.headers["user-agent"] or "-")
                            :gsub(":content-length", self.headers["Content-Length"] or "-")

                        stream.write(log_message)

                        return result
                    end

                    next()
                end
            end
        }
    }

    local s, e = pcall(function()
        local app = httpserv.server.create()
        app_data.server = app

        function app_data.get(self, path, handler) app.router:get(path, handler) end
        function app_data.post(self, path, handler) app.router:post(path, handler) end
        function app_data.put(self, path, handler) app.router:put(path, handler) end
        function app_data.delete(self, path, handler) app.router:delete(path, handler) end
        function app_data.patch(self, path, handler) app.router:patch(path, handler) end
        function app_data.head(self, path, handler) app.router:head(path, handler) end
        function app_data.options(self, path, handler) app.router:options(path, handler) end

        local create_group
        create_group = function(parent, prefix)
            if not type(prefix) == "string" then
                handle_error(app_data, "app.group(prefix) prefix not string", 2)
                return
            end
            local group = parent:group(prefix)
            return {
                get = function(self, path, handler) group:addRoute("GET", path, handler) end,
                post = function(self, path, handler) group:addRoute("POST", path, handler) end,
                put = function(self, path, handler) group:addRoute("PUT", path, handler) end,
                delete = function(self, path, handler) group:addRoute("DELETE", path, handler) end,
                patch = function(self, path, handler) group:addRoute("PATCH", path, handler) end,
                head = function(self, path, handler) group:addRoute("HEAD", path, handler) end,
                options = function(self, path, handler) group:addRoute("OPTIONS", path, handler) end,
                group = function(self, prefix)
                    return create_group(group, prefix)
                end
            }
        end

        app_data.group = function(self, prefix)
            return create_group(app, prefix)
        end

        app_data.listen = function(self, port, host, protocol, ssl_config)
            if not type(host) == "string" then
                handle_error(app_data, "app.listen(port, host, protocol, ssl_config) host not string", 2)
                return
            end
            if not type(port) == "number" then
                handle_error(app_data, "app.listen(port, host, protocol, ssl_config) port not number", 2)
                return
            end
            if protocol and not type(protocol) == "string" then
                handle_error(app_data, "app.listen(port, host, protocol, ssl_config) protocol not string", 2)
                return
            end
            if ssl_config and not type(ssl_config) == "table" then
                handle_error(app_data, "app.listen(port, host, protocol, ssl_config) ssl_config not table", 2)
                return
            end
            if ssl_config and (not ssl_config["key"] or not ssl_config["cert"]) then
                handle_error(app_data, "app.listen(port, host, protocol, ssl_config) ssl_config no key or cert found", 2)
                return
            end
            if protocol == "https" then
                if not app:checkSSL() then
                    handle_error(app_data, "SSL not found", 2)
                    return
                end
            end
            local s, e = pcall(app.listen, app, port, host, protocol, ssl_config)
            if not s then
                handle_error(app_data, e, 2)
                return
            end
            app_data.is_listen = true
            if app_data.debug then
                print(string_format("Server listening on " .. (protocol or "http") .. "://" .. host .. ":" .. port))
            end
        end
        app_data.stop = function(self)
            if app_data.debug then
                print("HTTP server stopped name: " .. app_data.name)
            end
            app_data.is_listen = false
            app:stop()
        end

        app_data.is_running = function(self)
            return app:isRunning()
        end
        app_data.get_client_count = function(self)
            return app:getClientCount()
        end

        app_data.set_default_timeout = function(self, timeout)
            app:setDefaultTimeout(timeout)
        end
        app_data.set_default_max_header_size = function(self, size)
            app:setDefaultMaxHeaderSize(size)
        end
        app_data.set_default_max_body_size = function(self, size)
            app:setDefaultMaxBodySize(size)
        end

        app_data.use = function(self, middlewareFn)
            if middlewareFn and not type(middlewareFn) == "table" then
                handle_error(app_data, "app.use(middlewareFn) middlewareFn not function", 2)
                return
            end
            app:use(middlewareFn)
        end

        app:on("new_client", function(ip, client_data)
            if app_data.new_client then
                app_data.new_client(ip, client_data)
            end
        end)
        app:on("close_client", function(ip, client_data, reason)
            if app_data.close_client then
                app_data.close_client(ip, client_data, reason)
            end
        end)
        app:on("timeout", function(ip, client_data, inactive_time)
            if app_data.timeout_client then
                app_data.timeout_client(ip, client_data, inactive_time)
            end
        end)
        app:on("error", function(ip, client_data, error_msg)
            if app_data.error_client then
                app_data.error_client(ip, client_data, error_msg)
            end
        end)

        if app_data.debug then
            app:use(function(req, res, next)
                print(string_format("[%s] %s %s", os_date("%H:%M:%S"), req.method, req.path))
                next()
            end)
        end
    end)

    if not s then
        handle_error(app_data, e, 2)
        return
    end

    if apps[app_data.name] then
        handle_error(app_data, "An application with that name already exists.", 2)
        return
    end
    apps[app_data.name] = app_data

    return app_data
end

http_app.update = function()
    for name, app_data in pairs(apps) do
        if app_data.is_listen then
            local s, e = pcall(app_data.server.update, app_data.server)
            if not s then
                handle_error(app_data, e, 2)
            end
        end
    end
end

http_app.remove = function(app_data_or_name)
    if type(app_data_or_name) == "string" then
        app_data_or_name = apps[app_data_or_name]
        if not app_data_or_name then
            return false, "Http-App not found"
        end
    end

    local name = app_data_or_name["name"]
    apps[name] = nil

    if app_data_or_name.debug then
        print("Http-App '" .. app_data_or_name.name .. "' close.")
    end
    app_data_or_name.server:stop()
end

http_app.close = function()
    for name, app_data in pairs(apps) do
        http_app.remove(app_data)
    end
end

return http_app
