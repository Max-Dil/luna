-------- Base server example ------------
--[[
local luna, lunac
function love.load()
    luna = require("luna")

    local app = luna.new_app({
        host = "127.0.0.1",
        port = 8081,
        name = "test server",
    })

    local default_router = app:new_router({prefix = "default"})
    default_router:new({prefix = "ping", fun = function(args, client) end})

    local main_router = app:new_router({
        prefix = "api",
    })

    main_router:new({
        prefix = "echo",
        fun = function(args, client)
            return args.text or "no text provided"
        end,
    })

    lunac = require("lunac")
    _G.client = lunac.connect_to_app({
        host = "127.0.0.1",
        port = 8081,
        name = "test server",

        server = luna,
        reconnect_time = 5
    })

    local response = client:fetch("api/echo", {text = "hello world"})
    print("Echo data: "..response)
end

local t = 0
function love.update(dt)
    lunac.update(dt)
    luna.update()

    t = t + dt
    if t > 2 then
        client:noawait_fetch("default/ping",function()end,{})
        t = 0
    end
end
]]
-----------------------------------------

-- _G.love = love

-- local luna, lunac
-- function love.load()
--     luna = require("luna")

--     local app = luna.new_app({
--         host = "127.0.0.1",
--         port = 8081,
--         name = "test server",
--         max_ip_connected = 20,
--         -- no_errors = true,
--         debug = true,
--         request_listener = function(req, client)
--             -- print("req: "..req)
--             -- print(client.send)
--         end,

--         disconnect_time = 10, -- the time after which the client will disconnect if you do not send requests is 10 by default.
--     })

--     local default_router = app:new_router({
--         prefix = "default",
--     })
--     default_router:new({
--         prefix = "ping",
--         fun = function(args, client) end,
--     })

--     local main_router = app:new_router({
--         prefix = "api",
--     })

--     local echo_middleware = function(context, is_pre)
--         if is_pre then
--             print("Middleware: Processing request for path " ..
--             context.request.path .. " with args: " .. require("luna.libs.json").encode(context.request.args))
--         else
--             if context.response.response then
--                 context.response.response = context.response.response .. " (processed by middleware)"
--             end
--         end
--     end

--     main_router:new({
--         validate = {text = {"string", "nil"}},
--         response_validate = {"string"},
--         prefix = "echo",
--         -- async = true,
--         fun = function(args, client)
--             return args.text or "no text provided"
--         end,
--         -- middlewares = {echo_middleware},
--     })

--     main_router:new({
--         prefix = "close",
--         async = true,
--         fun = function(args, client)
--             local start = os.time()
--             while os.time() - start < 2 do
--                 coroutine.yield()
--             end
--             client:close()
--             return true
--         end,
--     })

--     lunac = require("lunac")
--     _G.client = lunac.connect_to_app({
--         host = "127.0.0.1",
--         port = 8081,
--         name = "test server",
--         no_errors = true,
--         server = luna,
--         reconnect_time = 5,
--         listener = function(message)
--             print("New message client:send     ", message)
--         end
--     })

--     client:noawait_fetch("api/echo", function (data, err)
--         print("noawait_fetch response: ", data, "err:" ..tostring(err))
--     end,{text = "hello world2"})

--     local response = client:fetch("api/echo", {text = "hello world"})
--     print("Echo data: "..response)

--     -- client:noawait_fetch("api/close", function()end,{})

--     -- local send = function(app_data, message)
--     --     local security = require("luna.libs.security")
--     --     if app_data.shared_secret and app_data.nonce then
--     --         local success, err = pcall(security.chacha20.encrypt, message,
--     --             app_data.shared_secret, app_data.nonce)
--     --         if success then
--     --             err = err:match("^(.-)%z*$") or err
--     --             pcall(app_data.socket.send_message, err, app_data.host, app_data.port)
--     --         end
--     --         return success, err
--     --     else
--     --         return false, "Error not found connect args"
--     --     end
--     -- end
--     -- send(client, "api/echo text='value1' key2='value2' __id='cb9c1a5b-6910-4fb2-b457-a9c72a392d90' __time='1757352493' __noawait=True __client_token='"..client.client_token.."'")

--     -- client:noawait_fetch("api/echo", function (data, err)
--     --     print("noawait_fetch response: ", #data, " sizewait:" ..#string.rep("hello world",89900))
--     -- end,{text = string.rep("hello world",89900)})
--     -- local response = client:fetch("api/echo", {text = string.rep("hello world",99900)}, 100)
--     -- print("size: "..#response, " size wait: "..#string.rep("hello world",99900))

--     -- client:noawait_fetch("api/echo", function (data, err)
--     --     print("size: "..#data, " size wait: "..#string.rep("hello world",100))
--     -- end,{text = string.rep("hello world",100)})
-- end

-- local t = 0
-- function love.update(dt)
--     lunac.update(dt)
--     luna.update()

--     t = t + dt
--     if t > 2 then
--         client:noawait_fetch("default/ping",function()end,{})
--         t = 0
--     end
-- end

-- function love.quit()
--     luna.close()
-- end


-- _G.love = love
-- local lunac
-- function love.load()
--     lunac = require("lunac")
--     _G.client = lunac.connect_to_app({
--         host = "127.0.0.1",
--         port = 8081,
--         name = "test server",
--         no_errors = true,
--     })

--     client:noawait_fetch("api/echo", function (data, err)
--         print("noawait_fetch response: ", data, "err:" ..tostring(err))
--     end,{text = "hello world2"})

--     local response = client:fetch("api/echo", {text = "hello world"})
--     print("Echo data: "..response)
-- end

-- local t = 0
-- function love.update(dt)
--     lunac.update(dt)

--     t = t + dt
--     if t > 2 then
--         client:noawait_fetch("default/ping",function()end,{})
--         t = 0
--     end
-- end

-- local lunac
-- function love.load()
--     lunac = require("lunac")
--     _G.client = lunac.connect_to_app({
--         host = "127.0.0.1",
--         port = 1025,
--         name = "test server",

--         reconnect_time = 5
--     })

--     -- local response = client:fetch("api/echo", {text = "hello world"})
--     -- print("Echo data: "..response)
-- end

-- local t = 0
-- function love.update(dt)
--     lunac.update(dt)

--     t = t + dt
--     if t > 2 then
--         client:noawait_fetch("default/ping",function()end,{})
--         t = 0
--     end
-- end



-------------------
-- web_app_test --
-------------------
-- _G.love = love
-- local luna
-- local inc_clients = {}

-- function love.load()
--     luna = require("luna.init")

--     local app
--     app = luna.new_web_app({
--         name = "web socket test",
--         host = "*",
--         port = 12345,

--         debug = true,
--         -- no_errors = true,

--         protocols = {
--             default = function(ws)
--                 local ip, port = ws:getpeername()
--                 print("New client ip: "..ip .. " port: "..port)
--                 ws.on_close = function ()
--                     print("ws "..tostring(ws) .. " on_close.")
--                 end
--                 inc_clients[ws] = 0
--                 while true do
--                     local message, opcode = ws:receive()
--                     if not message then
--                         ws:close()
--                         inc_clients[ws] = nil
--                         return
--                     end
--                     if opcode == app.opcodes.TEXT then
--                         if message:match('reset') then
--                             inc_clients[ws] = 0
--                         end
--                         ws:send(tostring(inc_clients[ws]))
--                     end
--                 end
--             end,
--         }
--     })
-- end

-- local last_werserv_update = 0
-- function love.update(dt)
--     last_werserv_update = last_werserv_update + dt
--     if last_werserv_update >= 0.1 then
--         last_werserv_update = 0
--         for ws, number in pairs(inc_clients) do
--             ws:send(tostring(number))
--             inc_clients[ws] = number + 1
--         end
--     end

--     luna.update(dt)
-- end
-------------------
-- end ------------
-------------------



-------------------
-- http_app_test --
-------------------
_G.love = love

local luna = require("luna")
local app = luna.new_http_app({
    name = "test http app",
    debug = true,

    no_errors = true,

    new_client = function (ip, client_data)
        print("New client: "..ip)
    end,
    close_client = function (ip, client_data, reason)
        print("Close client: "..ip.. "reason: "..reason)
    end,
    error_client = function(ip, client_data, error_msg)
        print("Client error: " .. ip .. " - " .. error_msg)
    end,
})

app:get("test/json", function(req, res, cl)
    res:json({
        message = "Hello, world!"
    })
end)

local api = app:group("/api")
api:get("/time", function(req, res, cl)
    res:send("<h1>Current Time</h1><p>" .. os.date() .. "</p>")
end)

app:use(app.templates.static(arg[1]))
app:listen(8080, "localhost")

local inc_clients = {}
do -- Веб сокеты тест для index.html сайт по ссылке http://localhost:8080
    local app2
    app2 = luna.new_web_app({
        name = "web socket test",
        host = "*",
        port = 12345,

        debug = true,
        -- no_errors = true,

        protocols = {
            default = function(ws)
                local ip, port = ws:getpeername()
                print("New client ip: "..ip .. " port: "..port)
                ws.on_close = function ()
                    print("ws "..tostring(ws) .. " on_close.")
                end
                inc_clients[ws] = 0
                while true do
                    local message, opcode = ws:receive()
                    if not message then
                        ws:close()
                        inc_clients[ws] = nil
                        return
                    end
                    if opcode == app2.opcodes.TEXT then
                        if message:match('reset') then
                            inc_clients[ws] = 0
                        end
                        ws:send(tostring(inc_clients[ws]))
                    end
                end
            end,
        }
    })
end

local last_werserv_update = 0
function love.update(dt)
    last_werserv_update = last_werserv_update + dt
    if last_werserv_update >= 0.1 then
        last_werserv_update = 0
        for ws, number in pairs(inc_clients) do
            ws:send(tostring(number))
            inc_clients[ws] = number + 1
        end
    end

    luna.update(dt)
end

function love.quit()
    luna.close()
end
-------------------
-- end ------------
-------------------
