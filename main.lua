-------- Base server example ------------
--[[
local luna, lunac
function love.load()
    luna = require("luna.init")

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

    lunac = require("lunac.init")
    _G.client = lunac.connect_to_app({
        host = "127.0.0.1",
        port = 8081,
        name = "test server",

        server = luna,
        reconnect_time = 5,
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
--     luna = require("luna.init")

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

--         -- encryption = false,
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

--     lunac = require("lunac.init")
--     _G.client = lunac.connect_to_app({
--         host = "127.0.0.1",
--         port = 8081,
--         name = "test server",
--         no_errors = true,
--         server = luna,
--         reconnect_time = 5,
--         listener = function(message)
--             print("New message client:send     ", message)
--         end,

--         -- encryption = false,
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

--     -- local start = os.clock()
--     -- local response = client:fetch("api/echo", {text = string.rep("hello world",99900)}, 100)
--     -- print("size: "..#response, " size wait: "..#string.rep("hello world",99900))

--     -- print("Time", os.clock() - start)

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
--     lunac.close()
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

local luna = require("luna.init")
local app = luna.new_http_app({
    name = "test http app",
    debug = true,

    no_errors = true,

    new_client = function(ip, client_data)
        print("New client: " .. ip)
    end,
    close_client = function(ip, client_data, reason)
        print("Close client: " .. ip .. "reason: " .. reason)
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
        host = "localhost",
        port = 12345,

        debug = true,
        no_errors = true,

        protocols = {
            default = function(ws)
                local ip, port = ws:getpeername()
                print("New client ip: " .. ip .. " port: " .. port)
                ws.on_close = function()
                    print("ws " .. tostring(ws) .. " on_close.")
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

local lunac = require("lunac.init")
lunac.http.init({
    luna = luna,
})

lunac.http.noawait_fetch("http://localhost:8080/api/time", {}, function(result, code, headers, status)
    print("HTTP Code:", code)
    print("Headers:", headers)
    print("Status:", status)
    print("Data:", result)

    if result then
        print("Request completed successfully")
    else
        print("Error:", code)
    end
end)

local sync_data, sync_code, sync_headers, sync_status = lunac.http.fetch("http://localhost:8080/api/time")

if sync_data then
    print("-------------------")
    print("Success:", true)
    print("HTTP Code:", sync_code)
    print("Status:", sync_status)
    print("Data:", sync_data)
    print("-------------------")
else
    print("Error sync:", sync_code)
end

local client = lunac.connect_to_web_app({
    name = "web socket client test",
    url = "ws://localhost:12345",

    on_connect = function (self)
        print("Connect to ws://localhost:12345")
    end,

    on_message = function (self, data, opcode)
        print(data, opcode)
    end,

    on_close = function (self, code, reason)
        print("Web socket close: "..code)
    end
})

local t = 0

local last_werserv_update = 0
function love.update(dt)
    t = t + dt
    if t > 2 then
        client:send("reset")
        t = 0
    end

    last_werserv_update = last_werserv_update + dt
    if last_werserv_update >= 0.1 then
        last_werserv_update = 0
        for ws, number in pairs(inc_clients) do
            ws:send(tostring(number))
            inc_clients[ws] = number + 1
        end
    end

    luna.update(dt)
    lunac.update(dt)
end

function love.quit()
    luna.close()
    lunac.close()
end
-------------------
-- end ------------
-------------------


-- _G.love = love
-- local lunac = require("lunac.init")
-- lunac.http.init({ lunac = lunac })

-- local sync_data, sync_code, sync_headers, sync_status = lunac.http.fetch("https://www.google.com")

-- if sync_data then
--     print("HTTPS -------------------")
--     print("Sync Google:")
--     print("Success:", true)
--     print("HTTP Code:", sync_code)
--     print("Status:", sync_status)
--     print("Data size:", #sync_data)
--     print("-------------------")
-- else
--     print("Error google:", sync_code)
-- end

-- lunac.http.noawait_fetch("http://www.google.com", {}, function(result, code, headers, status)
--     print("HTTP -----------")
--     print("HTTP Code:", code)
--     print("Headers:", headers)
--     print("Status:", status)
--     print("Data: size", #result)
-- end)

-- function love.update(dt)
--     lunac.update(dt)
-- end

-- function love.quit()
--     lunac.close()
-- end


-- local security = require("luna.libs.security")

-- local start_time = os.clock()
-- local private, public = security.x25519.generate_keypair()
-- local cprivate, cpublic = security.x25519.generate_keypair()
-- local key = security.utils.key_to_string(security.x25519.get_shared_key(private, cpublic))
-- local ckey = security.utils.key_to_string(security.x25519.get_shared_key(cprivate, public))
-- local keygen_time = os.clock() - start_time

-- print("Key generation time: " .. keygen_time .. " seconds")

-- local message = string.rep("T", 1024 * 1024)
-- local nonce = security.utils.generate_nonce()

-- start_time = os.clock()
-- local encrypted = security.chacha20.encrypt(message, key, nonce)
-- local encryption_time = os.clock() - start_time

-- print("Encryption time: " .. encryption_time .. " seconds")

-- start_time = os.clock()
-- local decrypted = security.chacha20.encrypt(encrypted, key, nonce)
-- local decryption_time = os.clock() - start_time

-- print("Decryption time: " .. decryption_time .. " seconds")
-- print("Keys match: " .. tostring(key == ckey))
-- print("Message match: " .. tostring(message == decrypted))
