_G.love = love

local luna, lunac
function love.load()
    luna = require("luna")

    local app = luna.new_app({
        host = "127.0.0.1",
        port = 8081,
        name = "test server",
        max_ip_connected = 20,
        no_errors = true,
        debug = true,
        request_listener = function (req, client)
            -- print("req: "..req)
            -- print(client.send)
        end,
    })
    local main_router = app:new_router({
        prefix = "api",
    })

    local echo_middleware = function(context, is_pre)
        if is_pre then
            print("Middleware: Processing request for path "..context.request.path.." with args: "..require("luna.libs.json").encode(context.request.args))
        else
            if context.response.response then
                context.response.response = context.response.response .. " (processed by middleware)"
            end
        end
    end

    main_router:new({
        validate = {text = {"string", "nil"}},
        responce_validate = {"string"},
        prefix = "echo",
        -- async = true,
        fun = function(args, client)
            return args.text or "no text provided"
        end,
        -- middlewares = {echo_middleware},
    })

    main_router:new({
        prefix = "close",
        async = true,
        fun = function(args, client)
            local start = os.time()
            while os.time() - start < 2 do
                coroutine.yield()
            end
            client:close()
            return true
        end,
    })

    lunac = require("lunac")
    _G.client = lunac.connect_to_app({
        host = "127.0.0.1",
        port = 8081,
        name = "test server",
        no_errors = true,
        server = luna,
        reconnect_time = 5,
        listener = function (message)
            print("New message client:send     ", message)
        end
    })

    client:noawait_fetch("api/echo", function (data, err)
        print("noawait_fetch response: ", data, "err:" ..tostring(err))
    end,{text = "hello world2"})
    local response = client:fetch("api/echo", {text = "hello world"})
    print("Echo data: "..response)

    -- client:noawait_fetch("api/close", function (data, err)
    --     print("noawait_fetch response: ", data, "err:" ..tostring(err))
    -- end,{text = "hello world2"})





    -- local send = function(app_data, data)
    --     pcall(app_data.socket.send_message, data, app_data.host, app_data.port)
    -- end
    -- send(client, "api/echo text='value1' key2='value2' __id='cb9c1a5b-6910-4fb2-b457-a9c72a392d90' __time='1757352493' __noawait=True " .. string.rep("a='attack' ", 1000))

    -- local response = client:fetch("api/echo", {text = string.rep("hello world",999000)}, 100)
    -- print("size: "..#response, " size wait: "..#string.rep("hello world",999000))

    -- client:noawait_fetch("api/echo", function (data, err)
    --     print("size: "..#data, " size wait: "..#string.rep("hello world",100))
    -- end,{text = string.rep("hello world",100)})
end

function love.update(dt)
    lunac.update(dt)
    luna.update()
end