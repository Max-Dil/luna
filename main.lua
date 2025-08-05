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
        -- request_listener = function (req)
        --     print(req)
        -- end
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
        fun = function(args, client)
            return args.text or "no text provided"
        end,
        middlewares = {echo_middleware},
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

    client:noawait_fetch("api/echo", {text = "hello world2"})
    local response = client:fetch("api/echo", {text = "hello world"})
    print("Echo data: "..response)
end

function love.update(dt)
    lunac.update(dt)
    luna.update()
end