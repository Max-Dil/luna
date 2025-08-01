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
    })

    local main_router = app:new_router({
        prefix = "api",
    })

    main_router:new({
        validate = {text = {"string","nil"}},
        responce_validate = {"string"},
        prefix = "echo", fun = function(args, client)
            return args.text or "no text provided"
        end
    })

    lunac = require("lunac")
    _G.client = lunac.connect_to_app({
        host = "127.0.0.1",
        port = 8081,
        name = "test server",
        no_errors = true,
        server = luna,
        listener = function (message)
            print("New message client:send     ", message)
        end
    })

    client:noawait_fetch("api/echo", {text = "hello world"})
    local response = client:fetch("api/echo", {text = "hello world"})
    print("Echo data: "..response)
end

function love.update(dt)
    luna.update(dt)
    lunac.update(dt)
end