local req = require("luna.core.requests")

local router = {}

router.new_router = function(app, config)
    if app.routers[config.prefix] then
        router.remove_router(app, config.prefix)
    end
    local router_data
    router_data = setmetatable({
        prefix = config.prefix,
        no_errors = config.no_errors,
        error_handler = config.error_handler or function(message) 
            print("Error in router prefix: "..router_data.prefix.." error: "..message) 
        end,
        requests = {},
        app = app,
    }, {__index = req})

    app.routers[router_data.prefix] = router_data
    return router_data
end

router.remove_router = function(app, router_data)
    if type(router_data) == "string" then
        router_data = app.routers[router_data]
    end

    app.routers[router_data.prefix] = nil
end

return router