local app = require("luna.core.app")

local luna = {}

luna.new_app = function (config)
    return app.new_app(config)
end

luna.remove_app = function (app_data)
    app.remove(app_data)
end

return {luna, {app_update = app.update}}