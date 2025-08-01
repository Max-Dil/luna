local app = require("lunac.core.app")

local core = {}

core.connect_to_app = function (config)
    return app.connect(config)
end

return {core, {app_update = app.update}}