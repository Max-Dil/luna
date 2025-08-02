local app = require("lunac.core.app")

local core = {}

core.connect_to_app = function (config)
    return app.connect(config)
end

core.disconnect_to_app = function(app_reference)
    return app.close(app_reference)
end

return {core, {app_update = app.update}}