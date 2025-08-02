local core = require("luna.core.init")

local luna = {}

for key, value in pairs(core[1]) do
    luna[key] = value
end

luna.update = function (dt)
    core[2].app_update(dt)
end

return luna

--[[
luna.new_app(config)
luna.new_router(config)
]]