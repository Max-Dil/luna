local lunac = {}

local core = require("lunac.core.init")

for key, value in pairs(core[1]) do
    lunac[key] = value
end

lunac.update = function (dt)
    core[2].app_update(dt)
end

return lunac