-- globals
do
    local m_string = require("lunac.core.string")
    _G["f"] = function (text, t)
        return m_string.f(text, t)
    end

    _G["split"] = function (text, sep, unp, regex)
        return m_string.split(text, sep, unp, regex)
    end
end
----------

local lunac = {}

local core = require("lunac.core")

for key, value in pairs(core[1]) do
    lunac[key] = value
end

lunac.update = function (dt)
    core[2].app_update(dt)
end

return lunac