-- globals
do
    local m_string = require("luna.core.string")
    _G["f"] = function (text, t)
        return m_string.f(text, t)
    end

    _G["split"] = function (text, sep, unp, regex)
        return m_string.split(text, sep, unp, regex)
    end
end
----------

local core = require("luna.core")

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