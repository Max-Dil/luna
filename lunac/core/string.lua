local M_string = {}

function M_string:split(sep, unp, regex)
	sep = sep or ","
	local out = {}
	local a, b, c, i, _ = 1, #self, nil, 1
	c, b = self:find(sep, 1, not regex)

	while a and b do
		out[i] = self:sub(a, c - 1)
		a, i = b + 1, i + 1
		c, b = self:find(sep, a, not regex)
	end

	out[i] = self:sub(a)

	if unp then
		return unpack(out) or out
	end
	return out
end

local function eval_code(code, env)
    local fn = load("return "..code, "=(interpolation)", "t", env)
    if not fn then
        fn = load(code, "=(interpolation)", "t", env)
    end

    if fn then
        local ok, result = pcall(fn)
        if ok then return result else error(result, 4) end
    end

    return "{"..code.."}"
end

function M_string:f(env)
    return (self:gsub("{(.-)}", function(code)
        return eval_code(code, env or {})
    end))
end

return M_string