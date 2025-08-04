local m = {}
local running_funs = {}

local json = require("luna.libs.json")
local function request_coro()
    while true do
        local request_handler, request, client_data = coroutine.yield()

        local coro = coroutine.create(request_handler.fun)
        running_funs[coro] = {request_handler, request, client_data}
        m.freeWorker(coroutine.running())
    end
end

local cache = setmetatable({}, {__mode = "k"})
local workers = {}
function m.getFreeWorker()
    local coro = next(cache)
    if not coro then coro = coroutine.create(request_coro) coroutine.resume(coro) end
    cache[coro] = nil
    workers[coro] = true
    return coro
end

function m.freeWorker(coro)
    workers[coro] = nil
    cache[coro] = true
end

m.workers = workers
m.running_funs = running_funs

return m