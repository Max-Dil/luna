--[[
MIT License

Copyright (c) 2025 Max-Dil

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
]]

local string_gsub, math_random, math_ceil, tostring, tonumber, string_format, table_insert, table_remove =
    string.gsub, math.random, math.ceil, tostring, tonumber, string.format, table.insert, table.remove
local function create()
    local max_message_size = nil
    local connections = {}
    local message_status = {}
    local fragment_buffer = {}

    local message_timeout = 2
    local max_retries = 10
    local max_fragment_size = 1000
    local max_packets_per_tick = 63

    local function uuid()
        local template = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
        return string_gsub(template, '[xy]', function(c)
            local v = (c == 'x') and math_random(0, 15) or math_random(8, 11)
            return string_format('%x', v)
        end)
    end

    local function send_message(message, ip, port)
        message = tostring(message)
        local message_id = uuid()
        local message_bytes = #message
        local total_fragments = math_ceil(message_bytes / max_fragment_size)

        if message_status[message_id] then return end

        local status = {
            ip = ip,
            port = port,
            fragments = {},
            fragments_to_send = {},
            total_fragments = total_fragments,
            acknowledged_count = 0,
            time_since_sent = 0,
            retries = 0
        }

        for i = 1, total_fragments do
            local start = (i - 1) * max_fragment_size + 1
            local fragment_data = message:sub(start, start + max_fragment_size - 1)
            local packet = string_format("MSG:%s:%d:%d:%s", message_id, i, total_fragments, fragment_data)

            local fragment_info = {
                packet = packet,
                acknowledged = false,
                fragment_num = i
            }

            status.fragments[i] = fragment_info
            table_insert(status.fragments_to_send, fragment_info)
        end

        message_status[message_id] = status
        return message_id
    end

    local function receive_message(socket)
        local completed_messages = {}
        while true do
            local data, ip, port = socket:receivefrom()
            if not data then break end

            if data:match("^ACK:") then
                local message_id, fragment_num_str = data:match("^ACK:(.-):(%d+)")
                local fragment_num = tonumber(fragment_num_str)

                local status = message_status[message_id]
                if status and status.fragments[fragment_num] and not status.fragments[fragment_num].acknowledged then
                    status.fragments[fragment_num].acknowledged = true
                    status.acknowledged_count = status.acknowledged_count + 1

                    if status.acknowledged_count == status.total_fragments then
                        message_status[message_id] = nil
                    end
                end

            elseif data:match("^MSG:") then
                local message_id, frag_num, total_frags, fragment = data:match("^MSG:(.-):(%d+):(%d+):(.*)")
                frag_num = tonumber(frag_num)
                total_frags = tonumber(total_frags)

                if message_id and frag_num and total_frags and fragment then
                    socket:sendto(string_format("ACK:%s:%d", message_id, frag_num), ip, port)

                    local client_key = ip .. ":" .. port
                    fragment_buffer[client_key] = fragment_buffer[client_key] or {}

                    local msg_buffer = fragment_buffer[client_key][message_id]
                    if not msg_buffer then
                        msg_buffer = { fragments = {}, received_count = 0, total_fragments = total_frags, total_size = 0 }
                        fragment_buffer[client_key][message_id] = msg_buffer
                    end

                    if not msg_buffer.fragments[frag_num] then
                        local new_size = msg_buffer.total_size + #fragment
                        if max_message_size and new_size > max_message_size then
                            print("Message " .. message_id .. " from " .. client_key .. " exceeds max_message_size of " .. max_message_size .. " bytes. Discarding.")
                            fragment_buffer[client_key][message_id] = nil
                            return completed_messages
                        end

                        msg_buffer.fragments[frag_num] = fragment
                        msg_buffer.received_count = msg_buffer.received_count + 1
                        msg_buffer.total_size = new_size

                        if msg_buffer.received_count == msg_buffer.total_fragments then
                            local parts = {}
                            for i = 1, msg_buffer.total_fragments do
                                table_insert(parts, msg_buffer.fragments[i] or "")
                            end
                            local complete_message = table.concat(parts)
                            table_insert(completed_messages, { message = complete_message, ip = ip, port = port })
                            fragment_buffer[client_key][message_id] = nil
                        end
                    end
                end
            end
        end
        return completed_messages
    end

    local function update(socket, dt)
        local packets_sent_this_tick = 0
        for id, status in pairs(message_status) do
            while #status.fragments_to_send > 0 do
                if packets_sent_this_tick >= max_packets_per_tick then
                    break
                end

                local fragment_info = status.fragments_to_send[1]

                local bytes_sent, err = socket:sendto(fragment_info.packet, status.ip, status.port)

                if bytes_sent then
                    table_remove(status.fragments_to_send, 1)
                    packets_sent_this_tick = packets_sent_this_tick + 1
                    status.time_since_sent = 0
                else
                    break
                end
            end
            if packets_sent_this_tick >= max_packets_per_tick then
                break
            end
        end

        for id, status in pairs(message_status) do
            status.time_since_sent = status.time_since_sent + dt

            if status.time_since_sent > message_timeout then
                if status.retries < max_retries then
                    status.retries = status.retries + 1
                    status.time_since_sent = 0

                    for i = 1, status.total_fragments do
                        local frag_info = status.fragments[i]
                        if not frag_info.acknowledged then
                            local already_in_queue = false
                            for _, f in pairs(status.fragments_to_send) do
                                if f.fragment_num == i then
                                    already_in_queue = true
                                    break
                                end
                            end
                            if not already_in_queue then
                                table_insert(status.fragments_to_send, frag_info)
                            end
                        end
                    end
                else
                    print("Failed to deliver message " .. id .. " after " .. max_retries .. " retries.")
                    message_status[id] = nil
                end
            end
        end
    end

    local new_connect = function(socket, myip, myport)
        local client_key = myip .. ":" .. myport
        if connections[client_key] then
            connections[client_key]:close()
        end

        local connect = {
            socket = socket,
            ip = myip,
            port = myport,
            is_close = false,
        }
        connections[client_key] = connect

        function connect:send(message)
            return send_message(message, self.ip, self.port)
        end

        function connect:getpeername()
            return self.ip, self.port
        end

        function connect:close()
            pcall(function () self.socket:close() end)
            if connections[client_key] then
                fragment_buffer[client_key] = nil
                connections[client_key] = nil
            end
            connect.is_close = true
        end

        return connect
    end

    local function set_max_messages_size(new_max_messages_size)
        max_message_size = new_max_messages_size
    end

    local function set_max_retries(new_max_retries)
        max_retries = new_max_retries
    end

    local function set_message_timeout(new_message_timeout)
        message_timeout = new_message_timeout
    end

    return {
        new_connect = new_connect,
        send_message = send_message,
        receive_message = receive_message,
        connections = connections,
        update = update,
        set_max_messages_size = set_max_messages_size,
        set_max_retries = set_max_retries,
        set_message_timeout = set_message_timeout,
    }
end

return create