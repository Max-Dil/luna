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
SOFTWARE.]]

local security = {}

do
    --[[
MIT License

Copyright (c) 2023 BernhardZat

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
SOFTWARE.]]

    do
        local matrix = {};
        matrix.__index = matrix;

        local new = function(n, m, init, zero, one)
            local attrs = {
                n = n,
                m = m or n,
                init = init or 0,
                zero = zero or 0,
                one = one or 1,
                data = {},
            };
            return setmetatable(attrs, matrix);
        end

        local identity = function(size, zero, one)
            zero = zero or 0;
            one = one or 1;
            local id = new(size, size, zero, zero, one);
            for i = 0, size - 1 do
                id:set(i, i, one);
            end
            return id;
        end

        matrix.set = function(self, i, j, v)
            self.data[i * self.m + j] = v;
        end

        matrix.get = function(self, i, j)
            return self.data[i * self.m + j] or self.init;
        end

        matrix.set_sub = function(self, sub, i, j)
            for k = 0, sub.n - 1 do
                for l = 0, sub.m - 1 do
                    self:set(i + k, j + l, sub:get(k, l));
                end
            end
        end

        matrix.get_sub = function(self, i, j, n, m)
            local sub = new(n, m);
            for k = 0, n - 1 do
                for l = 0, m - 1 do
                    sub:set(k, l, self:get(i + k, j + l));
                end
            end
            return sub;
        end

        matrix.set_row = function(self, row, i)
            self:set_sub(row, i, 0);
        end

        matrix.get_row = function(self, i)
            return self:get_sub(i, 0, 1, self.m);
        end

        matrix.set_col = function(self, column, j)
            self:set_sub(column, 0, j);
        end

        matrix.get_col = function(self, j)
            return self:get_sub(0, j, self.n, 1);
        end

        matrix.__add = function(a, b)
            local c = new(a.n, a.m);
            for i = 0, a.n - 1 do
                for j = 0, a.m - 1 do
                    c:set(i, j, a:get(i, j) + b:get(i, j));
                end
            end
            return c;
        end

        matrix.__sub = function(a, b)
            local c = new(a.n, a.m);
            for i = 0, a.n - 1 do
                for j = 0, a.m - 1 do
                    c:set(i, j, a:get(i, j) - b:get(i, j));
                end
            end
            return c;
        end

        matrix.__mul = function(a, b)
            local c = new(a.n, b.m);
            for i = 0, a.n - 1 do
                for j = 0, b.m - 1 do
                    local sum = 0;
                    for k = 0, a.m - 1 do
                        sum = sum + a:get(i, k) * b:get(k, j);
                    end
                    c:set(i, j, sum);
                end
            end
            return c;
        end

        matrix.__tostring = function(self)
            local s = "";
            for i = 0, self.n - 1 do
                for j = 0, self.m - 1 do
                    s = s .. tostring(self:get(i, j)) .. " ";
                end
                s = s .. "\n";
            end
            return s;
        end

        security.matrix = {
            new = new,
            identity = identity,
            set = matrix.set,
            get = matrix.get,
            set_sub = matrix.set_sub,
            get_sub = matrix.get_sub,
            set_row = matrix.set_row,
            get_row = matrix.get_row,
            set_col = matrix.set_col,
            get_col = matrix.get_col,
        };
    end

    do
        local Matrix = security.matrix
        local M = Matrix.new;

        local u8_and_table = M(256);
        for i = 0, 7 do
            local m1 = u8_and_table:get_sub(0, 0, 2 ^ i, 2 ^ i);
            local m2 = M(2 ^ i, 2 ^ i, 2 ^ i);
            u8_and_table:set_sub(m1, 2 ^ i, 0);
            u8_and_table:set_sub(m1, 0, 2 ^ i);
            u8_and_table:set_sub(m1 + m2, 2 ^ i, 2 ^ i);
        end

        local u8_lsh = function(a, n)
            return a * 2 ^ n % 0x100;
        end

        local u8_rsh = function(a, n)
            return a / 2 ^ n - (a / 2 ^ n) % 1;
        end

        local u8_lrot = function(a, n)
            n = n % 8;
            return u8_lsh(a, n) + u8_rsh(a, 8 - n);
        end

        local u8_rrot = function(a, n)
            n = n % 8;
            return u8_rsh(a, n) + u8_lsh(a, 8 - n);
        end

        local u8_not = function(a)
            return 0xFF - a;
        end

        local u8_and = function(a, b)
            return u8_and_table:get(a, b);
        end

        local u8_xor = function(a, b)
            return u8_not(u8_and(a, b)) - u8_and(u8_not(a), u8_not(b));
        end

        local u8_or = function(a, b)
            return u8_and(a, b) + u8_xor(a, b);
        end

        local u16_lsh = function(a, n)
            return a * 2 ^ n % 0x10000;
        end

        local u16_rsh = function(a, n)
            return a / 2 ^ n - (a / 2 ^ n) % 1;
        end

        local u16_lrot = function(a, n)
            n = n % 16;
            return u16_lsh(a, n) + u16_rsh(a, 16 - n);
        end

        local u16_rrot = function(a, n)
            n = n % 16;
            return u16_rsh(a, n) + u16_lsh(a, 16 - n);
        end

        local u16_not = function(a)
            return 0xFFFF - a;
        end

        local u16_and = function(a, b)
            local a1, a2 = u16_rsh(a, 8), a % 0x100;
            local b1, b2 = u16_rsh(b, 8), b % 0x100;
            local r1, r2 = u8_and(a1, b1), u8_and(a2, b2);
            return u16_lsh(r1, 8) + r2;
        end

        local u16_xor = function(a, b)
            local a1, a2 = u16_rsh(a, 8), a % 0x100;
            local b1, b2 = u16_rsh(b, 8), b % 0x100;
            local r1, r2 = u8_xor(a1, b1), u8_xor(a2, b2);
            return u16_lsh(r1, 8) + r2;
        end

        local u16_or = function(a, b)
            local a1, a2 = u16_rsh(a, 8), a % 0x100;
            local b1, b2 = u16_rsh(b, 8), b % 0x100;
            local r1, r2 = u8_or(a1, b1), u8_or(a2, b2);
            return u16_lsh(r1, 8) + r2;
        end

        local u32_lsh = function(a, n)
            return a * 2 ^ n % 0x100000000;
        end

        local u32_rsh = function(a, n)
            return a / 2 ^ n - (a / 2 ^ n) % 1;
        end

        local u32_lrot = function(a, n)
            n = n % 32;
            return u32_lsh(a, n) + u32_rsh(a, 32 - n);
        end

        local u32_rrot = function(a, n)
            n = n % 32;
            return u32_rsh(a, n) + u32_lsh(a, 32 - n);
        end

        local u32_not = function(a)
            return 0xFFFFFFFF - a;
        end

        local u32_and = function(a, b)
            local a1, a2 = u32_rsh(a, 16), a % 0x10000;
            local b1, b2 = u32_rsh(b, 16), b % 0x10000;
            local r1, r2 = u16_and(a1, b1), u16_and(a2, b2);
            return u32_lsh(r1, 16) + r2;
        end

        local u32_xor = function(a, b)
            local a1, a2 = u32_rsh(a, 16), a % 0x10000;
            local b1, b2 = u32_rsh(b, 16), b % 0x10000;
            local r1, r2 = u16_xor(a1, b1), u16_xor(a2, b2);
            return u32_lsh(r1, 16) + r2;
        end

        local u32_or = function(a, b)
            local a1, a2 = u32_rsh(a, 16), a % 0x10000;
            local b1, b2 = u32_rsh(b, 16), b % 0x10000;
            local r1, r2 = u16_or(a1, b1), u16_or(a2, b2);
            return u32_lsh(r1, 16) + r2;
        end

        security.bitops = {
            u8_lsh = u8_lsh,
            u8_rsh = u8_rsh,
            u8_lrot = u8_lrot,
            u8_rrot = u8_rrot,
            u8_not = u8_not,
            u8_and = u8_and,
            u8_xor = u8_xor,
            u8_or = u8_or,
            u16_lsh = u16_lsh,
            u16_rsh = u16_rsh,
            u16_lrot = u16_lrot,
            u16_rrot = u16_rrot,
            u16_not = u16_not,
            u16_and = u16_and,
            u16_xor = u16_xor,
            u16_or = u16_or,
            u32_lsh = u32_lsh,
            u32_rsh = u32_rsh,
            u32_lrot = u32_lrot,
            u32_rrot = u32_rrot,
            u32_not = u32_not,
            u32_and = u32_and,
            u32_xor = u32_xor,
            u32_or = u32_or,
        };
    end

    do
        local number_to_bytestring = function(num, n)
            n = n or math.floor(math.log(num) / math.log(0x100) + 1);
            n = n > 0 and n or 1;
            local string_char = string.char;
            local t = {};
            for i = 1, n do
                t[n - i + 1] = string_char((num % 0x100 ^ i - num % 0x100 ^ (i - 1)) / 0x100 ^ (i - 1));
            end
            local s = table.concat(t);
            s = ("\0"):rep(n - #s) .. s;
            return s, n;
        end

        local function bytestring_to_number(s)
            local num = 0;
            local len = s:len();
            for i = 0, len - 1 do
                num = num + s:byte(len - i) * 0x100 ^ i;
            end
            return num;
        end

        local bytetable_to_bytestring = function(t)
            local s = t[0] and string.char(t[0]) or "";
            for i = 1, #t do
                s = s .. string.char(t[i]);
            end
            return s;
        end

        local bytestring_to_bytetable = function(s, zero_based)
            local t = {};
            local j = zero_based and 1 or 0;
            for i = 1, s:len() do
                t[i - j] = s:byte(i);
            end
            return t;
        end

        local bytetable_to_number = function(t)
            local num = 0;
            for i = 0, #t - (t[0] and 0 or 1) do
                num = num + t[#t - i] * 0x100 ^ i;
            end
            return num;
        end

        security.util = {
            number_to_bytestring = number_to_bytestring,
            bytestring_to_number = bytestring_to_number,
            bytetable_to_bytestring = bytetable_to_bytestring,
            bytestring_to_bytetable = bytestring_to_bytetable,
            bytetable_to_number = bytetable_to_number,
        }
    end

    do
        local Bitops = security.bitops
        local Util = security.util

        local XOR, LROT = Bitops.u32_xor, Bitops.u32_lrot;
        local num_to_bytes, num_from_bytes = Util.number_to_bytestring, Util.bytestring_to_number;

        local MOD = 0x100000000
        local MASK = 0xFFFFFFFF

        local is_luajit = type(jit) == 'table'
        if is_luajit then
            local bit = require('bit')
            XOR = bit.bxor
            LROT = bit.rol
        else
            XOR = Bitops.u32_xor
            LROT = Bitops.u32_lrot
        end

        local function unpack(s, len)
            local array = {};
            local count = 0;
            local char = string.char;
            len = len or s:len();

            for i = 1, len, 4 do
                local chunk = s:sub(i, i + 3);
                if #chunk < 4 then
                    chunk = chunk .. char(0):rep(4 - #chunk);
                end
                count = count + 1;
                array[count] = num_from_bytes(chunk);
            end
            return array;
        end

        local function pack(a, len)
            local t = {};
            local array_len = #a;
            local remaining = len or (array_len * 4);
            local min = math.min;
            for i = 1, array_len do
                local bytes = num_to_bytes(a[i], 4);
                local take = min(4, remaining - (i - 1) * 4);
                t[i] = bytes:sub(1, take);
            end
            return table.concat(t);
        end

        local function quarter_round(s, a, b, c, d)
            s[a] = (s[a] + s[b]) % MOD; s[d] = LROT(XOR(s[d], s[a]), 16);
            s[c] = (s[c] + s[d]) % MOD; s[b] = LROT(XOR(s[b], s[c]), 12);
            s[a] = (s[a] + s[b]) % MOD; s[d] = LROT(XOR(s[d], s[a]), 8);
            s[c] = (s[c] + s[d]) % MOD; s[b] = LROT(XOR(s[b], s[c]), 7);
        end

        local CONSTANTS = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}
        local block = function(key, nonce, counter)
            local init = {
                CONSTANTS[1], CONSTANTS[2], CONSTANTS[3], CONSTANTS[4],
                key[1], key[2], key[3], key[4],
                key[5], key[6], key[7], key[8],
                counter, nonce[1], nonce[2], nonce[3],
            }
            local state = {};
            for i = 1, 16 do
                state[i] = init[i];
            end
            for _ = 1, 10 do
                quarter_round(state, 1, 5, 9, 13);
                quarter_round(state, 2, 6, 10, 14);
                quarter_round(state, 3, 7, 11, 15);
                quarter_round(state, 4, 8, 12, 16);
                quarter_round(state, 1, 6, 11, 16);
                quarter_round(state, 2, 7, 12, 13);
                quarter_round(state, 3, 8, 9, 14);
                quarter_round(state, 4, 5, 10, 15);
            end
            for i = 1, 16 do
                state[i] = (state[i] + init[i]) % 0x100000000;
            end
            return state;
        end

        local encrypt = function(plain, key, nonce)
            local unpack, pack, floor, ceil = unpack, pack, math.floor, math.ceil;

            key = unpack(key);
            nonce = unpack(nonce);
            local counter = 0;
            local cipher = {};
            local cipher_count = 0;

            local plain_len = plain:len()

            local chunks = floor(plain_len / 64)
            while counter < chunks do
                local key_stream = block(key, nonce, counter);
                local plain_block = unpack(plain:sub(counter * 64 + 1, (counter + 1) * 64));

                local cipher_block = {};
                for j = 1, 16 do
                    cipher_block[j] = XOR(plain_block[j], key_stream[j]);
                end

                cipher_count = cipher_count + 1
                cipher[cipher_count] = pack(cipher_block);

                counter = counter + 1;
            end
            if plain_len % 64 ~= 0 then
                local key_stream = block(key, nonce, counter);
                local plain_block = unpack(plain:sub(counter * 64 + 1));
                local cipher_block = {};

                chunks = ceil((plain_len % 64) / 4)
                for j = 1, chunks do
                    cipher_block[j] = XOR(plain_block[j], key_stream[j]);
                end

                cipher_count = cipher_count + 1
                cipher[cipher_count] = pack(cipher_block);
            end
            return table.concat(cipher);
        end

        local decrypt = function(cipher, key, nonce)
            return encrypt(cipher, key, nonce);
        end

        security.chacha20 = {
            encrypt = encrypt,
            decrypt = decrypt,
        }
    end

    do
        local enc = {
            [0] =
            "A",
            "B",
            "C",
            "D",
            "E",
            "F",
            "G",
            "H",
            "I",
            "J",
            "K",
            "L",
            "M",
            "N",
            "O",
            "P",
            "Q",
            "R",
            "S",
            "T",
            "U",
            "V",
            "W",
            "X",
            "Y",
            "Z",
            "a",
            "b",
            "c",
            "d",
            "e",
            "f",
            "g",
            "h",
            "i",
            "j",
            "k",
            "l",
            "m",
            "n",
            "o",
            "p",
            "q",
            "r",
            "s",
            "t",
            "u",
            "v",
            "w",
            "x",
            "y",
            "z",
            "0",
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
            "8",
            "9",
            "+",
            "/"
        };

        local dec = {
            ["A"] = 0,
            ["B"] = 1,
            ["C"] = 2,
            ["D"] = 3,
            ["E"] = 4,
            ["F"] = 5,
            ["G"] = 6,
            ["H"] = 7,
            ["I"] = 8,
            ["J"] = 9,
            ["K"] = 10,
            ["L"] = 11,
            ["M"] = 12,
            ["N"] = 13,
            ["O"] = 14,
            ["P"] = 15,
            ["Q"] = 16,
            ["R"] = 17,
            ["S"] = 18,
            ["T"] = 19,
            ["U"] = 20,
            ["V"] = 21,
            ["W"] = 22,
            ["X"] = 23,
            ["Y"] = 24,
            ["Z"] = 25,
            ["a"] = 26,
            ["b"] = 27,
            ["c"] = 28,
            ["d"] = 29,
            ["e"] = 30,
            ["f"] = 31,
            ["g"] = 32,
            ["h"] = 33,
            ["i"] = 34,
            ["j"] = 35,
            ["k"] = 36,
            ["l"] = 37,
            ["m"] = 38,
            ["n"] = 39,
            ["o"] = 40,
            ["p"] = 41,
            ["q"] = 42,
            ["r"] = 43,
            ["s"] = 44,
            ["t"] = 45,
            ["u"] = 46,
            ["v"] = 47,
            ["w"] = 48,
            ["x"] = 49,
            ["y"] = 50,
            ["z"] = 51,
            ["0"] = 52,
            ["1"] = 53,
            ["2"] = 54,
            ["3"] = 55,
            ["4"] = 56,
            ["5"] = 57,
            ["6"] = 58,
            ["7"] = 59,
            ["8"] = 60,
            ["9"] = 61,
            ["+"] = 62,
            ["/"] = 63
        }

        local encode = function(s)
            local r = s:len() % 3;
            s = r == 0 and s or s .. ("\0"):rep(3 - r);
            local b64 = "";
            for i = 1, s:len(), 3 do
                local b1, b2, b3 = s:byte(i, i + 2);
                b64 = b64 .. enc[math.floor(b1 / 0x04)];
                b64 = b64 .. enc[math.floor(b2 / 0x10) + (b1 % 0x04) * 0x10];
                b64 = b64 .. enc[math.floor(b3 / 0x40) + (b2 % 0x10) * 0x04];
                b64 = b64 .. enc[b3 % 0x40];
            end
            b64 = b64 .. (r == 0 and "" or ("="):rep(3 - r));
            return b64;
        end

        local decode = function(b64)
            local b, p = b64:gsub("=", "");
            local s = "";
            for i = 1, b:len(), 4 do
                local b1 = dec[b:sub(i, i)];
                local b2 = dec[b:sub(i + 1, i + 1)];
                local b3 = dec[b:sub(i + 2, i + 2)];
                local b4 = dec[b:sub(i + 3, i + 3)];
                s = s .. string.char(
                    b1 * 0x04 + math.floor(b2 / 0x10),
                    (b2 % 0x10) * 0x10 + math.floor(b3 / 0x04),
                    (b3 % 0x04) * 0x40 + b4
                );
            end
            s = s:sub(1, -(p + 1));
            return s;
        end

        security.base64 = {
            encode = encode,
            decode = decode,
        }
    end

    do
        --------------------------------------------------------------------------------------------------------------------------
        --  Copyright (c) 2023, BernhardZat -- see LICENSE file                                                                 --
        --                                                                                                                      --
        --  X25519 elliptic-curve Diffie-Hellman key agreement implemented in pure Lua 5.1.                                     --
        --  Based on the original TweetNaCl library written in C. See https://tweetnacl.cr.yp.to/                               --
        --                                                                                                                      --
        --  Lua 5.1 doesn't have a 64 bit signed integer type and no bitwise operations.                                        --
        --  This implementation emulates bitwise operations arithmetically on 64 bit double precision floating point numbers.   --
        --  Note that double precision floating point numbers are only exact in the integer range of [-2^53, 2^53].             --
        --  This works for our purposes because values will not be outside the range of about [-2^43, 2^44].                    --
        --------------------------------------------------------------------------------------------------------------------------

        local carry = function(out)
            for i = 0, 15 do
                out[i] = out[i] + 0x10000;
                local c = out[i] / 0x10000 - (out[i] / 0x10000) % 1;
                if i < 15 then
                    out[i + 1] = out[i + 1] + c - 1;
                else
                    out[0] = out[0] + 38 * (c - 1);
                end
                out[i] = out[i] - c * 0x10000;
            end
        end

        local swap = function(a, b, bit)
            for i = 0, 15 do
                a[i], b[i] =
                    a[i] * ((bit - 1) % 2) + b[i] * bit,
                    b[i] * ((bit - 1) % 2) + a[i] * bit;
            end
        end

        local unpack = function(out, a)
            for i = 0, 15 do
                out[i] = a[2 * i] + a[2 * i + 1] * 0x100;
            end
            out[15] = out[15] % 0x8000;
        end

        local pack = function(out, a)
            local t, m = {}, {};
            for i = 0, 15 do
                t[i] = a[i];
            end
            carry(t);
            carry(t);
            carry(t);
            local prime = { [0] = 0xffed, [15] = 0x7fff };
            for i = 1, 14 do
                prime[i] = 0xffff;
            end
            for _ = 0, 1 do
                m[0] = t[0] - prime[0];
                for i = 1, 15 do
                    m[i] = t[i] - prime[i] - ((m[i - 1] / 0x10000 - (m[i - 1] / 0x10000) % 1) % 2);
                    m[i - 1] = (m[i - 1] + 0x10000) % 0x10000;
                end
                local c = (m[15] / 0x10000 - (m[15] / 0x10000) % 1) % 2;
                swap(t, m, 1 - c);
            end
            for i = 0, 15 do
                out[2 * i] = t[i] % 0x100;
                out[2 * i + 1] = t[i] / 0x100 - (t[i] / 0x100) % 1;
            end
        end

        local add = function(out, a, b)
            for i = 0, 15 do
                out[i] = a[i] + b[i];
            end
        end

        local sub = function(out, a, b)
            for i = 0, 15 do
                out[i] = a[i] - b[i];
            end
        end

        local mul = function(out, a, b)
            local prod = {};
            for i = 0, 31 do
                prod[i] = 0;
            end
            for i = 0, 15 do
                for j = 0, 15 do
                    prod[i + j] = prod[i + j] + a[i] * b[j];
                end
            end
            for i = 0, 14 do
                prod[i] = prod[i] + 38 * prod[i + 16];
            end
            for i = 0, 15 do
                out[i] = prod[i];
            end
            carry(out);
            carry(out);
        end

        local inv = function(out, a)
            local c = {};
            for i = 0, 15 do
                c[i] = a[i];
            end
            for i = 253, 0, -1 do
                mul(c, c, c);
                if i ~= 2 and i ~= 4 then
                    mul(c, c, a);
                end
            end
            for i = 0, 15 do
                out[i] = c[i];
            end
        end

        local scalarmult = function(out, scalar, point)
            local a, b, c, d, e, f, x, clam = {}, {}, {}, {}, {}, {}, {}, {};
            unpack(x, point);
            for i = 0, 15 do
                a[i], b[i], c[i], d[i] = 0, x[i], 0, 0;
            end
            a[0], d[0] = 1, 1;
            for i = 0, 30 do
                clam[i] = scalar[i];
            end
            clam[0] = clam[0] - (clam[0] % 8);
            clam[31] = scalar[31] % 64 + 64;
            for i = 254, 0, -1 do
                local bit = (clam[i / 8 - (i / 8) % 1] / 2 ^ (i % 8) - (clam[i / 8 - (i / 8) % 1] / 2 ^ (i % 8)) % 1) % 2;
                swap(a, b, bit);
                swap(c, d, bit);
                add(e, a, c);
                sub(a, a, c);
                add(c, b, d);
                sub(b, b, d);
                mul(d, e, e);
                mul(f, a, a);
                mul(a, c, a);
                mul(c, b, e);
                add(e, a, c);
                sub(a, a, c);
                mul(b, a, a);
                sub(c, d, f);
                mul(a, c, { [0] = 0xdb41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
                add(a, a, d);
                mul(c, c, a);
                mul(a, d, f);
                mul(d, b, x);
                mul(b, e, e);
                swap(a, b, bit);
                swap(c, d, bit);
            end
            inv(c, c);
            mul(a, a, c);
            pack(out, a);
        end

        local generate_keypair = function(rng)
            rng = rng or function() return math.random(0, 0xFF) end;
            local sk, pk = {}, {};
            for i = 0, 31 do
                sk[i] = rng();
            end
            local base = { [0] = 9 };
            for i = 1, 31 do
                base[i] = 0;
            end
            scalarmult(pk, sk, base);
            return sk, pk;
        end

        local get_shared_key = function(sk, pk)
            local shared = {};
            scalarmult(shared, sk, pk);
            return shared;
        end

        security.x25519 = {
            generate_keypair = generate_keypair,
            get_shared_key = get_shared_key,
        }
    end

    do
        local function key_to_string(key)
            local bytes = {}
            for i = 0, 31 do
                bytes[i + 1] = string.char(key[i] or 0)
            end
            return security.base64.encode(table.concat(bytes))
        end

        local function string_to_key(str)
            local decoded = security.base64.decode(str)
            if not decoded or #decoded ~= 32 then
                error("Invalid key length or decoding error")
            end
            local key = {}
            for i = 1, #decoded do
                key[i - 1] = string.byte(decoded, i)
            end
            return key
        end

        local function generate_nonce()
            local nonce = ""
            for i = 1, 12 do
                nonce = nonce .. string.char(math.random(0, 255))
            end
            return security.base64.encode(nonce)
        end

        local function uuid()
            local template = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
            return string.gsub(template, '[xy]', function(c)
                local v = (c == 'x') and math.random(0, 15) or math.random(8, 11)
                return string.format('%x', v)
            end)
        end

        local function split(str, sep)
            local result = {}
            for part in str:gmatch("[^" .. sep .. "]+") do
                table.insert(result, part)
            end
            return result
        end

        security.utils = {
            key_to_string = key_to_string,
            string_to_key = string_to_key,
            generate_nonce = generate_nonce,
            uuid = uuid,
            split = split
        }
    end
end

return security