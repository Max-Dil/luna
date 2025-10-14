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
    do
        local string_char, math_floor, math_log, table_concat = string.char, math.floor, math.log, table.concat;
        local number_to_bytestring = function(num, n)
            n = n or math_floor(math_log(num) / math_log(0x100) + 1);
            n = n > 0 and n or 1;
            local t = {};
            for i = 1, n do
                t[n - i + 1] = string_char((num % 0x100 ^ i - num % 0x100 ^ (i - 1)) / 0x100 ^ (i - 1));
            end
            local s = table_concat(t);
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

        security.util = {
            number_to_bytestring = number_to_bytestring,
            bytestring_to_number = bytestring_to_number,
        }
    end

    do
        local has_bit32, bit32 = pcall(require, "bit32");
        local has_bit, bit = pcall(require, "bit");
        local u32_xor, u32_lrot;
        if has_bit32 then
            u32_xor = bit32.bxor;
            u32_lrot = function(a, n)
                return bit32.lrotate(a, n % 32);
            end
        elseif has_bit then
            u32_xor = bit.bxor;
            u32_lrot = bit.rol;
        else
            local and_table = {};
            do
                for i = 0, 255 do
                    and_table[i] = {};
                    for j = 0, 255 do
                        local result = 0;
                        local bit_val = 1;
                        for k = 0, 7 do
                            if (i % (2 * bit_val)) >= bit_val and (j % (2 * bit_val)) >= bit_val then
                                result = result + bit_val;
                            end
                            bit_val = bit_val * 2;
                        end
                        and_table[i][j] = result;
                    end
                end
            end

            local math_floor = math.floor;
            function u32_xor(a, b)
                local a1, a2, b1, b2 = math_floor(a / 0x10000), a % 0x10000, math_floor(b / 0x10000), b % 0x10000;

                local a161, a162, b161, b162 = math_floor(a1 / 0x100), a1 % 0x100, math_floor(b1 / 0x100), b1 % 0x100;
                local r1 = (a161 + b161 - 2 * and_table[a161 % 0x100][b161 % 0x100]) % 0x100 * 0x100 + (a162 + b162 - 2 * and_table[a162 % 0x100][b162 % 0x100]) % 0x100;

                a161, a162, b161, b162 = math_floor(a2 / 0x100), a2 % 0x100, math_floor(b2 / 0x100), b2 % 0x100;
                local r2 = (a161 + b161 - 2 * and_table[a161 % 0x100][b161 % 0x100]) % 0x100 * 0x100 + (a162 + b162 - 2 * and_table[a162 % 0x100][b162 % 0x100]) % 0x100;
                return r1 * 0x10000 + r2;
            end

            function u32_lrot(a, n)
                n = n % 32;
                return ((a * (2 ^ n)) % 0x100000000 + math_floor(a / (2 ^ (32 - n)))) % 0x100000000;
            end
        end

        local num_to_bytes, num_from_bytes, MOD, char, XOR, LROT =
            security.util.number_to_bytestring, security.util.bytestring_to_number, 0x100000000, string.char, u32_xor,
            u32_lrot

        local function unpack(s, len)
            local array = {};
            local count = 0;
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

        local min, table_concat = math.min, table.concat;
        local function pack(a, len)
            local t = {};
            local array_len = #a;
            local remaining = len or (array_len * 4);
            for i = 1, array_len do
                local bytes = num_to_bytes(a[i], 4);
                local take = min(4, remaining - (i - 1) * 4);
                t[i] = bytes:sub(1, take);
            end
            return table_concat(t);
        end

        local function quarter_round(s, a, b, c, d)
            s[a] = (s[a] + s[b]) % MOD; s[d] = LROT(XOR(s[d], s[a]), 16);
            s[c] = (s[c] + s[d]) % MOD; s[b] = LROT(XOR(s[b], s[c]), 12);
            s[a] = (s[a] + s[b]) % MOD; s[d] = LROT(XOR(s[d], s[a]), 8);
            s[c] = (s[c] + s[d]) % MOD; s[b] = LROT(XOR(s[b], s[c]), 7);
        end

        local CONSTANTS = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };
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

        local unpack, pack, floor, ceil, table_concat = unpack, pack, math.floor, math.ceil, table.concat;
        local encrypt = function(plain, key, nonce)
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

                cipher_count = cipher_count + 1;
                cipher[cipher_count] = pack(cipher_block);

                counter = counter + 1;
            end
            if plain_len % 64 ~= 0 then
                local key_stream = block(key, nonce, counter);
                local plain_block = unpack(plain:sub(counter * 64 + 1));
                local cipher_block = {};

                chunks = ceil((plain_len % 64) / 4);
                for j = 1, chunks do
                    cipher_block[j] = XOR(plain_block[j], key_stream[j]);
                end

                cipher_count = cipher_count + 1;
                cipher[cipher_count] = pack(cipher_block);
            end
            return table_concat(cipher);
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

        local floor, table_concat = math.floor, table.concat;
        local encode = function(s)
            local r = s:len() % 3;
            s = r == 0 and s or s .. ("\0"):rep(3 - r);
            local b64 = {};
            local count = 0;
            local len = s:len();
            for i = 1, len, 3 do
                local b1, b2, b3 = s:byte(i, i + 2);
                count = count + 1;
                b64[count] = enc[floor(b1 / 0x04)];
                count = count + 1;
                b64[count] = enc[floor(b2 / 0x10) + (b1 % 0x04) * 0x10];
                count = count + 1;
                b64[count] = enc[floor(b3 / 0x40) + (b2 % 0x10) * 0x04];
                count = count + 1;
                b64[count] = enc[b3 % 0x40];
            end
            count = count + 1;
            b64[count] = (r == 0 and "" or ("="):rep(3 - r));
            return table_concat(b64);
        end

        local char, floor, table_concat = string.char, math.floor, table.concat;
        local decode = function(b64)
            local b, p = b64:gsub("=", "");
            local s = {};
            local count = 0;
            local len = b:len();
            for i = 1, len, 4 do
                local b1 = dec[b:sub(i, i)];
                local b2 = dec[b:sub(i + 1, i + 1)];
                local b3 = dec[b:sub(i + 2, i + 2)];
                local b4 = dec[b:sub(i + 3, i + 3)];
                count = count + 1;
                s[count] = char(
                    b1 * 0x04 + floor(b2 / 0x10),
                    (b2 % 0x10) * 0x10 + floor(b3 / 0x04),
                    (b3 % 0x04) * 0x40 + b4
                );
            end
            local result = table_concat(s);
            result = result:sub(1, -(p + 1));
            return result;
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

        local math_random = math.random
        local generate_keypair = function(rng)
            rng = rng or function() return math_random(0, 0xFF) end;
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
            local bytes = {};
            local char = string.char;
            for i = 0, 31 do
                bytes[i + 1] = char(key[i] or 0);
            end
            return security.base64.encode(table.concat(bytes));
        end

        local function string_to_key(str)
            local decoded = security.base64.decode(str);
            local len = #decoded;
            if not decoded or len ~= 32 then
                error("Invalid key length or decoding error");
            end
            local key = {};
            local byte = string.byte;
            for i = 1, len do
                key[i - 1] = byte(decoded, i);
            end
            return key;
        end

        local string_char, math_random = string.char, math.random
        local function generate_nonce()
            local nonce = "";
            for i = 1, 12 do
                nonce = nonce .. string_char(math_random(0, 255));
            end
            return security.base64.encode(nonce);
        end

        local string_gsub, math_random, string_format = string.gsub, math.random, string.format
        local function uuid()
            local template = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx';
            return string_gsub(template, '[xy]', function(c)
                local v = (c == 'x') and math_random(0, 15) or math_random(8, 11);
                return string_format('%x', v);
            end)
        end

        local table_insert = table.insert
        local function split(str, sep)
            local result = {};
            for part in str:gmatch("[^" .. sep .. "]+") do
                table_insert(result, part);
            end
            return result;
        end

        security.utils = {
            key_to_string = key_to_string,
            string_to_key = string_to_key,
            generate_nonce = generate_nonce,
            uuid = uuid,
            split = split
        };
    end
end

return security
