--[[

Copyright (c) 2016 xsec.io

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THEq
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

]]

if ngx.var.uri:sub(1, 8) == "/cgi-waf" then
    local info = debug.getinfo(1, "S")
    local src = info.source or ""
    local filepath = src:match("^@(.*)") or src
    local dir = filepath:gsub("\\", "/"):match("^(.*)/")
    if dir then
        local f = loadfile(dir .. "/webui.lua")
        if f then
            local cgi = f()
            if cgi and cgi.run then return cgi.run() end
        end
    end
    ngx.status = 500
    ngx.header["Content-Type"] = "text/plain; charset=utf-8"
    ngx.say("webui module not found")
    return ngx.exit(500)
end

if ngx.var.uri:sub(1, 8) == "/cgi-rfw" then
    local ok, rfw = pcall(require, "ma_rfw")
    if ok and rfw and rfw.run then return rfw.run() end
    ngx.status = 500
    ngx.header["Content-Type"] = "text/plain; charset=utf-8"
    ngx.say("rfw module not found")
    return ngx.exit(500)
end

waf.check()