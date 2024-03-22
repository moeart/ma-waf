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

local io = require("io")
local cjson = require("cjson")
local string = require("string")
local config = require("config")

local _M = {
    version = "0.1",
    RULE_TABLE = {},
    RULE_FILES = {
        "system/args.rule",
        "system/cookie.rule",
        "system/post.rule",
        "system/url.rule",
        "system/useragent.rule",
        "system/referer.rule",
        "system/header.rule",
        "blackip.rule",
        "useragentforcc.rule",
        "whiteip.rule",
        "whiteurl.rule"
    }
}

-- security_token_check
function _M.security_token_check(token)
    if token ~= nil then
        if token == config.firewall_security_token then
            --_M.write(config.config_log_dir.."/token.log","token firewall_security_token ok:"..token.."\n")
            return true
        end
    end
    return false
end

-- security_timestamp_check
function _M.security_timestamp_check(times)
    if times ~= nil then
        local times_recv = tonumber(times);
        -- 检查时间戳格式
        if times_recv ~= nil then
          local times_current = _M.security_get_timestamp()
          --_M.write(config.config_log_dir.."/token.log","token timestamp abs:"..math.abs(times_current - times_recv).."\n")
          -- 时间差不得超过10分钟
          if math.abs(times_current - times_recv) <= 600 then
              --_M.write(config.config_log_dir.."/token.log","token timestamp abs is <= 600:"..math.abs(times_current - times_recv).."\n")
              return true
          end
        else
            --_M.write(config.config_log_dir.."/token.log","token timestamp format error:"..times.."\n")
        end
        
    end
    --_M.write(config.config_log_dir.."/token.log","token timestamp error\n")
    return false
end

-- security_get_timestamp
function _M.security_get_timestamp()
    return os.time()
end

-- security_is_vaild_token
function _M.security_is_vaild_token(tokenlab,plaintext)
    if _M.security_token_check(tokenlab["token"]) and _M.security_timestamp_check(tokenlab["timestamp"]) then
        --_M.write(config.config_log_dir.."/token.log","token is valid \n")
        return true
    end
    -- fixd crash bug.
    --_M.write(config.config_log_dir.."/token.log","token not valid :"..tokenlab["token"].."___"..tokenlab["timestamp"].."\n")
    --_M.write(config.config_log_dir.."/token.log","token not valid :"..plaintext)
    return false
end

-- security_feature_string_check
function _M.security_feature_string_check(ptext)
    if string.find(ptext,"normal_feature_string_firewall_sec") ~= nil then
        return true
    end
    
    return false
end

-- security_check
function _M.security_check(secstr)
    if secstr ~= nil then
        -- 此处缺少异常处理
        --_M.write(config.config_log_dir.."/token.log","token get secstr :"..secstr.."\n")
        local plaintext = _M.security_token_decode(secstr)
        
        if plaintext ~= nil then
          -- 检查格式特征是否正确，以防乱输入
          if _M.security_feature_string_check(plaintext) then
              --_M.write(config.config_log_dir.."/token.log","token feature check ok :"..plaintext.."\n")
              local token_table = cjson.decode(plaintext)
              -- 检查是否有效
              if token_table ~= nil then
                return _M.security_is_vaild_token(token_table,plaintext)
              end
          end
        else
          --_M.write(config.config_log_dir.."/token.log","token decode plaintext is nil\n")
        end
    end
    
    return false
end

-- security_str_gen
function _M.security_str_gen()
    local sec_token_table = {}
    
    sec_token_table["status"] = "normal_feature_string_firewall_sec"
    sec_token_table["timestamp"] = tostring(_M.security_get_timestamp()) -- 这里需要字符串化，否则传入非数字json解析会引起崩溃
    sec_token_table["token"] = config.firewall_security_token
    
    return _M.security_token_encode(cjson.encode(sec_token_table))
end

-- security_test
function _M.security_test()
    local test = _M.security_str_gen()
    return ("token: "..test)
end

-- encode/crypt_de
function _M.security_token_encode(source_str)
    --local b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    local b64chars = config.firewall_security_table
    local s64 = ''
    local str = source_str

    while #str > 0 do
        local bytes_num = 0
        local buf = 0

        for byte_cnt=1,3 do
            buf = (buf * 256)
            if #str > 0 then
                buf = buf + string.byte(str, 1, 1)
                str = string.sub(str, 2)
                bytes_num = bytes_num + 1
            end
        end

        for group_cnt=1,(bytes_num+1) do
            local b64char = math.fmod(math.floor(buf/262144), 64) + 1
            s64 = s64 .. string.sub(b64chars, b64char, b64char)
            buf = buf * 64
        end

        for fill_cnt=1,(3-bytes_num) do
            s64 = s64 .. '='
        end
    end

    return s64
end

function _M.security_token_decode(str64)
    --local b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    local b64chars = config.firewall_security_table
    local temp={}
    for i=1,64 do
        temp[string.sub(b64chars,i,i)] = i
    end
    temp['=']=0
    local str=""
    for i=1,#str64,4 do
        if i>#str64 then
            break
        end
        local data = 0
        local str_count=0
        for j=0,3 do
            local str1=string.sub(str64,i+j,i+j)
            if not temp[str1] then
                return
            end
            if temp[str1] < 1 then
                data = data * 64
            else
                data = data * 64 + temp[str1]-1
                str_count = str_count + 1
            end
        end
        for j=16,0,-8 do
            if str_count > 0 then
                str=str..string.char(math.floor(data/math.pow(2,j)))
                --data=math.mod(data,math.pow(2,j))
                data=(data % math.pow(2,j))
                str_count = str_count - 1
            end
        end
    end

    local last = tonumber(string.byte(str, string.len(str), string.len(str)))
    if last == 0 then
        str = string.sub(str, 1, string.len(str) - 1)
    end
    return str
end


-- log_write
function _M.write(logfile,msg)
    local fd = io.open(logfile,"ab")
    if fd == nil then return end
    fd:write(msg)
    fd:flush()
    fd:close()
end

-- Get all rule file name
function _M.get_rule_files(rules_path)
    local rule_files = {}
    for _, file in ipairs(_M.RULE_FILES) do
        if file ~= "" then
            local file_name = rules_path .. '/' .. file
            ngx.log(ngx.DEBUG, string.format("rule key:%s, rule file name:%s", file, file_name))
            rule_files[file] = file_name
        end
    end
    return rule_files
end


-- Load WAF rules into table when on nginx's init phase
function _M.get_rules(rules_path)
    local rule_files = _M.get_rule_files(rules_path)
    if rule_files == {} then
        return nil
    end

    for rule_name, rule_file in pairs(rule_files) do
        local t_rule = {}
        local file_rule_name = io.open(rule_file)
        local json_rules = file_rule_name:read("*a")
        file_rule_name:close()
        local table_rules = cjson.decode(json_rules)
        if table_rules ~= nil then
            ngx.log(ngx.INFO, string.format("%s:%s", table_rules, type(table_rules)))
            for _, table_name in pairs(table_rules) do
                -- ngx.log(ngx.INFO, string.format("Insert table:%s, value:%s", t_rule, table_name["RuleItem"]))
                table.insert(t_rule, table_name["RuleItem"])
            end
        end
        ngx.log(ngx.INFO, string.format("rule_name:%s, value:%s", rule_name, t_rule))
        _M.RULE_TABLE[rule_name] = t_rule
    end
    return(_M.RULE_TABLE)
end

-- Get the client IP
function _M.get_client_ip()
    local CLIENT_IP = ngx.req.get_headers()["Client_Ip"]
    if CLIENT_IP == nil then
        CLIENT_IP = ngx.req.get_headers()["Cdn_Src_Ip"]
    end
    if CLIENT_IP == nil then
        CLIENT_IP = ngx.req.get_headers()["X_Real_Ip"]
    end
    if CLIENT_IP == nil then
        CLIENT_IP = ngx.req.get_headers()["X_Forwarded_For"]
    end
    if CLIENT_IP == nil then
        CLIENT_IP  = ngx.var.remote_addr
    end
    if CLIENT_IP == nil then
        CLIENT_IP  = ""
    end
    return CLIENT_IP
end

-- Get the client user agent
function _M.get_user_agent()
    local USER_AGENT = ngx.var.http_user_agent
    if USER_AGENT == nil then
        USER_AGENT = "unknown"
    end
    return USER_AGENT
end
-- get server's host
function _M.get_server_host()
    local host = ngx.req.get_headers()["Host"]
    return host
end

-- Get all rule file name by lfs
--function _M.get_rule_files(rules_path)
--local lfs = require("lfs")
--    local rule_files = {}
--    for file in lfs.dir(rules_path) do
--        if file ~= "." and file ~= ".." then
--            local file_name = rules_path .. '/' .. file
--            ngx.log(ngx.DEBUG, string.format("rule key:%s, rule file name:%s", file, file_name))
--            rule_files[file] = file_name
--        end
--    end
--    return rule_files
--end

-- WAF log record for json
function _M.log_record(config_log_dir, method, url, data, ruletag)
    local log_path = config_log_dir
    local client_IP = _M.get_client_ip()
    local user_agent = _M.get_user_agent()
    local server_name = ngx.var.server_name
    local local_time = ngx.localtime()
    local log_json_obj = {
        client_ip = client_IP,
        local_time = local_time,
        server_name = server_name,
        user_agent = user_agent,
        attack_method = method,
        req_url = url,
        req_data = data,
        rule_tag = ruletag,
    }

    local log_line = cjson.encode(log_json_obj)
    local log_name = string.format("%s/%s_waf.log", log_path, ngx.today())
    local file = io.open(log_name, "a")
    if file == nil then
        return
    end

    file:write(string.format("%s\n", log_line))
    file:flush()
    file:close()
end

-- WAF response
function _M.waf_output()
    if config.config_waf_model == "reset" then
        ngx.exit(444)
    elseif config.config_waf_model == "redirect" then
        ngx.redirect(config.config_waf_redirect_url, 301)
    elseif config.config_waf_model == "jinghuashuiyue" then
        local bad_guy_ip = _M.get_client_ip()
        _M.set_bad_guys(bad_guy_ip, config.config_expire_time)
    else
        ngx.header.content_type = "text/html"
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say(string.format(config.config_output_html, _M.get_client_ip()))
        ngx.exit(ngx.status)
    end
end

-- set bad guys ip to ngx.shared dict
function _M.set_bad_guys(bad_guy_ip, expire_time)
    local badGuys = ngx.shared.badGuys
    local req, _ = badGuys:get(bad_guy_ip)
    if req then
        badGuys:incr(bad_guy_ip, 1)
    else
        badGuys:set(bad_guy_ip, 1, expire_time)
    end
end

return _M
