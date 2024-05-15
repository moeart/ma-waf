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

local rulematch = ngx.re.find
local unescape = ngx.unescape_uri

local config = require("config")
local util = require("util")
local iputils = require("iputils")
local cjson = require("cjson")

local _M = {
    RULES = {}
}

-- 系统记录初始化
system_info = ngx.shared.system_info
function _M.system_share_info_init()
    --local system_info = ngx.shared.system_info
    -- 读取标记位，防止 reload 时重新初始化共享区，导致统计数据丢失
    local system_init_status, _ = system_info:get("firewall_init")
    if system_init_status then -- 已初始化
        system_info:incr("firewall_reload_count",1)
    else
        -- 未初始化，进行初始化操作
        system_info:set("firewall_init",true)
        -- 初始化系统状态记录
        -- good
        system_info:set("firewall_req_total",0)      -- 0.请求总数
        system_info:set("firewall_req_normal",0)     -- 1.正常请求总数
        system_info:set("firewall_req_white_ip",0)   -- 2.白名单 IP 命中数
        system_info:set("firewall_req_white_url",0)  -- 3.白名单 URL 命中数

        -- bad
        system_info:set("firewall_req_attack",0)     -- 4.攻击请求总数
        system_info:set("firewall_req_black_ip",0)   -- 5.黑名单 IP 命中数
        system_info:set("firewall_req_header",0)     -- 6.规则 Header 命中数量 
        system_info:set("firewall_req_referer",0)    -- 7.规则 Referer 命中数量
        system_info:set("firewall_req_cc",0)         -- 8.规则 CC 命中数量
        system_info:set("firewall_req_cookie",0)     -- 9.规则 Cookie 命中数量
        system_info:set("firewall_req_url",0)        -- 10.规则 URL 命中数量
        system_info:set("firewall_req_url_args",0)   -- 11.规则 URL 参数 命中数量
        system_info:set("firewall_req_ua",0)         -- 12.规则 UA 命中数量
        system_info:set("firewall_req_post",0)       -- 13.规则 POST 命中数量

        -- info
        system_info:set("firewall_reload_count",0)   -- 14.系统 Reload 重载次数
    end
end

-- 系统记录读取接口_json
function _M.system_share_info_readall()
    local method = ngx.req.get_method()
    local result_table = {}
    local args = nil
    local result = nil
    
    if "GET" == method then
        args = ngx.req.get_uri_args()
    elseif "POST" == method then
        ngx.req.read_body()
        args = ngx.req.get_post_args()
    end
    
    if args["token"] ~= nil then
        if util.security_check(args["token"]) then
            -- 检查通过，返回数据

            -- good
            result_table["firewall_req_total"] = system_info:get("firewall_req_total")
            -- firewall_req_normal 考虑在前端自行计算汇总
            result_table["firewall_req_normal"] = system_info:get("firewall_req_normal")
            result_table["firewall_req_white_ip"] = system_info:get("firewall_req_white_ip")
            result_table["firewall_req_white_url"] = system_info:get("firewall_req_white_url")

            --- bad
            result_table["firewall_req_attack"] = system_info:get("firewall_req_attack")
            result_table["firewall_req_black_ip"] = system_info:get("firewall_req_black_ip")
            result_table["firewall_req_header"] = system_info:get("firewall_req_header")
            result_table["firewall_req_referer"] = system_info:get("firewall_req_referer")
            result_table["firewall_req_cc"] = system_info:get("firewall_req_cc")
            result_table["firewall_req_cookie"] = system_info:get("firewall_req_cookie")
            result_table["firewall_req_url"] = system_info:get("firewall_req_url")
            result_table["firewall_req_url_args"] = system_info:get("firewall_req_url_args")
            result_table["firewall_req_ua"] = system_info:get("firewall_req_ua")
            result_table["firewall_req_post"] = system_info:get("firewall_req_post")

            -- info
            result_table["firewall_reload_count"] = system_info:get("firewall_reload_count")
            
            result = util.security_token_encode(cjson.encode(result_table))
        else
            result = 'token is invalid.'
        end
    else
        result = 'args is null.'
    end

    -- 回收空间
    result_table = nil
    args = nil
    method = nil
    
    return result
end

-- 系统记录设置
function _M.system_share_info_set(key,value)
    system_info:set(key,value)
end

-- 系统记录读取
function _M.system_share_info_get(key)
    return system_info:get(key)
end

-- 系统记录增加
function _M.system_share_info_incr(key)
    system_info:incr(key,1)
end

-- 系统攻击记录增加
function _M.system_share_attack_info_incr(key)
    system_info:incr("firewall_req_attack",1)
    system_info:incr(key,1)
end

function _M.load_rules()
    _M.RULES = util.get_rules(config.config_rule_dir)
    for k, v in pairs(_M.RULES)
    do
        ngx.log(ngx.INFO, string.format("%s Rule Set", k))
        for kk, vv in pairs(v)
        do
            ngx.log(ngx.INFO, string.format("index:%s, Rule:%s", kk, vv))
        end
    end
    return _M.RULES
end

function _M.get_rule(rule_file_name)
    ngx.log(ngx.DEBUG, rule_file_name)
    return _M.RULES[rule_file_name]
end

-- deny header(ScanTools)
function _M.header_check()
    if config.config_header_check == "on" then
        local Header_RULES = _M.get_rule('system/header.rule')
        local HEADER_VALUES = ngx.req.get_headers()
        for HeaderName, HeaderValue in pairs(HEADER_VALUES) do
          -- ngx.log(ngx.DEBUG, HEADER_VALUES)
          -- ngx.say("check : ", HeaderName," : ",HeaderValue,"</br>")
          for _, rule in pairs(Header_RULES) do
              -- ngx.say("match : ", HeaderName," : ",rule,"</br>")
              if rule ~= "" and rulematch(HeaderName, rule, "ijo") then
                  util.log_record(config.config_log_dir,'Deny_Header', ngx.var.request_uri, HeaderName, rule)
                  if config.config_waf_enable == "on" then
                      _M.system_share_attack_info_incr("firewall_req_header")
                      util.waf_output()
                      return true
                  end
              end
          end
        end
    end
    return false
end

-- deny referer
function _M.referer_check()
    if config.config_referer_check == "on" then
        local Referer_RULES = _M.get_rule('system/referer.rule')
        local Referer = ngx.var.http_referer
        if Referer ~= nil then
            for _, rule in pairs(Referer_RULES) do
                if rule ~= "" and rulematch(Referer, rule, "ijo") then
                    util.log_record(config.config_log_dir,'Deny_Referer', ngx.var.request_uri, Referer, rule)
                    if config.config_waf_enable == "on" then
                        _M.system_share_attack_info_incr("firewall_req_referer")
                        util.waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end

-- white ip check
function _M.white_ip_check()
    if config.config_white_ip_check == "on" then
        local IP_WHITE_RULE = _M.get_rule('whiteip.rule')
        local WHITE_IP = util.get_client_ip()
        if IP_WHITE_RULE ~= nil then
            for _, rule in pairs(IP_WHITE_RULE) do
                if rule ~= "" and iputils.ip_in_cidr(WHITE_IP, rule) then
                    _M.system_share_attack_info_incr("firewall_req_white_ip")
                    util.log_record(config.config_log_dir,'White_IP', ngx.var_request_uri, "_", "_")
                    return true
                end
            end
        end
    end
end

-- Bad guys check
function _M.bad_guy_check()
    local client_ip = util.get_client_ip()
    local ret = false
    if client_ip ~= "" then
        ret = ngx.shared.badGuys.get(client_ip)
        if ret ~= nil and ret > 0 then
            ret = true
        end
    end
    return ret
end


-- deny black ip
function _M.black_ip_check()
    if config.config_black_ip_check == "on" then
        local IP_BLACK_RULE = _M.get_rule('blackip.rule')
        local BLACK_IP = util.get_client_ip()
        if IP_BLACK_RULE ~= nil then
            for _, rule in pairs(IP_BLACK_RULE) do
                if rule ~= "" and iputils.ip_in_cidr(BLACK_IP, rule) then
                    _M.system_share_attack_info_incr("firewall_req_black_ip")
                    util.log_record(config.config_log_dir,'BlackList_IP', ngx.var_request_uri, "_", "_")
                    if config.config_waf_enable == "on" then
                        ngx.exit(403)
                        return true
                    end
                end
            end
        end
    end
end

-- allow white url
function _M.white_url_check()
    if config.config_white_url_check == "on" then
        local URL_WHITE_RULES = _M.get_rule('whiteurl.rule')
        local REQ_URI = ngx.var.http_host .. ngx.var.request_uri
        if URL_WHITE_RULES ~= nil then
            for _,rule in pairs(URL_WHITE_RULES) do
                if rule ~= "" and rulematch(REQ_URI, rule, "ijo") then
                    _M.system_share_attack_info_incr("firewall_req_white_url")
                    return true
                end
            end
        end
    end
end

-- deny cc attack
function _M.cc_attack_check()
    if config.config_cc_check == "on" then
        local ATTACK_URI = ngx.var.request_uri
        -- check ua whitelist
        -- if in whitelist then use ip+url only
        local USER_AGENT_RULES = _M.get_rule('useragentforcc.rule')
        local USER_AGENT = ngx.var.http_user_agent
        local USER_AGENT_WHITE = false
        if USER_AGENT ~= nil then
            for _, rule in pairs(USER_AGENT_RULES) do
                if rule ~= "" and rulematch(USER_AGENT, rule, "jo") then
                    USER_AGENT_WHITE = true
                end
            end
        end
        -- ip only mode
        local CC_TOKEN = util.get_client_ip()
        local CC_LOGTAG = "CC_Attack_IP"
        local limit = ngx.shared.limit
        local CCcount = tonumber(string.match(config.config_cc_rate_ip, '(.*)/'))
        local CCseconds = tonumber(string.match(config.config_cc_rate_ip, '/(.*)'))
        -- ip + url mode
        if config.config_cc_mode == "ipurl" or USER_AGENT_WHITE then
            CC_TOKEN = util.get_client_ip() .. ATTACK_URI
            CC_LOGTAG = "CC_Attack_IPURL"
            CCcount = tonumber(string.match(config.config_cc_rate_ipurl, '(.*)/'))
            CCseconds = tonumber(string.match(config.config_cc_rate_ipurl, '/(.*)'))
        end
        local req,_ = limit:get(CC_TOKEN)
        if req then
            if req > CCcount then
                _M.system_share_attack_info_incr("firewall_req_cc")
                util.log_record(config.config_log_dir, CC_LOGTAG, ngx.var.request_uri, "-", "-")
                if config.config_waf_enable == "on" then
                    ngx.exit(444)
                end
            else
                limit:incr(CC_TOKEN, 1)
            end
        else
            limit:set(CC_TOKEN, 1, CCseconds)
        end
    end
    return false
end

-- deny cookie
function _M.cookie_attack_check()
    if config.config_cookie_check == "on" then
        local COOKIE_RULES = _M.get_rule('system/cookie.rule')
        local USER_COOKIE = ngx.var.http_cookie
        if USER_COOKIE ~= nil then
            for _, rule in pairs(COOKIE_RULES) do
                if rule ~="" and rulematch(USER_COOKIE, rule, "jo") then
                    _M.system_share_attack_info_incr("firewall_req_cookie")
                    util.log_record(config.config_log_dir,'Deny_Cookie', ngx.var.request_uri, "-", rule)
                    if config.config_waf_enable == "on" then
                        util.waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end

-- deny url
function _M.url_attack_check()
    if config.config_url_check == "on" then
        local URL_RULES = _M.get_rule('system/url.rule')
        local REQ_URI = ngx.var.request_uri
        for _,rule in pairs(URL_RULES) do
            if rule ~="" and rulematch(REQ_URI,rule,"ijo") then
                _M.system_share_attack_info_incr("firewall_req_url")
                util.log_record(config.config_log_dir,'Deny_URL', REQ_URI, "-", rule)
                if config.config_waf_enable == "on" then
                    util.waf_output()
                    return true
                end
            end
        end
    end
    return false
end

-- deny url args
function _M.url_args_attack_check()
    if config.config_url_args_check == "on" then
        local ARGS_RULES = _M.get_rule('system/args.rule')
        for _,rule in pairs(ARGS_RULES) do
            local REQ_ARGS = ngx.req.get_uri_args()
            for key, val in pairs(REQ_ARGS) do
                ngx.log(ngx.DEBUG, key)
                local ARGS_DATA = {}
                if type(val) == 'table' then
                    ARGS_DATA = table.concat(val, " ")
                    ngx.log(ngx.DEBUG, ARGS_DATA)
                else
                    ARGS_DATA = val
                end
                if ARGS_DATA and type(ARGS_DATA) ~= "boolean" and rule ~="" and rulematch(unescape(ARGS_DATA), rule, "ijo") then
                    _M.system_share_attack_info_incr("firewall_req_url_args")
                    util.log_record(config.config_log_dir,'Deny_URL_Args', ngx.var.request_uri, "-", rule)
                    if config.config_waf_enable == "on" then
                        util.waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end

-- deny user agent
function _M.user_agent_attack_check()
    if config.config_user_agent_check == "on" then
        local USER_AGENT_RULES = _M.get_rule('system/useragent.rule')
        local USER_AGENT = ngx.var.http_user_agent
        if USER_AGENT ~= nil then
            for _, rule in pairs(USER_AGENT_RULES) do
                if rule ~= "" and rulematch(USER_AGENT, rule, "jo") then
                    _M.system_share_attack_info_incr("firewall_req_ua")
                    util.log_record(config.config_log_dir,'Deny_USER_AGENT', ngx.var.request_uri, USER_AGENT, rule)
                    if config.config_waf_enable == "on" then
                        util.waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end

-- deny post
function _M.post_attack_check()
    if config.config_post_check == "on" then
        ngx.req.read_body()
        local POST_RULES = _M.get_rule('system/post.rule')
        local REQ_METHOD = ngx.req.get_method()
        local REQ_QUERY = nil
        
        -- get query string
        if REQ_METHOD == "GET" then
            REQ_QUERY = ngx.var.query_string
        else
            local content_type = ngx.req.get_headers()["content-type"]
            if content_type ~= nil and string.sub(content_type,1,16) == "application/json" then
                REQ_METHOD = "JSON"
                ngx.req.read_body()
                REQ_QUERY = ngx.req.get_body_data()
            elseif REQ_METHOD == "POST" or REQ_METHOD == "PUT" then
                if content_type ~= nil and string.sub(content_type,1,33) == "application/x-www-form-urlencoded" then
                    ngx.req.read_body()
                    REQ_QUERY = ngx.encode_args(ngx.req.get_post_args())
                elseif content_type ~= nil then
                    REQ_METHOD = "POST_RAW"
                    ngx.req.read_body()
                    REQ_QUERY = ngx.req.get_body_data()
                end
            end
        end
        
        -- do url-deocding all string
        REQ_QUERY = unescape(REQ_QUERY)
        
        -- matching and filtering from rule list
        for _, rule in pairs(POST_RULES) do
            if rule ~= "" and rulematch(REQ_QUERY, rule, "ijo") then
                _M.system_share_attack_info_incr("firewall_req_post")
                util.log_record(config.config_log_dir,'Deny_USER_POST_DATA', REQ_QUERY, "-", rule)
                if config.config_waf_enable == "on" then
                    util.waf_output()
                    return true
                end
            end
        end
    end
    return false
end

-- start change to jinghuashuiyue mode, set in vhosts's location segument
function _M.start_jingshuishuiyue()
    local host = util.get_server_host()
    ngx.var.target = string.format("proxy_%s", host)
    if host and _M.bad_guy_check() then
        ngx.var.target = string.format("unreal_%s", host)
    end
end

-- waf start
function _M.check()
    _M.system_share_info_incr("firewall_req_total")
    if _M.white_ip_check() then
    elseif _M.white_url_check() then
    elseif _M.black_ip_check() then
    elseif _M.cc_attack_check() then
    elseif _M.header_check() then
    elseif _M.user_agent_attack_check() then
    elseif _M.referer_check() then
    elseif _M.url_attack_check() then
    elseif _M.cookie_attack_check() then
    elseif _M.url_args_attack_check() then
    elseif _M.post_attack_check() then
    else
        _M.system_share_info_incr("firewall_req_normal")
        return
    end
end

return _M
