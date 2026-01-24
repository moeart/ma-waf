-- API接口实现

local cjson = require("cjson")
local util = require("util")
local waf = require("waf")
local config = require("config")
local io = require("io")

-- 处理统计信息请求
local function handle_stats()
    local result = waf.system_share_info_readall()
    if result then
        -- 解码结果
        local util = require("util")
        local decoded = util.security_token_decode(result)
        if decoded then
            -- 提取JSON部分
            local json_start = string.find(decoded, "{")
            if json_start then
                local json_str = string.sub(decoded, json_start)
                local stats = cjson.decode(json_str)
                ngx.say(cjson.encode(stats))
                return
            end
        end
    end
    
    -- 返回默认统计数据
    local stats = {
        firewall_req_total = 0,
        firewall_req_normal = 0,
        firewall_req_attack = 0,
        firewall_req_white_ip = 0,
        firewall_req_white_url = 0,
        firewall_req_black_ip = 0
    }
    ngx.say(cjson.encode(stats))
end

-- 处理获取规则请求
local function handle_get_rules(rule_file)
    local rule_path = config.config_rule_dir .. "/" .. rule_file
    local file = io.open(rule_path, "r")
    if not file then
        ngx.status = 404
        ngx.say(cjson.encode({ error = "规则文件不存在" }))
        return
    end
    
    local content = file:read("*a")
    file:close()
    
    local rules = cjson.decode(content)
    local rule_items = {}
    for _, rule in ipairs(rules) do
        table.insert(rule_items, rule.RuleItem)
    end
    
    ngx.say(cjson.encode(rule_items))
end

-- 处理保存规则请求
local function handle_save_rules(rule_file)
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body)
    local rules = data.rules
    
    if not rules then
        ngx.status = 400
        ngx.say(cjson.encode({ error = "缺少规则数据" }))
        return
    end
    
    -- 转换为规则文件格式
    local rule_objects = {}
    for _, rule in ipairs(rules) do
        table.insert(rule_objects, { RuleItem = rule })
    end
    
    local rule_path = config.config_rule_dir .. "/" .. rule_file
    local file = io.open(rule_path, "w")
    if not file then
        ngx.status = 500
        ngx.say(cjson.encode({ error = "无法打开规则文件" }))
        return
    end
    
    file:write(cjson.encode(rule_objects))
    file:close()
    
    ngx.say(cjson.encode({ success = true, message = "规则保存成功" }))
end

-- 处理日志设置请求
local function handle_log_settings()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body)
    
    if data and data.enabled ~= nil then
        -- 保存到配置文件
        local config_path = "D:/BtNginxLua/moewaf/config.lua"
        local file = io.open(config_path, "r")
        if file then
            local content = file:read("*a")
            file:close()
            
            -- 更新配置
            local enabled_value = data.enabled and "on" or "off"
            content = string.gsub(content, 'config_log_whitelist_enable = "[^"]*"', 'config_log_whitelist_enable = "' .. enabled_value .. '"')
            
            -- 写回文件
            local file = io.open(config_path, "w")
            if file then
                file:write(content)
                file:close()
                ngx.say(cjson.encode({ success = true, message = "日志设置保存成功" }))
                return
            end
        end
    end
    
    ngx.say(cjson.encode({ success = false, message = "日志设置保存失败" }))
end

-- 处理获取配置请求
local function handle_get_config()
    local config_path = "D:/BtNginxLua/moewaf/config.lua"
    local file = io.open(config_path, "r")
    if not file then
        ngx.status = 500
        ngx.say(cjson.encode({ error = "无法打开配置文件" }))
        return
    end
    
    local content = file:read("*a")
    file:close()
    
    -- 解析配置文件
    local config_data = {}
    
    -- 提取配置项
    config_data.config_waf_enable = content:match('config_waf_enable%s*=%s*"([^"]*)"')
    config_data.config_log_dir = content:match('config_log_dir%s*=%s*"([^"]*)"')
    config_data.config_rule_dir = content:match('config_rule_dir%s*=%s*"([^"]*)"')
    config_data.config_header_check = content:match('config_header_check%s*=%s*"([^"]*)"')
    config_data.config_referer_check = content:match('config_referer_check%s*=%s*"([^"]*)"')
    config_data.config_white_url_check = content:match('config_white_url_check%s*=%s*"([^"]*)"')
    config_data.config_white_ip_check = content:match('config_white_ip_check%s*=%s*"([^"]*)"')
    config_data.config_black_ip_check = content:match('config_black_ip_check%s*=%s*"([^"]*)"')
    config_data.config_url_check = content:match('config_url_check%s*=%s*"([^"]*)"')
    config_data.config_url_args_check = content:match('config_url_args_check%s*=%s*"([^"]*)"')
    config_data.config_user_agent_check = content:match('config_user_agent_check%s*=%s*"([^"]*)"')
    config_data.config_cookie_check = content:match('config_cookie_check%s*=%s*"([^"]*)"')
    config_data.config_post_check = content:match('config_post_check%s*=%s*"([^"]*)"')
    config_data.config_cc_check = content:match('config_cc_check%s*=%s*"([^"]*)"')
    config_data.config_cc_mode = content:match('config_cc_mode%s*=%s*"([^"]*)"')
    config_data.config_cc_rate_ip = content:match('config_cc_rate_ip%s*=%s*"([^"]*)"')
    config_data.config_cc_rate_ipurl = content:match('config_cc_rate_ipurl%s*=%s*"([^"]*)"')
    config_data.config_waf_model = content:match('config_waf_model%s*=%s*"([^"]*)"')
    config_data.config_waf_redirect_url = content:match('config_waf_redirect_url%s*=%s*"([^"]*)"')
    config_data.firewall_security_token = content:match('firewall_security_token%s*=%s*"([^"]*)"')
    config_data.firewall_security_table = content:match('firewall_security_table%s*=%s*"([^"]*)"')
    
    ngx.say(cjson.encode(config_data))
end

-- 处理保存配置请求
local function handle_save_config()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body)
    
    if not data then
        ngx.status = 400
        ngx.say(cjson.encode({ success = false, message = "缺少配置数据" }))
        return
    end
    
    local config_path = "D:/BtNginxLua/moewaf/config.lua"
    local file = io.open(config_path, "r")
    if not file then
        ngx.status = 500
        ngx.say(cjson.encode({ success = false, message = "无法打开配置文件" }))
        return
    end
    
    local content = file:read("*a")
    file:close()
    
    -- 更新配置项
    if data.config_waf_enable then
        content = string.gsub(content, 'config_waf_enable%s*=%s*"[^"]*"', 'config_waf_enable = "' .. data.config_waf_enable .. '"')
    end
    if data.config_log_dir then
        content = string.gsub(content, 'config_log_dir%s*=%s*"[^"]*"', 'config_log_dir = "' .. data.config_log_dir .. '"')
    end
    if data.config_rule_dir then
        content = string.gsub(content, 'config_rule_dir%s*=%s*"[^"]*"', 'config_rule_dir = "' .. data.config_rule_dir .. '"')
    end
    if data.config_header_check then
        content = string.gsub(content, 'config_header_check%s*=%s*"[^"]*"', 'config_header_check = "' .. data.config_header_check .. '"')
    end
    if data.config_referer_check then
        content = string.gsub(content, 'config_referer_check%s*=%s*"[^"]*"', 'config_referer_check = "' .. data.config_referer_check .. '"')
    end
    if data.config_white_url_check then
        content = string.gsub(content, 'config_white_url_check%s*=%s*"[^"]*"', 'config_white_url_check = "' .. data.config_white_url_check .. '"')
    end
    if data.config_white_ip_check then
        content = string.gsub(content, 'config_white_ip_check%s*=%s*"[^"]*"', 'config_white_ip_check = "' .. data.config_white_ip_check .. '"')
    end
    if data.config_black_ip_check then
        content = string.gsub(content, 'config_black_ip_check%s*=%s*"[^"]*"', 'config_black_ip_check = "' .. data.config_black_ip_check .. '"')
    end
    if data.config_url_check then
        content = string.gsub(content, 'config_url_check%s*=%s*"[^"]*"', 'config_url_check = "' .. data.config_url_check .. '"')
    end
    if data.config_url_args_check then
        content = string.gsub(content, 'config_url_args_check%s*=%s*"[^"]*"', 'config_url_args_check = "' .. data.config_url_args_check .. '"')
    end
    if data.config_user_agent_check then
        content = string.gsub(content, 'config_user_agent_check%s*=%s*"[^"]*"', 'config_user_agent_check = "' .. data.config_user_agent_check .. '"')
    end
    if data.config_cookie_check then
        content = string.gsub(content, 'config_cookie_check%s*=%s*"[^"]*"', 'config_cookie_check = "' .. data.config_cookie_check .. '"')
    end
    if data.config_post_check then
        content = string.gsub(content, 'config_post_check%s*=%s*"[^"]*"', 'config_post_check = "' .. data.config_post_check .. '"')
    end
    if data.config_cc_check then
        content = string.gsub(content, 'config_cc_check%s*=%s*"[^"]*"', 'config_cc_check = "' .. data.config_cc_check .. '"')
    end
    if data.config_cc_mode then
        content = string.gsub(content, 'config_cc_mode%s*=%s*"[^"]*"', 'config_cc_mode = "' .. data.config_cc_mode .. '"')
    end
    if data.config_cc_rate_ip then
        content = string.gsub(content, 'config_cc_rate_ip%s*=%s*"[^"]*"', 'config_cc_rate_ip = "' .. data.config_cc_rate_ip .. '"')
    end
    if data.config_cc_rate_ipurl then
        content = string.gsub(content, 'config_cc_rate_ipurl%s*=%s*"[^"]*"', 'config_cc_rate_ipurl = "' .. data.config_cc_rate_ipurl .. '"')
    end
    if data.config_waf_model then
        content = string.gsub(content, 'config_waf_model%s*=%s*"[^"]*"', 'config_waf_model = "' .. data.config_waf_model .. '"')
    end
    if data.config_waf_redirect_url then
        content = string.gsub(content, 'config_waf_redirect_url%s*=%s*"[^"]*"', 'config_waf_redirect_url = "' .. data.config_waf_redirect_url .. '"')
    end
    if data.firewall_security_token then
        content = string.gsub(content, 'firewall_security_token%s*=%s*"[^"]*"', 'firewall_security_token = "' .. data.firewall_security_token .. '"')
    end
    if data.firewall_security_table then
        content = string.gsub(content, 'firewall_security_table%s*=%s*"[^"]*"', 'firewall_security_table = "' .. data.firewall_security_table .. '"')
    end
    
    -- 写回文件
    local file = io.open(config_path, "w")
    if not file then
        ngx.status = 500
        ngx.say(cjson.encode({ success = false, message = "无法写入配置文件" }))
        return
    end
    
    file:write(content)
    file:close()
    
    ngx.say(cjson.encode({ success = true, message = "配置保存成功" }))
end

-- 处理重启Nginx请求
local function handle_restart_nginx()
    local os = require("os")
    
    -- 尝试执行重启命令
    local handle = io.popen("nginx -s reload 2>&1")
    if handle then
        local result = handle:read("*a")
        handle:close()
        
        if result and result == "" then
            ngx.say(cjson.encode({ success = true, message = "Nginx重新加载成功" }))
        else
            ngx.say(cjson.encode({ success = false, message = "Nginx重新加载失败: " .. (result or "未知错误") }))
        end
    else
        ngx.say(cjson.encode({ success = false, message = "无法执行Nginx重启命令，请手动重启Nginx" }))
    end
end

-- 处理API请求
local function handle_request()
    local uri = ngx.var.uri
    local method = ngx.req.get_method()
    
    -- 统计信息接口
    if uri == "/api/stats" and method == "GET" then
        handle_stats()
        return
    end
    
    -- 规则管理接口
    local rule_match = ngx.re.match(uri, "/api/rules/(.*)")
    if rule_match then
        local rule_file = rule_match[1]
        if method == "GET" then
            handle_get_rules(rule_file)
        elseif method == "POST" then
            handle_save_rules(rule_file)
        end
        return
    end
    
    -- 日志设置接口
    if uri == "/api/log-settings" and method == "POST" then
        handle_log_settings()
        return
    end
    
    -- 配置管理接口
    if uri == "/api/config" and method == "GET" then
        handle_get_config()
        return
    end
    
    if uri == "/api/config" and method == "POST" then
        handle_save_config()
        return
    end
    
    -- 重启Nginx接口
    if uri == "/api/restart-nginx" and method == "POST" then
        handle_restart_nginx()
        return
    end
    
    -- 404处理
    ngx.status = 404
    ngx.say(cjson.encode({ error = "接口不存在" }))
end

-- 执行请求处理
handle_request()