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
    
    -- 404处理
    ngx.status = 404
    ngx.say(cjson.encode({ error = "接口不存在" }))
end

-- 执行请求处理
handle_request()