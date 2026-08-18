local cjson = require("cjson")
local io = require("io")
local waf = require("waf")
local iputils = require("iputils")

local _M = {}

local VERSION = "1.0.0"
local PROJECT = "MA-WAF"
local BRAND_COLOR = "#3b82f6"

local src = debug.getinfo(1, "S").source
local plugin_dir = (src:sub(1, 1) == "@" and src:sub(2) or src):match("^(.*)[/\\][^/\\]+$") or "."

local config
do
    local f = io.open(plugin_dir .. "/config.json", "r")
    if not f then error("webui: config.json not found: " .. plugin_dir) end
    local content = f:read("*a"); f:close()
    config = cjson.decode(content)
    for k in pairs(config) do
        if k:sub(1, 3) == "___" then config[k] = nil end
    end
end

-- ============================================================
-- Utility
-- ============================================================

local function get_client_ip()
    return ngx.req.get_headers()["X-Real-Ip"]
        or ngx.req.get_headers()["X-Forwarded-For"]
        or ngx.var.remote_addr
        or ""
end

local function ip_in_list(ip, list)
    if not list then return false end
    for _, entry in ipairs(list) do
        if entry ~= "" then
            if entry == ip then return true end
            local ok, _ = pcall(function() return iputils.ip_in_cidr(ip, entry) end)
            if ok then return true end
        end
    end
    return false
end

local function admin_check()
    local wl = config.admin_whitelist
    if not wl or #wl == 0 then return true end
    return ip_in_list(get_client_ip(), wl)
end

local function json_response(obj, status)
    ngx.status = status or 200
    ngx.header["Content-Type"] = "application/json; charset=utf-8"
    ngx.header["Cache-Control"] = "no-store, no-cache, must-revalidate"
    ngx.header["Pragma"] = "no-cache"
    ngx.say(cjson.encode(obj))
    ngx.exit(status or 200)
end

local function html_response(html)
    ngx.status = 200
    ngx.header["Content-Type"] = "text/html; charset=utf-8"
    ngx.header["Cache-Control"] = "no-store, no-cache, must-revalidate"
    ngx.header["Pragma"] = "no-cache"
    ngx.say(html)
    ngx.exit(200)
end

local function read_rule_file(file)
    local path = plugin_dir .. "/rules/" .. file
    local f = io.open(path, "r")
    if not f then return {} end
    local content = f:read("*a")
    f:close()
    if not content or content == "" then return {} end
    local ok, rules = pcall(cjson.decode, content)
    if not ok or type(rules) ~= "table" then return {} end
    return rules
end

local function write_rule_file(file, rules)
    local path = plugin_dir .. "/rules/" .. file
    local tmp_path = path .. ".tmp"
    local json = cjson.encode(rules)
    
    local f, err = io.open(tmp_path, "w")
    if not f then return false, "写入临时文件失败: " .. (err or "unknown") end
    f:write(json)
    f:close()
    
    local ok, err = os.rename(tmp_path, path)
    if not ok then
        local f2, err2 = io.open(path, "w")
        if f2 then
            f2:write(json)
            f2:close()
            pcall(os.remove, tmp_path)
        else
            return false, "写入原文件失败: " .. (err2 or "unknown")
        end
    end
    return true
end

local RULE_FILES_META = {
    { name = "blackip.rule", title = "黑名单 IP", kind = "ip", desc = "IP 或 CIDR，命中即 403", ruletype = "blackip" },
    { name = "whiteip.rule", title = "白名单 IP", kind = "ip", desc = "IP 或 CIDR，命中跳过全部检测", ruletype = "whiteip" },
    { name = "whiteurl.rule", title = "白名单 URL", kind = "regex", desc = "host+uri 正则，命中放行", ruletype = "whiteurl" },
    { name = "useragentforcc.rule", title = "CC-UA 白名单", kind = "regex", desc = "UA 正则，命中后 CC 切 ipurl 模式", ruletype = "cc_ua_ipurl" },
    { name = "system/header.rule", title = "Header 规则", kind = "regex", desc = "请求头名正则匹配", ruletype = "deny_header" },
    { name = "system/referer.rule", title = "Referer 规则", kind = "regex", desc = "Referer 正则匹配", ruletype = "deny_referer" },
    { name = "system/url.rule", title = "URL 规则", kind = "regex", desc = "请求 URI 正则匹配", ruletype = "deny_url" },
    { name = "system/args.rule", title = "参数规则", kind = "regex", desc = "URL 参数值正则匹配", ruletype = "deny_args" },
    { name = "system/useragent.rule", title = "User-Agent 规则", kind = "regex", desc = "User-Agent 正则匹配", ruletype = "deny_ua" },
    { name = "system/cookie.rule", title = "Cookie 规则", kind = "regex", desc = "Cookie 正则匹配", ruletype = "deny_cookie" },
    { name = "system/post.rule", title = "POST 规则", kind = "regex", desc = "POST body 正则匹配", ruletype = "deny_post" },
}

local RULE_FILES_META_BY_NAME = {}
for _, v in ipairs(RULE_FILES_META) do RULE_FILES_META_BY_NAME[v.name] = v end

local RULE_FILES_WHITELIST = {}
for _, v in ipairs(RULE_FILES_META) do RULE_FILES_WHITELIST[v.name] = true end

local function generate_next_id()
    local max_id = 0
    for _, meta in ipairs(RULE_FILES_META) do
        local rules = read_rule_file(meta.name)
        for _, rule in ipairs(rules) do
            if type(rule) == "table" and rule.Id and rule.Id > max_id then
                max_id = rule.Id
            end
        end
    end
    return max_id + 1
end

local function validate_rule(rule, kind)
    if not rule or type(rule) ~= "string" or rule == "" then
        return "规则内容不能为空"
    end
    if #rule > 2048 then
        return "规则内容过长"
    end
    if kind == "ip" then
        local lower, err = iputils.parse_cidr(rule)
        if not lower then
            return "无效的 IP/CIDR: " .. rule
        end
    else
        local _, err = ngx.re.find("ruletest", rule, "jo")
        if err then
            return "无效的正则表达式: " .. rule .. " (" .. tostring(err) .. ")"
        end
    end
    return nil
end

-- ============================================================
-- HTML Templates
-- ============================================================

local CSS = [[
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --brand:]] .. BRAND_COLOR .. [[;
  --brand-light:#eff6ff;
  --bg:#f8fafc;
  --card:#ffffff;
  --text:#1e293b;
  --text2:#64748b;
  --border:#e2e8f0;
  --success:#10b981;
  --danger:#ef4444;
  --warning:#f59e0b;
  --radius:12px;
  --shadow:0 1px 3px rgba(0,0,0,.08),0 1px 2px rgba(0,0,0,.06)
}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.6}
a{color:var(--brand);text-decoration:none}
nav{position:fixed;top:0;left:0;right:0;height:56px;background:#fff;border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 24px;z-index:100;box-shadow:0 1px 3px rgba(0,0,0,.05)}
nav .brand{font-size:18px;font-weight:700;color:var(--brand);margin-right:32px;white-space:nowrap}
nav .brand span{font-size:12px;font-weight:400;color:var(--text2);margin-left:8px}
nav .nav-links{display:flex;gap:4px}
nav .nav-links a{padding:8px 16px;border-radius:8px;color:var(--text2);font-size:14px;font-weight:500;transition:all .15s}
nav .nav-links a:hover{background:var(--brand-light);color:var(--brand)}
nav .nav-links a.active{background:var(--brand);color:#fff}
main{max-width:1200px;margin:0 auto;padding:72px 24px 40px}
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
.metric-card{background:var(--card);border-radius:var(--radius);padding:20px 24px;box-shadow:var(--shadow);border:1px solid var(--border)}
.metric-card .label{font-size:13px;color:var(--text2);margin-bottom:4px}
.metric-card .value{font-size:28px;font-weight:700}
.metric-card.blue .value{color:var(--brand)}
.metric-card.green .value{color:var(--success)}
.metric-card.red .value{color:var(--danger)}
.metric-card.yellow .value{color:var(--warning)}
.charts{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px}
.chart-card{background:var(--card);border-radius:var(--radius);padding:20px;box-shadow:var(--shadow);border:1px solid var(--border)}
.chart-card h3{font-size:15px;font-weight:600;margin-bottom:12px;color:var(--text)}
.chart-box{width:100%;height:300px}
.section{background:var(--card);border-radius:var(--radius);padding:24px;box-shadow:var(--shadow);border:1px solid var(--border);margin-bottom:24px}
.section h3{font-size:15px;font-weight:600;margin-bottom:16px;color:var(--text)}
.detail-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px}
.detail-item{display:flex;justify-content:space-between;padding:10px 14px;background:var(--bg);border-radius:8px;font-size:13px}
.detail-item .k{color:var(--text2)}
.detail-item .v{font-weight:600}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:10px 14px;background:var(--bg);font-weight:600;color:var(--text2);border-bottom:1px solid var(--border)}
td{padding:10px 14px;border-bottom:1px solid var(--border)}
tr:last-child td{border-bottom:none}
.tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:500}
.tag-green{background:#d1fae5;color:#065f46}
.tag-red{background:#fee2e2;color:#991b1b}
.form-group{margin-bottom:20px}
.form-group label{display:block;font-size:13px;font-weight:600;color:var(--text2);margin-bottom:6px}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:16px}
input[type=text],input[type=number],select{width:100%;padding:10px 14px;border:1px solid var(--border);border-radius:8px;font-size:14px;background:var(--card);color:var(--text);transition:border-color .15s}
input:focus,select:focus{outline:none;border-color:var(--brand);box-shadow:0 0 0 3px rgba(59,130,246,.1)}
.switch-row{display:flex;flex-wrap:wrap;gap:8px 24px}
.switch-item{display:flex;align-items:center;gap:8px;font-size:14px;min-width:180px}
.switch-item input[type=checkbox]{width:18px;height:18px;accent-color:var(--brand)}
.btn{padding:10px 24px;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;transition:all .15s}
.btn-primary{background:var(--brand);color:#fff}
.btn-primary:hover{opacity:.9}
.btn-secondary{background:var(--bg);color:var(--text);border:1px solid var(--border)}
.btn-secondary:hover{background:var(--border)}
.btn-group{display:flex;gap:12px;margin-top:24px}
.tag-list{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:8px}
.tag-list .tag{cursor:pointer;padding:4px 10px;font-size:12px}
.tag-list .tag:hover{opacity:.7}
.toast{position:fixed;bottom:24px;right:24px;padding:14px 20px;border-radius:8px;color:#fff;font-size:14px;font-weight:500;z-index:200;transform:translateY(100px);opacity:0;transition:all .3s}
.toast.show{transform:translateY(0);opacity:1}
.toast-ok{background:var(--success)}
.toast-err{background:var(--danger)}
@media(max-width:768px){
  .metrics{grid-template-columns:repeat(2,1fr)}
  .charts{grid-template-columns:1fr}
  .form-row{grid-template-columns:1fr}
  nav .brand span{display:none}
}
@media(max-width:480px){
  .metrics{grid-template-columns:1fr}
}
</style>
]]

local NAV = [[
<nav>
  <div class="brand">]] .. PROJECT .. [[<span>v]] .. VERSION .. [[</span></div>
  <div class="nav-links">
    <a href="/cgi-waf/status" id="nav-status">状态</a>
    <a href="/cgi-waf/config" id="nav-config">配置</a>
    <a href="/cgi-waf/rules" id="nav-rules">规则</a>
  </div>
</nav>
]]

local SHARED_JS = [[
<script>
function toast(msg,ok){
  var d=document.createElement('div');
  d.className='toast '+(ok?'toast-ok':'toast-err');
  d.textContent=msg;
  document.body.appendChild(d);
  requestAnimationFrame(function(){d.classList.add('show')});
  setTimeout(function(){d.classList.remove('show');setTimeout(function(){d.remove()},300)},3000);
}
</script>
]]

-- ============================================================
-- Status Page
-- ============================================================

local STATUS_HTML = [[<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>]] .. PROJECT .. [[ - 状态</title>
<script src="https://cdn.jsdelivr.net/npm/echarts@5/dist/echarts.min.js"></script>
]] .. CSS .. [[
</head><body>
]] .. NAV .. [[
<main>
  <div class="metrics">
    <div class="metric-card blue"><div class="label">请求总数</div><div class="value" id="m-total">-</div></div>
    <div class="metric-card green"><div class="label">正常请求</div><div class="value" id="m-normal">-</div></div>
    <div class="metric-card red"><div class="label">攻击请求</div><div class="value" id="m-attack">-</div></div>
    <div class="metric-card yellow"><div class="label">拦截率</div><div class="value" id="m-rate">-</div></div>
  </div>
  <div class="charts">
    <div class="chart-card"><h3>请求类型分布</h3><div class="chart-box" id="chart-pie"></div></div>
    <div class="chart-card"><h3>攻击类型分布</h3><div class="chart-box" id="chart-attack"></div></div>
  </div>
  <div class="section">
    <h3>攻击分类明细</h3>
    <div class="detail-grid" id="attack-details"></div>
  </div>
  <div class="section">
    <h3>系统信息</h3>
    <div class="detail-grid" id="sys-info"></div>
  </div>
</main>
]] .. SHARED_JS .. [[
<script>
var pieChart,attackChart;
function initCharts(){
  pieChart=echarts.init(document.getElementById('chart-pie'));
  attackChart=echarts.init(document.getElementById('chart-attack'));
  window.addEventListener('resize',function(){pieChart.resize();attackChart.resize()});
}
function fmt(n){return n==null?'-':n.toLocaleString()}
function renderPie(d){
  pieChart.setOption({
    tooltip:{trigger:'item',formatter:'{b}: {c} ({d}%)'},
    color:['#3b82f6','#10b981','#f59e0b','#ef4444','#8b5cf6','#ec4899','#06b6d4'],
    series:[{type:'pie',radius:['40%','70%'],avoidLabelOverlap:true,
      itemStyle:{borderRadius:6,borderColor:'#fff',borderWidth:2},
      label:{show:true,formatter:'{b}\n{d}%',fontSize:12},
      data:d}]
  });
}
function renderAttack(d){
  if(!d.length){attackChart.setOption({title:{text:'暂无攻击数据',left:'center',top:'center',textStyle:{color:'#94a3b8',fontSize:14}}});return}
  attackChart.setOption({
    tooltip:{trigger:'item',formatter:'{b}: {c} ({d}%)'},
    color:['#ef4444','#f97316','#f59e0b','#ec4899','#8b5cf6','#06b6d4','#14b8a6'],
    series:[{type:'pie',radius:['40%','70%'],
      itemStyle:{borderRadius:6,borderColor:'#fff',borderWidth:2},
      label:{show:true,formatter:'{b}\n{d}%',fontSize:12},
      data:d}]
  });
}
function renderDetails(s){
  var items=[
    ['Header',s.firewall_req_header],['Referer',s.firewall_req_referer],
    ['URL',s.firewall_req_url],['URL 参数',s.firewall_req_url_args],
    ['User-Agent',s.firewall_req_ua],['Cookie',s.firewall_req_cookie],
    ['POST',s.firewall_req_post],['CC',s.firewall_req_cc],
    ['黑名单 IP',s.firewall_req_black_ip]
  ];
  var h='';
  items.forEach(function(i){
    h+='<div class="detail-item"><span class="k">'+i[0]+'</span><span class="v">'+fmt(i[1])+'</span></div>';
  });
  document.getElementById('attack-details').innerHTML=h;
}
function renderSys(s){
  var items=[
    ['白名单 IP 命中',s.firewall_req_white_ip],['白名单 URL 命中',s.firewall_req_white_url],
    ['Reload 次数',s.firewall_reload_count],['版本',']] .. VERSION .. [[']
  ];
  var h='';
  items.forEach(function(i){
    h+='<div class="detail-item"><span class="k">'+i[0]+'</span><span class="v">'+fmt(i[1])+'</span></div>';
  });
  document.getElementById('sys-info').innerHTML=h;
}
function refresh(){
  fetch('/cgi-waf/api/stats').then(function(r){return r.json()}).then(function(s){
    var t=s.firewall_req_total||0,a=s.firewall_req_attack||0,n=s.firewall_req_normal||0;
    document.getElementById('m-total').textContent=fmt(t);
    document.getElementById('m-normal').textContent=fmt(n);
    document.getElementById('m-attack').textContent=fmt(a);
    document.getElementById('m-rate').textContent=t>0?(a/t*100).toFixed(1)+'%':'0%';
    renderPie([
      {value:n,name:'正常请求'},{value:s.firewall_req_white_ip||0,name:'白名单 IP'},
      {value:s.firewall_req_white_url||0,name:'白名单 URL'},{value:a,name:'攻击请求'}
    ]);
    var ad=[
      {value:s.firewall_req_header||0,name:'Header'},{value:s.firewall_req_referer||0,name:'Referer'},
      {value:s.firewall_req_url||0,name:'URL'},{value:s.firewall_req_url_args||0,name:'URL 参数'},
      {value:s.firewall_req_ua||0,name:'User-Agent'},{value:s.firewall_req_cookie||0,name:'Cookie'},
      {value:s.firewall_req_post||0,name:'POST'},{value:s.firewall_req_cc||0,name:'CC'}
    ].filter(function(x){return x.value>0});
    renderAttack(ad);
    renderDetails(s);
    renderSys(s);
  }).catch(function(){});
}
document.getElementById('nav-status').classList.add('active');
initCharts();refresh();setInterval(refresh,10000);
</script>
</body></html>]]

-- ============================================================
-- Config Page
-- ============================================================

local CONFIG_HTML = [[<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>]] .. PROJECT .. [[ - 配置</title>
]] .. CSS .. [[
</head><body>
]] .. NAV .. [[
<main>
  <div class="section">
    <h3>基础设置</h3>
    <div class="form-row">
      <div class="form-group">
        <label>WAF 总开关</label>
        <select id="cfg-waf-enable"><option value="on">启用</option><option value="off">禁用</option></select>
      </div>
      <div class="form-group">
        <label>拦截模式</label>
        <select id="cfg-waf-model">
          <option value="reset">重置连接</option><option value="redirect">重定向</option>
          <option value="html">返回 HTML</option><option value="jinghuashuiyue">静画水月</option>
        </select>
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label>重定向 URL</label>
        <input type="text" id="cfg-redirect-url" placeholder="http://...">
      </div>
      <div class="form-group">
        <label>过期时间(秒)</label>
        <input type="number" id="cfg-expire-time" value="600">
      </div>
    </div>
  </div>

  <div class="section">
    <h3>检测开关</h3>
    <div class="switch-row" id="toggle-grid"></div>
  </div>

  <div class="section">
    <h3>CC 防护设置</h3>
    <div class="form-row">
      <div class="form-group">
        <label>模式</label>
        <select id="cfg-cc-mode"><option value="ip">IP 模式</option><option value="ipurl">IP+URL 模式</option></select>
      </div>
      <div class="form-group">
        <label>IP 限流 (次数/秒数)</label>
        <input type="text" id="cfg-cc-rate-ip" placeholder="1000/600">
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label>IP+URL 限流 (次数/秒数)</label>
        <input type="text" id="cfg-cc-rate-ipurl" placeholder="20/60">
      </div>
      <div class="form-group"></div>
    </div>
  </div>

  <div class="section">
    <h3>管理员白名单</h3>
    <p style="font-size:13px;color:var(--text2);margin-bottom:12px">允许访问此管理面板的 IP 地址（支持 CIDR），留空则允许所有</p>
    <div class="tag-list" id="whitelist-tags"></div>
    <div style="display:flex;gap:8px">
      <input type="text" id="wl-input" placeholder="输入 IP 或 CIDR，回车添加" style="flex:1">
      <button class="btn btn-secondary" onclick="addWl()">添加</button>
    </div>
  </div>

  <div class="btn-group">
    <button class="btn btn-primary" onclick="saveConfig()">保存配置</button>
  </div>
</main>
]] .. SHARED_JS .. [[
<script>
var toggles=[
  ['config_header_check','Header 检测'],['config_referer_check','Referer 检测'],
  ['config_url_check','URL 检测'],['config_url_args_check','URL 参数检测'],
  ['config_user_agent_check','User-Agent 检测'],['config_cookie_check','Cookie 检测'],
  ['config_post_check','POST 检测'],['config_cc_check','CC 攻击防护'],
  ['config_white_ip_check','白名单 IP'],['config_white_url_check','白名单 URL'],
  ['config_black_ip_check','黑名单 IP'],  ['logging_skip_whitelist','日志白名单过滤']
];
var tg=document.getElementById('toggle-grid');
toggles.forEach(function(t){
  tg.innerHTML+='<label class="switch-item"><input type="checkbox" id="'+t[0]+'">'+t[1]+'</label>';
});
var wlData=[];
function renderWl(){
  var c=document.getElementById('whitelist-tags');c.innerHTML='';
  wlData.forEach(function(ip,i){
    var s=document.createElement('span');s.className='tag';s.textContent=ip;
    s.style.background='var(--brand-light)';s.style.color='var(--brand)';
    s.onclick=function(){wlData.splice(i,1);renderWl()};
    c.appendChild(s);
  });
}
function addWl(){
  var inp=document.getElementById('wl-input');
  var v=inp.value.trim();
  if(v&&wlData.indexOf(v)===-1){wlData.push(v);renderWl()}
  inp.value='';
}
document.getElementById('wl-input').addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();addWl()}});
function loadConfig(){
  fetch('/cgi-waf/api/config').then(function(r){return r.json()}).then(function(c){
    document.getElementById('cfg-waf-enable').value=c.config_waf_enable||'on';
    document.getElementById('cfg-waf-model').value=c.config_waf_model||'reset';
    document.getElementById('cfg-redirect-url').value=c.config_waf_redirect_url||'';
    document.getElementById('cfg-expire-time').value=c.config_expire_time||600;
    document.getElementById('cfg-cc-mode').value=c.config_cc_mode||'ip';
    document.getElementById('cfg-cc-rate-ip').value=c.config_cc_rate_ip||'';
    document.getElementById('cfg-cc-rate-ipurl').value=c.config_cc_rate_ipurl||'';
    toggles.forEach(function(t){var _k=t[0];var el=document.getElementById(_k);if(el)el.checked=c[_k]==='on'});
    wlData=c.admin_whitelist||[];renderWl();
  }).catch(function(e){toast('加载配置失败: '+e.message,false)});
}
function saveConfig(){
  var cfg={};
  cfg.config_waf_enable=document.getElementById('cfg-waf-enable').value;
  cfg.config_waf_model=document.getElementById('cfg-waf-model').value;
  cfg.config_waf_redirect_url=document.getElementById('cfg-redirect-url').value;
  cfg.config_expire_time=parseInt(document.getElementById('cfg-expire-time').value)||600;
  cfg.config_cc_mode=document.getElementById('cfg-cc-mode').value;
  cfg.config_cc_rate_ip=document.getElementById('cfg-cc-rate-ip').value;
  cfg.config_cc_rate_ipurl=document.getElementById('cfg-cc-rate-ipurl').value;
  cfg.admin_whitelist=wlData;
  toggles.forEach(function(t){var _k=t[0];var el=document.getElementById(_k);cfg[_k]=el&&el.checked?'on':'off'});
  fetch('/cgi-waf/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(cfg)})
    .then(function(r){return r.json()}).then(function(d){
      if(d.success)toast('配置已保存，重启 Nginx 后生效',true);
      else toast('保存失败: '+(d.message||''),false);
    }).catch(function(e){toast('保存失败: '+e.message,false)});
}
document.getElementById('nav-config').classList.add('active');
loadConfig();
</script>
</body></html>]]

-- ============================================================
-- Rules Page
-- ============================================================

local RULES_CSS = [[
<style>
  .rule-tabs { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 20px; }
  .rule-tab { padding: 8px 16px; border-radius: 8px; background: var(--bg); border: 1px solid var(--border); cursor: pointer; font-size: 13px; font-weight: 500; }
  .rule-tab:hover { background: var(--border); }
  .rule-tab.active { background: var(--brand); color: #fff; border-color: var(--brand); }
  .rule-header { margin-bottom: 16px; }
  .rule-desc { font-size: 13px; color: var(--text2); margin-bottom: 8px; }
  .rule-table { width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 16px; }
  .rule-table th { text-align: left; padding: 10px 14px; background: var(--bg); font-weight: 600; color: var(--text2); border-bottom: 1px solid var(--border); }
  .rule-table td { padding: 10px 14px; border-bottom: 1px solid var(--border); }
  .rule-table input { width: 100%; padding: 6px 8px; border: 1px solid var(--border); border-radius: 4px; }
  .btn-danger { background: var(--danger); color: #fff; }
  .rule-add-area { margin-top: 16px; padding: 16px; background: var(--bg); border-radius: 8px; border: 1px dashed var(--border); }
  .invalid input { border-color: var(--danger); }
  .error-msg { color: var(--danger); font-size: 12px; margin-top: 4px; }
  .sticky-bottom { position: fixed; bottom: 0; left: 0; right: 0; background: #fff; padding: 16px 24px; box-shadow: 0 -2px 4px rgba(0,0,0,0.05); z-index: 100; display: flex; justify-content: space-between; align-items: center; }
</style>
]]

local RULES_HTML = [[<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>]] .. PROJECT .. [[ - 规则</title>
<style>body{margin-bottom:80px}</style>
]] .. CSS .. RULES_CSS .. [[
</head><body>
]] .. NAV .. [[
<main>
  <div class="section">
    <div class="rule-tabs" id="rule-tabs"></div>
    <div id="rule-content"></div>
  </div>
</main>
<div class="sticky-bottom" id="rule-footer">
  <div id="rule-status" style="font-size:13px;font-weight:500">加载中...</div>
  <div style="display:flex;gap:12px">
    <button class="btn btn-secondary" onclick="loadRules()">放弃更改</button>
    <button class="btn btn-primary" id="save-rule-btn" disabled onclick="saveCurrentRule()">保存此文件</button>
  </div>
</div>
]] .. SHARED_JS .. [[
<script>
var META = [];
var allData = {};
var currentFile = null;
var hasChanges = false;

function init(){
  loadRules();
}

function loadRules(){
  fetch('/cgi-waf/api/rules').then(function(r){return r.json()}).then(function(d){
    META = d.files;
    META.forEach(function(f){ allData[f.name] = f.rules.slice(); });
    var container = document.getElementById('rule-tabs');
    while(container.firstChild) container.removeChild(container.firstChild);
    META.forEach(function(f){
      var btn = document.createElement('div');
      btn.className = 'rule-tab';
      btn.textContent = f.title;
      btn.onclick = function(){selectFile(f.name)};
      container.appendChild(btn);
    });
    if(currentFile && allData[currentFile]){
      selectFile(currentFile, true);
    } else if(META.length>0){
      selectFile(META[0].name);
    }
  }).catch(function(e){toast('加载规则失败: '+e.message, false)});
}

function selectFile(name, skipConfirm){
  if(!skipConfirm && hasChanges && !confirm('当前文件有未保存的更改，确定要切换吗？')) return;
  currentFile = name;
  hasChanges = false;
  updateFooter();
  var btns = document.querySelectorAll('.rule-tab');
  META.forEach(function(f, i){
    if(f.name===name) btns[i].classList.add('active');
    else btns[i].classList.remove('active');
  });
  renderTable();
}

function renderTable(){
  var file = META.find(function(f){return f.name===currentFile});
  var rules = allData[currentFile];
  
  var h = '<div class="rule-header">';
  h += '<h3 style="font-size:16px;margin-bottom:8px;color:var(--text)">' + file.title + '</h3>';
  h += '<p class="rule-desc">匹配对象：' + file.desc + '</p></div>';
  
  h += '<table class="rule-table"><thead><tr>';
  h += '<th style="width:40px">#</th>';
  h += '<th style="width:100px">Id</th>';
  h += '<th style="width:120px">RuleType</th>';
  h += '<th>RuleItem</th>';
  h += '<th style="width:120px">操作</th>';
  h += '</tr></thead><tbody>';
  
  rules.forEach(function(r, i){
    h += '<tr>';
    h += '<td>' + (i+1) + '</td>';
    h += '<td>' + (r.Id||'') + '</td>';
    h += '<td>' + (r.RuleType||'') + '</td>';
    h += '<td>' + escapeHtml(r.RuleItem) + '</td>';
    h += '<td><button class="btn btn-secondary" style="padding:4px 8px;margin-right:4px" onclick="editRule(' + i + ')">编辑</button>';
    h += '<button class="btn btn-danger" style="padding:4px 8px" onclick="deleteRule(' + i + ')">删除</button></td>';
    h += '</tr>';
  });
  h += '</tbody></table>';
  
  h += '<div class="rule-add-area">';
  h += '<div style="font-size:14px;font-weight:600;margin-bottom:12px">添加新规则</div>';
  h += '<div style="display:flex;gap:8px;align-items:center">';
  h += '<input id="new-item" placeholder="' + (file.kind==='ip'?'IP 或 CIDR':'正则表达式') + '" style="flex:1">';
  h += '<button class="btn btn-primary" onclick="addRule()">添加</button>';
  h += '</div></div>';
  
  document.getElementById('rule-content').innerHTML = h;
  validateNewInputs();
}

function escapeHtml(s){
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function editRule(idx){
  var r = allData[currentFile][idx];
  var table = document.querySelector('.rule-table tbody');
  var tr = table.children[idx];
  
  var h = '<td>' + (idx+1) + '</td>';
  h += '<td>' + (r.Id||'') + '</td>';
  h += '<td>' + (r.RuleType||'') + '</td>';
  h += '<td><input id="edit-item" value="' + escapeHtml(r.RuleItem) + '" style="width:100%"></td>';
  h += '<td><button class="btn btn-primary" style="padding:4px 8px;margin-right:4px" onclick="saveEdit(' + idx + ')">确定</button>';
  h += '<button class="btn btn-secondary" style="padding:4px 8px" onclick="renderTable()">取消</button></td>';
  
  tr.innerHTML = h;
}

function saveEdit(idx){
  var item = document.getElementById('edit-item').value.trim();
  if(!item){ toast('规则内容不能为空', false); return; }
  
  allData[currentFile][idx].RuleItem = item;
  hasChanges = true;
  updateFooter();
  renderTable();
}

function deleteRule(idx){
  if(!confirm('确定删除此规则？')) return;
  allData[currentFile].splice(idx, 1);
  hasChanges = true;
  updateFooter();
  renderTable();
}

function addRule(){
  var item = document.getElementById('new-item').value.trim();
  if(!item){ toast('规则内容不能为空', false); return; }
  
  allData[currentFile].push({RuleItem: item});
  hasChanges = true;
  updateFooter();
  
  document.getElementById('new-item').value = '';
  renderTable();
}

function updateFooter(){
  if(hasChanges){
    document.getElementById('rule-status').textContent = '当前文件有未保存的更改';
    document.getElementById('save-rule-btn').disabled = false;
  } else {
    document.getElementById('rule-status').textContent = '无更改';
    document.getElementById('save-rule-btn').disabled = true;
  }
}

function validateNewInputs(){
  var item = document.getElementById('new-item');
  if(item){
    item.onblur = function(){
      var val = this.value.trim();
      if(!val) return;
      var file = META.find(function(f){return f.name===currentFile});
      if(file.kind==='ip'){
        this.style.borderColor = /^\d+\.\d+\.\d+\.\d+(\/\d+)?$/.test(val) ? 'var(--success)' : 'var(--danger)';
      } else {
        try { new RegExp(val); this.style.borderColor = 'var(--success)'; }
        catch(e) { this.style.borderColor = 'var(--danger)'; }
      }
    };
    item.onkeydown = function(e){ if(e.key==='Enter'){e.preventDefault(); addRule();} };
  }
}

function saveCurrentRule(){
  if(!currentFile) return;
  fetch('/cgi-waf/api/rules?file=' + encodeURIComponent(currentFile), {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({rules: allData[currentFile]})
  }).then(function(r){return r.json()}).then(function(d){
    if(d.success){
      toast(d.message, true);
      hasChanges = false;
      updateFooter();
    } else {
      var msg = d.message || (d.errors ? d.errors.map(function(e){return '第'+e.index+'条: '+e.error}).join(', ') : '未知错误');
      toast('保存失败: ' + msg, false);
    }
  }).catch(function(e){toast('请求失败: '+e.message, false)});
}

document.getElementById('nav-rules').classList.add('active');
init();
</script>
</body></html>]]

-- ============================================================
-- API Handlers
-- ============================================================

local function handle_api_stats()
    local si = ngx.shared.waf
    if not si then return json_response({}) end
    local keys = {
        "firewall_req_total", "firewall_req_normal", "firewall_req_attack",
        "firewall_req_white_ip", "firewall_req_white_url", "firewall_req_black_ip",
        "firewall_req_header", "firewall_req_referer", "firewall_req_cc",
        "firewall_req_cookie", "firewall_req_url", "firewall_req_url_args",
        "firewall_req_ua", "firewall_req_post", "firewall_reload_count"
    }
    local stats = {}
    for _, key in ipairs(keys) do
        local val = si:get(key)
        stats[key] = val or 0
    end
    return json_response(stats)
end

local function handle_api_config_get()
    return json_response(config)
end

local function handle_api_config_save()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then return json_response({success = false, message = "请求体为空"}, 400) end

    local ok, data = pcall(cjson.decode, body)
    if not ok or type(data) ~= "table" then
        return json_response({success = false, message = "JSON 解析失败"}, 400)
    end

    for k, v in pairs(data) do
        config[k] = v
    end

    local json_path = plugin_dir .. "/config.json"
    local f = io.open(json_path, "w")
    if not f then return json_response({success = false, message = "写入配置文件失败"}, 500) end
    f:write(cjson.encode(config))
    f:close()
    return json_response({success = true, message = "配置已保存，重启 Nginx 后生效"})
end

local function handle_check(ip)
    if not ip or ip == "" then
        return json_response({error = "invalid_ip", message = "IP 地址不能为空"})
    end

    local result = {ip = ip, blocked = false, reason = nil, detail = nil}

    local black_rules = waf.get_rule("blackip.rule")
    if black_rules then
        for _, rule in ipairs(black_rules) do
            if rule ~= "" then
                local ok, match = pcall(function() return iputils.ip_in_cidr(ip, rule) end)
                if ok and match then
                    result.blocked = true
                    result.reason = "black_ip"
                    result.detail = "IP 在黑名单中 (规则: " .. rule .. ")"
                    return json_response(result)
                end
            end
        end
    end

    local white_rules = waf.get_rule("whiteip.rule")
    if white_rules then
        for _, rule in ipairs(white_rules) do
            if rule ~= "" then
                local ok, match = pcall(function() return iputils.ip_in_cidr(ip, rule) end)
                if ok and match then
                    result.reason = "whitelisted"
                    result.detail = "IP 在白名单中 (规则: " .. rule .. ")"
                    return json_response(result)
                end
            end
        end
    end

    local waf_dict = ngx.shared.waf
    if waf_dict then
        local count = waf_dict:get("bg:" .. ip)
        if count and count > 0 then
            result.blocked = true
            result.reason = "bad_guy"
            result.detail = "IP 在动态黑名单中 (计数: " .. tostring(count) .. ")"
            return json_response(result)
        end
    end

    return json_response(result)
end

local function handle_api_rules_get()
    local result = { files = {} }
    for _, meta in ipairs(RULE_FILES_META) do
        local rules = read_rule_file(meta.name)
        table.insert(result.files, {
            name = meta.name,
            title = meta.title,
            kind = meta.kind,
            desc = meta.desc,
            rules = rules
        })
    end
    return json_response(result)
end

local function handle_api_rules_get_one(file)
    if not RULE_FILES_WHITELIST[file] then
        return json_response({error = "invalid_file", message = "文件名非法"}, 400)
    end
    local rules = read_rule_file(file)
    return json_response({ rules = rules })
end

local function handle_api_rules_save(file)
    if not RULE_FILES_WHITELIST[file] then
        return json_response({error = "invalid_file", message = "文件名非法"}, 400)
    end
    local meta = RULE_FILES_META_BY_NAME[file]
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then return json_response({success = false, message = "请求体为空"}, 400) end
    
    local ok, data = pcall(cjson.decode, body)
    if not ok or type(data) ~= "table" or type(data.rules) ~= "table" then
        return json_response({success = false, message = "JSON 格式错误，需要 {rules: [...]} 的结构"}, 400)
    end
    
    local errors = {}
    local next_id = generate_next_id()
    for i, rule in ipairs(data.rules) do
        if type(rule) ~= "table" then
            table.insert(errors, {index = i, error = "规则项必须是对象 {RuleItem: '...'}"})
        else
            local item = rule.RuleItem
            local err = validate_rule(item, meta.kind)
            if err then
                table.insert(errors, {index = i, error = err})
            end
        end
    end
    
    if #errors > 0 then
        return json_response({success = false, errors = errors}, 400)
    end
    
    local out = {}
    for _, rule in ipairs(data.rules) do
        local obj = {RuleItem = rule.RuleItem}
        if rule.Id and type(rule.Id) == "number" and rule.Id > 0 then
            obj.Id = rule.Id
        else
            obj.Id = next_id
            next_id = next_id + 1
        end
        obj.RuleType = meta.ruletype
        table.insert(out, obj)
    end
    
    local write_ok, err = write_rule_file(file, out)
    if not write_ok then
        return json_response({success = false, message = "保存失败: " .. (err or "")}, 500)
    end
    
    return json_response({success = true, message = "已保存 " .. #out .. " 条规则"})
end

function _M.run()
    local uri = ngx.var.uri

    if not admin_check() then
        ngx.status = 403
        ngx.header["Content-Type"] = "text/html; charset=utf-8"
        ngx.say("<html><body><h1>403 Forbidden</h1><p>IP " .. get_client_ip() .. " not in admin whitelist.</p></body></html>")
        return ngx.exit(403)
    end

    if uri == "/cgi-waf" or uri == "/cgi-waf/" then
        return ngx.redirect("/cgi-waf/status")
    elseif uri == "/cgi-waf/api/stats" then
        return handle_api_stats()
    elseif uri == "/cgi-waf/status" then
        return html_response(STATUS_HTML)
    elseif uri == "/cgi-waf/config" then
        return html_response(CONFIG_HTML)
    elseif uri == "/cgi-waf/rules" then
        return html_response(RULES_HTML)
    elseif uri == "/cgi-waf/api/config" then
        local method = ngx.req.get_method()
        if method == "GET" then
            return handle_api_config_get()
        elseif method == "POST" then
            return handle_api_config_save()
        else
            return json_response({error = "method_not_allowed"}, 405)
        end
    elseif uri == "/cgi-waf/api/rules" then
        local method = ngx.req.get_method()
        local file = ngx.var.arg_file
        if method == "GET" then
            if file then
                return handle_api_rules_get_one(file)
            else
                return handle_api_rules_get()
            end
        elseif method == "POST" then
            if not file then
                return json_response({error = "missing_param", message = "缺少 file 参数"}, 400)
            end
            return handle_api_rules_save(file)
        else
            return json_response({error = "method_not_allowed"}, 405)
        end
    elseif uri:match("^/cgi%-waf/check/(.+)$") then
        local ip = uri:match("^/cgi%-waf/check/(.+)$")
        return handle_check(ip)
    else
        return ngx.redirect("/cgi-waf/status")
    end
end

return _M
