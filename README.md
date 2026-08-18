# MA-WAF 萌绘WAF

基于 OpenResty/Lua 的轻量级 Web 应用防火墙，通过 WebUI 管理面板提供实时监控、规则编辑、配置管理、日志查看等功能。

## 特性

- SQL 注入 / XSS / 路径穿越 / 扫描器阻断
- CC 攻击防护（IP 模式 / IP+URL 模式）
- IP / URL / Referer / User-Agent / Cookie / POST 多维检测
- IP 白名单 / URL 白名单 / IP 黑名单
- 反向代理模式，后端服务器无需暴露公网
- WebUI 管理面板（状态统计 / 配置 / 规则编辑 / 日志查看）
- 历史统计图表（日志驱动）
- 跨平台（Linux / macOS / Windows）

## 文件结构

| 文件 | 说明 |
| --- | --- |
| `webui.lua` | WebUI 单文件插件（状态页 / 配置页 / 规则页 / 日志页 + 所有 API） |
| `waf.lua` | WAF 核心逻辑（检测链） |
| `access.lua` | access 阶段入口（一行 `waf.access()`） |
| `init.lua` | init 阶段加载（`require("waf")` + 日志目录初始化） |
| `util.lua` | 工具函数（日志记录、规则热加载等） |
| `iputils.lua` | IP/CIDR 匹配工具 |
| `config.json` | 运行时配置（WebUI 可修改，不纳入 git） |
| `config.json.example` | 配置模板（纳入 git） |
| `rules/` | 规则文件目录（`*.rule`，不纳入 git） |
| `logs/` | 日志目录（自动创建，不纳入 git） |

## 依赖

- [OpenResty](https://openresty.org) ≥ 1.19+（LuaJIT 2.1+）
- `lua-cjson`（OpenResty 自带）

## 安装

### 1. 部署文件

```bash
# 将 moewaf 目录放到插件目录
cp -r moewaf /path/to/plugins/moewaf
cd /path/to/plugins/moewaf

# 初始化配置
cp config.json.example config.json
# 编辑 config.json 修改密钥等配置（可选）

# 初始化规则和日志目录
mkdir -p rules logs
```

### 2. 配置 nginx.conf

所有插件指令放在 `http` 块中（全局生效），WebUI location 放在 `server` 块中：

```nginx
http {
    lua_package_path "/path/to/plugins/moewaf/?.lua;/path/to/plugins/other/?.lua;;";
    lua_shared_dict waf 256m;
    lua_code_cache on;

    init_by_lua_file /path/to/plugins/moewaf/init.lua;
    access_by_lua_file /path/to/plugins/moewaf/access.lua;
}
```

### 3. 验证 & 启动

```bash
nginx -t
nginx -s reload
```

### 4. 访问管理面板

浏览器打开 `http://your-server:80/cgi-waf/status`

首次访问需确认管理员 IP 在 `config.json` 的 `admin_whitelist` 中（默认 `127.0.0.1` 和 `::1`）。面板位于反向代理后时，需在 `admin_trusted_proxies` 中添加反代 IP。

## 配置说明（config.json）

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `config_waf_enable` | `on` | WAF 总开关 |
| `config_waf_model` | `reset` | 拦截模式：`reset`（断开连接）/ `redirect` / `html` |
| `config_waf_redirect_url` | - | redirect 模式的目标 URL |
| `config_expire_time` | 600 | IP 黑名单封禁时长（秒） |
| `config_cc_check` | `on` | CC 攻击防护开关 |
| `config_cc_mode` | `ip` | CC 限流模式：`ip` / `ipurl` |
| `config_cc_rate_ip` | `1000/600` | IP 限流：次数/秒数 |
| `config_cc_rate_ipurl` | `20/60` | IP+URL 限流：次数/秒数 |
| `admin_whitelist` | `["127.0.0.1","::1"]` | 管理面板白名单（留空=允许所有） |
| `admin_trusted_proxies` | `[]` | 受信反代 IP（仅当 remote_addr 在此列表时解析 XFF） |
| `logging_skip_whitelist` | `on` | 白名单 IP 不记日志 |

## 日志文件

- **业务日志**: `logs/waf_YYYY-MM-DD.log`（JSON 行，仅命中规则时产生）
- **错误日志**: `logs/waf.error.log`（nginx error_log 输出，含 `admin: rejected` 审计行）

## 管理面板安全

- 默认仅允许 `127.0.0.1` / `::1` 访问
- 未授权访问返回 404（nginx 风格页面），并在 error log 记录 WARN 审计行
- 反向代理部署时：将反代 IP 加入 `admin_trusted_proxies`，管理员真实 IP 加入 `admin_whitelist`

## 版权

本版本由萌绘图站开发组维护，禁止转卖。二次开发请注明出处。
