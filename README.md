# MOEWAF

**版本：1.3.3**

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
| `webui.lua` | WebUI 单文件插件（状态页 / 配置页 / 规则页 / 日志页及所有 API） |
| `history_cache.lua` | 按日期和查询范围持久化历史统计摘要，供 status 接口快速读取 |
| `waf.lua` | WAF 核心逻辑（检测链） |
| `access.lua` | access 阶段入口（一行 `waf.access()`） |
| `init.lua` | init 阶段加载（`require("waf")` + 日志目录初始化） |
| `util.lua` | 工具函数（日志记录、规则热加载等） |
| `iputils.lua` | IP/CIDR 匹配工具 |
| `config.json` | 运行时配置（WebUI 可修改，不纳入 git） |
| `config.json.example` | 配置模板（纳入 git） |
| `rules/` | 规则文件目录（`*.rule`，不纳入 git） |
| `logs/` | 日志目录（自动创建，不纳入 git） |
| `logs/.history_stats/` | 历史统计缓存目录（自动创建，不纳入 git） |
| `tools/waf_selftest.py` | 受限的命令行 WAF 自测与 Markdown 报告工具 |
| `reports/` | 自测报告输出目录（按需创建） |

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
# 编辑 config.json 修改配置

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

单个 `server` 需要跳过 WAF（例如只监听 `127.0.0.1` 的本机反代入口）时，在 `server` 块里加
`set $waf_on 0;`；判定在 `waf.lua` 的 `check()` 内完成（与 `$rfw_on` 同一约定），
`access.lua` 仍只保留一行 `waf.check()`，不设置该变量时照常检测。

### 3. 验证与启动

```bash
nginx -t
nginx -s reload
```

### 4. 访问管理面板

浏览器打开 `http://your-server:80/cgi-waf/status`。

首次访问需确认管理员 IP 在 `config.json` 的 `admin_whitelist` 中（默认 `127.0.0.1` 和 `::1`）。面板位于反向代理后时，需在 `admin_trusted_proxies` 中添加反代 IP。

## 配置说明（config.json）

配置文件中的备注字段统一采用 `__大写NAME` 格式，并使用字符串保存备注内容，例如：

```json
{
    "__WAF_ENABLE": "WAF 总开关",
    "config_waf_enable": "on"
}
```

程序加载配置时会自动忽略所有以 `__` 开头的备注字段；实际配置项不使用双下划线前缀。运行时配置与模板配置均已采用此格式。

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
| `admin_trusted_proxies` | `[]` | 受信反代 IP（仅当 `remote_addr` 在此列表时解析 XFF） |
| `logging_skip_whitelist` | `on` | 白名单 IP 不记日志 |

## 日志文件

- **业务日志**：`logs/waf_YYYY-MM-DD.log`（JSON 行，仅命中规则时产生）
- **错误日志**：`logs/waf.error.log`（Nginx `error_log` 输出，含 `admin: rejected` 审计行）

## 管理面板安全

默认仅允许 `127.0.0.1` / `::1` 访问。未授权访问返回 404（Nginx 风格页面），并在 error log 记录 WARN 审计行。反向代理部署时，应将反代 IP 加入 `admin_trusted_proxies`，并将管理员真实 IP 加入 `admin_whitelist`。

当前 WebUI 页面包括状态、配置、规则和日志四个模块，不再嵌入自测模块。规则页面采用统一的表格操作区和新增规则输入区，编辑、删除、确定和取消按钮会保持同一行的稳定布局。

## 历史统计性能与缓存

status 页的历史统计接口使用 `history_cache.lua` 将每个日期的日志聚合结果写入 `logs/.history_stats/waf_YYYY-MM-DD.json`，并按查询天数维护 `range_1.json`、`range_7.json` 等范围摘要。接口请求优先读取范围统计文件；对于过去日期，命中缓存时不会打开或读取原始日志，也不会重新逐行 JSON 解析。首次发现某个日志文件时会建立摘要；当天日志仅追加时只解析新增部分；日志轮转、截断、缓存损坏或缓存版本变化时才会重建相关摘要。

统计摘要包含攻击总数、白名单命中数、攻击类型、Top IP 和 Top URL。IP/URL 维度最多保留 50000 个键，返回仍只保留 Top 10。缓存文件使用临时文件写入并原子替换，缓存目录不会被日志浏览接口列出。

第一次对既有超大日志建立缓存仍需要扫描一次；缓存建立后，status 接口只需读取小型 JSON 摘要。缓存模块会在第一次建立摘要时自动创建 `logs/.history_stats/`，Linux 使用 `mkdir -p`，Windows 使用系统 `mkdir`，不要求手工创建目录。若需要手动重建，可删除对应日期的 `logs/.history_stats/waf_YYYY-MM-DD.json` 或范围缓存文件，下一次请求会自动重建。

## WAF 自测与攻击面验证

项目提供独立的 `tools/waf_selftest.py` 命令行工具，用于在**自有或已获明确授权的测试环境**中验证 WAF 检测链。工具默认只允许 loopback 目标；对非本机目标必须显式提供匹配的 `--allow-host` 并使用 `--confirm-authorized`。工具拒绝外部 URL、管理路径、重定向、并发压测、文件上传、命令执行、黑名单伪造和外部资产发现。

默认用例覆盖 URL 参数、敏感路径 URL、请求头、Cookie、POST SQLi 与 POST XSS 六个检测面。HTTP 4xx、连接重置或对应统计项增量会被记录为拦截信号，但这不等同于漏洞不存在；报告使用者仍应结合 WAF 日志、Nginx 日志和业务路由确认拦截来源。

```bash
cd /path/to/plugins/moewaf
python3 tools/waf_selftest.py \
  --base-url http://127.0.0.1 \
  --target-path /health \
  --output reports/ma-waf-selftest.md
```

如果必须测试已授权的非 loopback 环境，应显式声明主机并确认授权：

```bash
python3 tools/waf_selftest.py \
  --base-url https://waf-test.example.internal \
  --allow-host waf-test.example.internal \
  --confirm-authorized \
  --target-path /health \
  --output reports/ma-waf-selftest.md
```

## 版权

本版本由萌绘图站开发组维护，禁止转卖。二次开发请注明出处。
