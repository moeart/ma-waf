#!/usr/bin/env python3
"""MA-WAF authorized, same-origin canary self-test.

This tool deliberately avoids discovery, concurrency, redirects, uploads,
command execution, and arbitrary exploit payloads. It is intended for a WAF
instance owned or explicitly authorized by the operator.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass(frozen=True)
class Case:
    case_id: str
    surface: str
    method: str
    summary: str
    note: str
    kind: str
    query: str = ""
    suffix: str = ""
    body: str = ""
    content_type: str = ""
    header_name: str = ""
    header_value: str = ""
    cookie_value: str = ""


CASES = [
    Case("args-sqli", "URL 参数", "GET", "ma_waf_probe=select…information_schema", "验证 URL 参数 SQLi 规则", "args", query="ma_waf_probe=select%20user%20from%20information_schema"),
    Case("url-sensitive", "URL 路径", "GET", "/.git/mawaf_probe", "验证敏感目录路径规则", "url", suffix="/.git/mawaf_probe"),
    Case("header-canary", "Header", "GET", "X-Scan-Memo: MA-WAF-SELFTEST", "验证请求头扫描器标记规则", "header", header_name="X-Scan-Memo", header_value="MA-WAF-SELFTEST"),
    Case("cookie-sqli", "Cookie", "GET", "mawaf_probe=select…information_schema", "验证 Cookie SQLi 规则", "cookie", cookie_value="select user from information_schema"),
    Case("post-sqli", "POST", "POST", "select…information_schema", "验证 POST SQLi 规则", "post", body="ma_waf_probe=select%20user%20from%20information_schema", content_type="application/x-www-form-urlencoded"),
    Case("post-xss", "POST", "POST", "HTML tag canary", "验证 POST XSS 规则", "post", body="ma_waf_probe=%3Cscript%3Emawaf_probe%3C%2Fscript%3E", content_type="application/x-www-form-urlencoded"),
]

STAT_KEYS = {
    "args": "firewall_req_url_args",
    "url": "firewall_req_url",
    "header": "firewall_req_header",
    "cookie": "firewall_req_cookie",
    "post": "firewall_req_post",
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def die(message: str) -> "NoReturn":
    print(f"错误：{message}", file=sys.stderr)
    raise SystemExit(2)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="MA-WAF 授权、自包含、非破坏性 canary 自测")
    parser.add_argument("--base-url", required=True, help="WAF 基地址，例如 http://127.0.0.1")
    parser.add_argument("--target-path", default="/", help="同源目标路径，默认 /")
    parser.add_argument("--timeout", type=float, default=5.0, help="单请求超时秒数，范围 1-15")
    parser.add_argument("--output", default="ma-waf-selftest-report.md", help="Markdown 报告输出路径")
    parser.add_argument("--cookie", default="", help="可选的管理/业务 Cookie，格式 name=value")
    parser.add_argument("--allow-host", default="", help="非本机目标的显式授权主机名；不填则拒绝非 loopback")
    parser.add_argument("--confirm-authorized", action="store_true", help="确认目标属于你管理或已获书面授权的环境")
    return parser.parse_args()


def validate_target(base_url: str, target_path: str, allow_host: str, confirmed: bool) -> tuple[str, str]:
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        die("--base-url 必须是 http(s) URL")
    if not target_path.startswith("/") or target_path.startswith("//") or "\\" in target_path or "#" in target_path:
        die("--target-path 必须是同源绝对路径，且不得包含 //、反斜杠或片段")
    if target_path.startswith("/cgi-waf") or target_path.startswith("/cgi-rfw"):
        die("禁止把管理路径作为自测目标")
    try:
        ip = socket.gethostbyname(parsed.hostname)
    except socket.gaierror as exc:
        die(f"无法解析目标主机：{exc}")
    loopback = ip.startswith("127.") or ip == "::1" or parsed.hostname.lower() == "localhost"
    if not loopback:
        if not allow_host or parsed.hostname != allow_host or not confirmed:
            die("非本机目标必须同时提供匹配的 --allow-host 与 --confirm-authorized")
    base = base_url.rstrip("/")
    return base, target_path


def request_json(url: str, timeout: float, headers: dict[str, str]) -> dict:
    req = urllib.request.Request(url, method="GET", headers={"Cache-Control": "no-cache", **headers})
    with OPENER.open(req, timeout=timeout) as response:
        raw = response.read(2 * 1024 * 1024)
        return json.loads(raw.decode("utf-8", errors="replace"))


def stats(base: str, timeout: float, headers: dict[str, str]) -> dict:
    try:
        value = request_json(f"{base}/cgi-waf/api/stats?t={int(time.time() * 1000)}", timeout, headers)
        return value if isinstance(value, dict) else {}
    except Exception as exc:  # stats are supplementary; the probes still run
        return {"_stats_error": str(exc)}


def case_url(base: str, target: str, case: Case) -> str:
    path = target + case.suffix
    params = case.query or f"mawaf_case={urllib.parse.quote(case.case_id)}"
    params += f"&mawaf_selftest={int(time.time() * 1000)}"
    return f"{base}{path}{'&' if '?' in path else '?'}{params}"


def run_case(base: str, target: str, case: Case, timeout: float, headers: dict[str, str]) -> dict:
    request_headers = {"Cache-Control": "no-cache", **headers}
    if case.header_name:
        request_headers[case.header_name] = case.header_value
    if case.cookie_value:
        request_headers["Cookie"] = f"mawaf_probe={urllib.parse.quote(case.cookie_value)}"
    data = case.body.encode("ascii") if case.body else None
    if case.content_type:
        request_headers["Content-Type"] = case.content_type
    req = urllib.request.Request(case_url(base, target, case), data=data, method=case.method, headers=request_headers)
    started = time.monotonic()
    try:
        with OPENER.open(req, timeout=timeout) as response:
            status = response.status
            response.read(4096)
            blocked = status >= 400
            return {"status": status, "blocked_signal": blocked, "error": "", "latency_ms": round((time.monotonic() - started) * 1000)}
    except urllib.error.HTTPError as exc:
        return {"status": exc.code, "blocked_signal": exc.code >= 400, "error": "", "latency_ms": round((time.monotonic() - started) * 1000)}
    except Exception as exc:
        return {"status": None, "blocked_signal": True, "error": str(exc), "latency_ms": round((time.monotonic() - started) * 1000)}


def delta(before: dict, after: dict, key: str) -> int:
    try:
        return int(after.get(key, 0) or 0) - int(before.get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0


def make_report(meta: dict, results: list[dict], before: dict, after: dict, target: str) -> str:
    passed = sum(1 for row in results if row["pass"])
    failed = len(results) - passed
    blocked = sum(1 for row in results if row["response"]["blocked_signal"])
    started = meta["started"]
    finished = meta["finished"]
    lines = [
        "# MA-WAF 自测报告", "",
        "> 本报告由授权范围内的同源、低频、非破坏性 canary 自测生成；它不等同于完整渗透测试。", "",
        "## 执行摘要", "",
        f"- 执行时间：{started} 至 {finished}",
        f"- 目标路径：`{target}`",
        f"- 用例数：{len(results)}；通过：{passed}；未拦截：{failed}；拦截信号：{blocked}", "",
        "## 用例结果", "",
        "| 状态 | 攻击面 | 方法 | HTTP | WAF 信号 | 延迟 | 说明 |",
        "| --- | --- | --- | ---: | --- | ---: | --- |",
    ]
    for row in results:
        response = row["response"]
        status = response["status"] if response["status"] is not None else "—"
        signal = "请求被拒绝或返回 4xx+" if response["blocked_signal"] else "返回成功状态，待统计核验"
        if row["stat_delta"] > 0:
            signal += f"；统计增加 {row['stat_delta']} 次"
        if response["error"]:
            signal += f"；{response['error']}"
        lines.append(f"| {'通过' if row['pass'] else '未拦截'} | {row['case'].surface} | {row['case'].method} | {status} | {signal} | {response['latency_ms']} ms | {row['case'].note} |")
    lines += ["", "## WAF 统计增量", "", "| 指标 | 增量 |", "| --- | ---: |"]
    for key in ["firewall_req_total", "firewall_req_normal", "firewall_req_attack", "firewall_req_header", "firewall_req_url", "firewall_req_url_args", "firewall_req_cookie", "firewall_req_post"]:
        lines.append(f"| {key} | {delta(before, after, key)} |")
    lines += [
        "", "## 安全边界与限制", "",
        "本次只访问当前 WAF 的同源目标路径，按顺序发送 6 个固定 canary 请求，不执行外部资产扫描、CC 压测、文件上传、命令执行、黑名单伪造或漏洞利用。HTTP 4xx 与网络错误只代表请求被拒绝或未完成，仍需结合 `logs/waf_YYYY-MM-DD.log`、Nginx error log 与业务路由确认是否由 WAF 产生。", "",
        "## 后续建议", "",
        "对标记为“未拦截”的面，先核对对应检测开关和规则文件是否热加载，再在隔离环境中补充经批准的测试样本；不要把目标改为未经授权的公网第三方站点。", "",
    ]
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    if not 1 <= args.timeout <= 15:
        die("--timeout 必须在 1 到 15 秒之间")
    base, target = validate_target(args.base_url, args.target_path, args.allow_host, args.confirm_authorized)
    headers = {"Cookie": args.cookie} if args.cookie else {}
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    before = stats(base, args.timeout, headers)
    results = []
    for case in CASES:
        response = run_case(base, target, case, args.timeout, headers)
        time.sleep(0.12)
        results.append({"case": case, "response": response, "stat_delta": 0, "pass": response["blocked_signal"]})
    after = stats(base, args.timeout, headers)
    for row in results:
        key = STAT_KEYS[row["case"].kind]
        row["stat_delta"] = delta(before, after, key)
        if row["stat_delta"] > 0:
            row["pass"] = True
    finished = dt.datetime.now(dt.timezone.utc).isoformat()
    report = make_report({"started": started, "finished": finished}, results, before, after, target)
    output = Path(args.output)
    output.write_text(report, encoding="utf-8")
    passed = sum(1 for row in results if row["pass"])
    print(f"完成：{passed}/{len(results)} 个用例通过，报告已写入 {output}")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
