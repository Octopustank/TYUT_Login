#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TYUT 校园网保活（demo）

检测校园网认证是否掉线，掉线则自动重登。双端点：
  1) Dr.COM eportal（参数需 XOR 加密，端口自动在 804/803 间试）
  2) 旧 Dr.COM CGI（明文参数，走 443，与 chkstatus 同一入口）

用法：
    python3 tyut_login.py              # 常驻：在线每 60s 查一次，掉线自动重登
    python3 tyut_login.py --once       # 只跑一轮（手动测试，在线退 0 / 掉线重登失败退 1）
    python3 tyut_login.py --once -v    # 带调试日志

凭证来源（优先级）：--user/--password > 环境变量 TYUT_USER/TYUT_PASS > 脚本同目录 .env
"""

import argparse
import json
import logging
import os
import re
import signal
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import NamedTuple

import requests

PORTAL = "drcom.tyut.edu.cn"
STATUS_URL = f"https://{PORTAL}/drcom/chkstatus?callback=dr1001&jsVersion=4.X&v=8249&lang=zh"
SECRET_KEY = "drcom"        # 与 portal 的 a41.js 一致：encryption_type=1, secret_key='drcom'
TIMEOUT = (5, 10)           # (连接, 读取) 秒
ENV_FILE = Path(__file__).resolve().parent / ".env"   # 脚本同目录
PROBE_URLS = (
    "http://connect.rom.miui.com/generate_204",
    "http://wifi.vivo.com.cn/generate_204",
)
JSONP_RE = re.compile(r"^[^(]*\((.*)\)\s*;?\s*$", re.S)
ONLINE_HINTS = ("已在线", "已经在线", "online")
# eportal 返回 result=0 但 msg 属于服务端/Portal侧临时故障的信号词：
# 值得换端点+退避重试，而不是当业务拒绝停住
TRANSIENT_MSGS = ("认证超时", "超时", "繁忙", "temporarily", "timeout")

log = logging.getLogger("tyut")
DUMP = False        # --dump：把每次请求的原始响应体打出来（探测协议用）


def dump_raw(label: str, resp) -> None:
    if DUMP:
        log.info("%s 原始响应: %s", label, resp.text.strip()[:800])


class Endpoint(NamedTuple):
    name: str
    url: str
    style: str      # eportal = 参数需 XOR 加密；legacy = 明文参数


# 登录端点候选，按序尝试；成功的那个会被提到最前（缓存）
ENDPOINTS = [
    Endpoint("eportal:804", f"https://{PORTAL}:804/eportal/portal/login", "eportal"),
    Endpoint("eportal:803", f"http://{PORTAL}:803/eportal/portal/login", "eportal"),
    Endpoint("legacy:443", f"https://{PORTAL}/drcom/login", "legacy"),
]


# ---------- Dr.COM 加密（对应 portal a41.js 的 getkey / enc_pwd） ----------

def xor_key(text: str) -> int:
    key = 0
    for ch in text:
        key ^= ord(ch)
    return key


def enc(text: str, key: int) -> str:
    return "".join(f"{ord(c) ^ key:02x}" for c in text)


def parse_jsonp(text: str) -> dict:
    m = JSONP_RE.match(text.strip())
    return json.loads(m.group(1) if m else text)


def request(session, url, params=None):
    """带超时；TLS 校验失败降级重试一次（认证前 AC 可能换成自签证书）"""
    try:
        return session.get(url, params=params, timeout=TIMEOUT)
    except requests.exceptions.SSLError:
        log.warning("TLS 校验失败，降级 verify=False 重试：%s", url)
        return session.get(url, params=params, timeout=TIMEOUT, verify=False)


# ---------- 状态与登录 ----------

def fetch_status(session) -> dict:
    resp = request(session, STATUS_URL)
    resp.raise_for_status()
    dump_raw("chkstatus", resp)
    return parse_jsonp(resp.text)


def client_ip(status: dict) -> str:
    """取 IP 的顺序与 portal 的 a41.js 一致"""
    for key in ("v46ip", "ss5", "v4ip"):
        value = status.get(key)
        if value:
            return str(value)
    return ""


def mask_url(url: str) -> str:
    """日志里隐去密码字段（eportal 的 user_password / 旧 CGI 的 upass）"""
    return re.sub(r"(user_password=|upass=)[^&]*", r"\1***", url)


def build_params(ep: Endpoint, user: str, password: str, ip: str) -> dict:
    if ep.style == "eportal":
        key = xor_key(SECRET_KEY)
        return {
            "callback": enc("dr1005", key),
            "login_method": enc("1", key),
            "user_account": enc(user, key),
            "user_password": enc(password, key),
            "wlan_user_ip": enc(ip, key),
            "wlan_user_ipv6": "",
            "wlan_user_mac": enc("000000000000", key),
            "wlan_ac_ip": "",
            "wlan_ac_name": "",
            "mac_type": enc("0", key),
            "authex_enable": "",
            "jsVersion": enc("4.3", key),
            "web": enc("0", key),
            "terminal_type": enc("1", key),
            "enable_r3": enc("0", key),
            "encrypt": "1",
            "v": "10327",
        }
    return {                       # 旧 CGI：明文参数
        "callback": "dr1003",
        "DDDDD": user,
        "upass": password,
        "0MKKey": "123456",
        "R1": "0", "R2": "", "R3": "0", "R6": "0", "para": "00",
        "v6ip": "", "terminal_type": "1", "lang": "zh-cn",
        "jsVersion": "4.1.3", "v": "1234",
        "wlan_user_ip": ip,
    }


def is_success(data: dict) -> bool:
    if data.get("result") == 1:
        return True
    msg = str(data.get("msg") or data.get("msga") or "")
    return any(hint in msg for hint in ONLINE_HINTS)


def is_transient(msg: str) -> bool:
    """服务端临时故障类应答（认证超时/系统繁忙等）：换端点或下轮重试可能成功"""
    low = msg.lower()
    return any(t in low for t in TRANSIENT_MSGS)


def try_login(session, user, password, ip, endpoints):
    """返回 (是否成功, 说明)。

    只有服务器给出"明确答复"（成功 或 密码错/账号限制等业务拒绝）才停止换端点；
    连不上/返回非 JSON/认证超时类服务端故障 → 换下一个端点，全部失败则保留
    最后一条错误说明交给外层退避重试。密码错时仍在第一个端点即停，不触发风控。
    """
    last_detail = None
    for i, ep in enumerate(endpoints):
        try:
            resp = request(session, ep.url, params=build_params(ep, user, password, ip))
            dump_raw(ep.name, resp)
            data = parse_jsonp(resp.text)
        except (requests.RequestException, ValueError) as exc:
            log.debug("端点 %s 不可用：%s", ep.name, exc)
            continue
        msg = str(data.get("msg") or data.get("msga") or "")
        detail = f"{ep.name} result={data.get('result')} msg={msg or '(空)'}"
        if is_transient(msg):
            log.debug("端点 %s 服务端临时故障（%s），尝试下一端点", ep.name, msg)
            last_detail = detail
            continue
        if i:
            endpoints.insert(0, endpoints.pop(i))      # 明确应答的端点提到最前
        return is_success(data), detail
    return False, last_detail or "所有登录端点都不可用（网络 / 端口 / 解析失败）"


def probe_ok(session) -> bool:
    """轻量连通性探测：portal 说在线 ≠ 真能上网（IP 变了 / 会话僵死也会 result=1）"""
    for url in PROBE_URLS:
        try:
            resp = session.get(url, timeout=TIMEOUT, allow_redirects=False)
            if resp.status_code == 204:
                return True
            log.debug("探测 %s -> HTTP %s", url, resp.status_code)
        except requests.RequestException as exc:
            log.debug("探测 %s 失败：%s", url, exc)
    return False


# ---------- 主流程 ----------

def parse_env_file(path: Path):
    """返回 (user, password) 元组，缺项为空串"""
    user = password = ""
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key in ("TYUT_USER", "USER", "ACCOUNT") and not user:
            user = value
        elif key in ("TYUT_PASS", "PASS", "PASSWORD") and not password:
            password = value
    return user, password


def load_credentials(args):
    user = args.user or os.environ.get("TYUT_USER") or ""
    password = args.password or os.environ.get("TYUT_PASS") or ""
    if not (user and password) and ENV_FILE.exists():
        fu, fp = parse_env_file(ENV_FILE)
        user = user or fu
        password = password or fp
    if not (user and password):
        sys.exit(
            "缺少账号/密码，任选一种：\n"
            "  1) 配置文件   " + str(ENV_FILE) +
            "（chmod 600；内容 TYUT_USER=... 与 TYUT_PASS=...，模板见 .env.example）\n"
            "  2) 环境变量   export TYUT_USER=... TYUT_PASS=...\n"
            "  3) 命令行     --user ... --password ..."
        )
    return user, password


def backoff(args, failures: int) -> int:
    return min(args.retry_max, args.retry_base * (2 ** max(0, failures - 1)))


def run(args) -> int:
    user, password = load_credentials(args)
    session = requests.Session()
    endpoints = list(ENDPOINTS)
    failures = 0
    log.info("启动：账号=%s 端点=%s 间隔=%ss 探测=%s",
             user, " → ".join(e.name for e in endpoints), args.interval,
             "开" if args.probe else "关")

    while True:
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            status = fetch_status(session)
        except (requests.RequestException, ValueError) as exc:
            failures += 1
            wait = backoff(args, failures)
            log.error("[%s] 状态查询失败（%s），%ss 后重试", stamp, exc, wait)
            if args.once:
                return 1
            time.sleep(wait)
            continue

        online = status.get("result") == 1
        ip = args.ip or client_ip(status)

        if online:
            if args.probe and not probe_ok(session):
                log.warning("[%s] portal 认为在线，但连通性探测失败 → 仍尝试重登", stamp)
            else:
                failures = 0
                log.info("[%s] 在线 ip=%s actt=%ss flow=%s",
                         stamp, ip, status.get("actt"), status.get("flow"))
                if args.once:
                    return 0
                time.sleep(args.interval)
                continue
        else:
            log.warning("[%s] 未登录（result=%s）", stamp, status.get("result"))

        if not ip:
            log.error("[%s] 拿不到客户端 IP，跳过本轮", stamp)
        elif args.dry_run:
            req = requests.Request("GET", endpoints[0].url,
                                   params=build_params(endpoints[0], user, password, ip))
            log.info("[%s] dry-run：本应登录 %s", stamp, mask_url(req.prepare().url))
            return 0
        else:
            ok, detail = try_login(session, user, password, ip, endpoints)
            if ok:
                failures = 0
                log.info("[%s] 重登成功：%s", stamp, detail)
                time.sleep(2)
                try:
                    again = fetch_status(session)
                    log.info("复核：result=%s ip=%s", again.get("result"), client_ip(again))
                except (requests.RequestException, ValueError) as exc:
                    log.warning("复核失败：%s", exc)
                if args.once:
                    return 0
                time.sleep(args.interval)
                continue
            failures += 1
            log.error("[%s] 重登失败：%s", stamp, detail)

        if args.once:
            return 1
        time.sleep(backoff(args, failures))


def main() -> int:
    parser = argparse.ArgumentParser(description="TYUT 校园网保活 demo")
    parser.add_argument("--once", action="store_true", help="只跑一轮后退出（手动测试）")
    parser.add_argument("-v", "--verbose", action="store_true", help="输出调试日志")
    parser.add_argument("--interval", type=int, default=60, help="在线时的检查间隔（秒，默认 60）")
    parser.add_argument("--retry-base", type=int, default=10, help="掉线重试起始间隔（秒，默认 10）")
    parser.add_argument("--retry-max", type=int, default=60, help="重试间隔上限（秒，默认 60）")
    parser.add_argument("--no-probe", dest="probe", action="store_false", help="关闭连通性探测")
    parser.add_argument("--user", help="账号（覆盖环境变量/配置文件）")
    parser.add_argument("--password", help="密码（覆盖环境变量/配置文件）")
    parser.add_argument("--ip", help="手动指定客户端 IP（调试用）")
    parser.add_argument("--dump", action="store_true", help="打印每次请求的原始响应体（探测协议用）")
    parser.add_argument("--dry-run", action="store_true",
                        help="掉线时只打印本应发送的登录请求、不真的登录（零风险自检）")
    args = parser.parse_args()

    global DUMP
    DUMP = args.dump

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-5s %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stdout,          # StreamHandler 每条都 flush，重定向到文件也不会丢日志
    )
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        return run(args)
    except KeyboardInterrupt:
        log.info("已停止")
        return 130


if __name__ == "__main__":
    sys.exit(main())
