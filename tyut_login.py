#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TYUT 校园网保活

检测校园网认证是否掉线，掉线则自动重登。登录端点按序尝试：
  1) Dr.COM eportal（参数需 XOR 加密，端口 804/803 自动降级）
  2) 旧 Dr.COM CGI（明文参数，走 443，与 chkstatus 同一入口）

认证协议细节见 drcom.py。

用法：
    ./run.sh                      # 常驻，日志落同目录 logs.txt（已 gitignore）
    python3 tyut_login.py         # 常驻；日志到 stdout，去向由启动方式决定
    python3 tyut_login.py --once  # 只跑一轮（手动测试）
    python3 tyut_login.py --once -v --dump    # 调试：流水 + 原始应答

凭证优先级：--user/--password > 环境变量 TYUT_USER/TYUT_PASS > 脚本同目录 .env
"""

import argparse
import ipaddress
import logging
import os
import signal
import sys
import time
from datetime import datetime
from pathlib import Path

import requests

import drcom
from drcom import ENDPOINTS, TIMEOUT, build_params, client_ip, fetch_status, mask_url, try_login

ENV_FILE = Path(__file__).resolve().parent / ".env"   # 脚本同目录
PROBE_URLS = (
    "http://connect.rom.miui.com/generate_204",
    "http://wifi.vivo.com.cn/generate_204",
)

CAMPUS_PREFIX_DEFAULT = "101.7.0.0/16"   # 校网段（登录门闸）
STABLE_AFTER = 5            # 连续成功多少轮后转入慢查
SUMMARY_EVERY = 3600        # 汇总间隔（秒）

log = logging.getLogger("tyut")
ONCE = False        # --once：手动单轮模式


def heartbeat(msg, *args) -> None:
    """每分钟心跳流水：平时 DEBUG，--once 手动跑时打到 INFO。"""
    (log.info if ONCE else log.debug)(msg, *args)


# ---------- 连通性探测与复核 ----------

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


def verify_after_login(session, probe: bool) -> tuple[bool, str]:
    """重登后的复核：result=1 且（未关闭时）探测通过，才算真的回来了。"""
    try:
        again = fetch_status(session)
    except (requests.RequestException, ValueError):
        return False, "复核请求失败"
    if again.get("result") != 1:
        return False, f"result={again.get('result')}"
    if probe and not probe_ok(session):
        return False, "204 未通过"
    return True, ""


# ---------- 环境门闸 ----------

def parse_prefixes(text: str) -> list:
    """解析 --campus-prefix（逗号分隔 CIDR）；空串 = 关掉门闸。"""
    nets = []
    for part in (text or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            sys.exit(f"校网段格式不对：{part!r}（应为 CIDR，如 {CAMPUS_PREFIX_DEFAULT}）")
    return nets


def ip_in_campus(ip: str, networks: list):
    """True/False = 在/不在校网段；None = IP 无法解析（门闸放行，外层打警告）。"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return any(addr in net for net in networks)


# ---------- 运行统计（每小时汇总） ----------

class Stats:
    def __init__(self):
        self.state = "启动"
        self.state_since = time.monotonic()
        self.drops = 0
        self.relogins = 0
        self.loginfail = 0
        self.silent_probes = 0

    def set_state(self, state: str) -> bool:
        """记录状态；返回是否发生了转移。"""
        if state == self.state:
            return False
        self.state = state
        self.state_since = time.monotonic()
        return True

    def summary(self) -> str:
        held = int(time.monotonic() - self.state_since)
        line = (f"近1小时：掉线 {self.drops} 次、重登成功 {self.relogins}、"
                f"登录失败 {self.loginfail}、静默重探 {self.silent_probes} 轮；"
                f"当前 {self.state} 已持续 {held}s")
        self.drops = self.relogins = self.loginfail = self.silent_probes = 0
        return line


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
    networks = parse_prefixes(args.campus_prefix)
    session = requests.Session()
    endpoints = list(ENDPOINTS)
    stats = Stats()
    failures = 0
    stable_streak = 0
    silent = False      # portal 不可达（多半不在校园网）：只慢速重探，不登录
    skipped = False     # 客户端 IP 不在校网段：跳过登录，只观察
    last_summary = time.monotonic()

    log.info("启动：账号=%s 端点=%s 活跃=%ss 稳定=%ss 校网段=%s 探测=%s",
             user, "、".join(e.name for e in endpoints), args.interval, args.steady,
             args.campus_prefix or "(关)", "开" if args.probe else "关")

    while True:
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if time.monotonic() - last_summary >= SUMMARY_EVERY:
            last_summary = time.monotonic()
            log.info("[%s] 汇总 %s", stamp, stats.summary())

        # —— 状态查询（环境门：不可达 → 静默，只重探不登录）——
        try:
            status = fetch_status(session)
        except (requests.RequestException, ValueError) as exc:
            failures += 1
            stats.silent_probes += 1
            if not silent:
                silent = True
                stable_streak = 0
                stats.set_state("静默（校园网不可达）")
                log.info("[%s] 校园网不可达（%s），转静默：每 %ss 重探，不登录",
                         stamp, exc, args.steady)
            if args.once:
                return 1
            time.sleep(args.retry_base if failures == 1 else args.steady)
            continue
        if silent:
            silent = False
            log.info("[%s] 校园网恢复可达", stamp)

        online = status.get("result") == 1
        ip = args.ip or client_ip(status)

        # —— 在线且探测通过：正常心跳 ——
        if online and (not args.probe or probe_ok(session)):
            failures = 0
            stable_streak += 1
            stats.set_state("在线")
            heartbeat("[%s] 在线 ip=%s actt=%ss flow=%s",
                      stamp, ip, status.get("actt"), status.get("flow"))
            if args.once:
                return 0
            time.sleep(args.steady if stable_streak >= STABLE_AFTER else args.interval)
            continue

        # —— 未登录 / 探测失败：准备重登 ——
        prefix = "在线但探测失败（204 未通过）" if online else "检测到未登录"

        if not ip:
            log.error("[%s] %s（客户端 IP 获取失败），跳过本轮", stamp, prefix)
            failures += 1
            if args.once:
                return 1
            time.sleep(backoff(args, failures))
            continue

        if networks and not args.ip:        # --ip 手动指定时视为调试，放行门闸
            verdict = ip_in_campus(ip, networks)
            if verdict is None:
                log.warning("[%s] 客户端 IP 无法解析（%r），门闸放行", stamp, ip)
            elif not verdict:
                if not skipped:
                    skipped = True
                    log.warning("[%s] %s（客户端 IP %s 不在校网段），跳过登录", stamp, prefix, ip)
                stats.set_state("跳过（IP 非校网段）")
                if args.once:
                    return 1
                time.sleep(args.steady)
                continue
            elif skipped:
                skipped = False
                log.info("[%s] 客户端 IP 回到校网段（%s）", stamp, ip)

        if stats.set_state("重登中"):
            stats.drops += 1
            stable_streak = 0

        if args.dry_run:
            req = requests.Request("GET", endpoints[0].url,
                                   params=build_params(endpoints[0], user, password, ip))
            log.info("[%s] dry-run：本应登录 %s", stamp, mask_url(str(req.prepare().url)))
            return 0

        ok, brief, detail = try_login(session, user, password, ip, endpoints)
        if ok:
            time.sleep(2)
            good, check = verify_after_login(session, args.probe)
            if good:
                failures = 0
                stable_streak = 0
                stats.relogins += 1
                stats.set_state("在线")
                log.info("[%s] %s，重登成功（%s，复核通过）", stamp, prefix, brief)
                if args.once:
                    return 0
                time.sleep(args.interval)
                continue
            failures += 1
            wait = backoff(args, failures)
            log.warning("[%s] %s，重登应答成功但复核未通过（%s），%ss 后重试",
                        stamp, prefix, check, wait)
            log.debug("复核详情：%s", detail)
        else:
            stats.loginfail += 1
            failures += 1
            wait = backoff(args, failures)
            log.error("[%s] %s，重登失败（%s），%ss 后重试", stamp, prefix, brief, wait)
            log.debug("重登详情：%s", detail)

        if args.once:
            return 1
        time.sleep(wait)


def main() -> int:
    parser = argparse.ArgumentParser(description="TYUT 校园网保活")
    parser.add_argument("--once", action="store_true", help="只跑一轮后退出（手动测试）")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="输出流水日志（每分钟心跳、探测细节；默认只写事件）")
    parser.add_argument("--interval", type=int, default=60,
                        help="活跃/刚恢复时的检查间隔（秒，默认 60）")
    parser.add_argument("--steady", type=int, default=300,
                        help="稳定后的检查间隔（秒，默认 300）")
    parser.add_argument("--retry-base", type=int, default=10, help="掉线重试起始间隔（秒，默认 10）")
    parser.add_argument("--retry-max", type=int, default=60, help="重试间隔上限（秒，默认 60）")
    parser.add_argument("--campus-prefix", default=CAMPUS_PREFIX_DEFAULT,
                        help="校网段（逗号分隔 CIDR；IP 不在其中则不登录。空串=关门闸）")
    parser.add_argument("--no-probe", dest="probe", action="store_false", help="关闭连通性探测")
    parser.add_argument("--user", help="账号（覆盖环境变量/配置文件）")
    parser.add_argument("--password", help="密码（覆盖环境变量/配置文件）")
    parser.add_argument("--ip", help="手动指定客户端 IP（调试用；给定时绕过校网段门闸）")
    parser.add_argument("--dump", action="store_true", help="打印每次请求的原始响应体（探测协议用）")
    parser.add_argument("--dry-run", action="store_true",
                        help="掉线时只打印本应发送的登录请求、不真的登录（零风险自检）")
    args = parser.parse_args()

    global ONCE
    ONCE = args.once
    drcom.DUMP = args.dump

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
