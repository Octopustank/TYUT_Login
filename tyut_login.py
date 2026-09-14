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
from pathlib import Path

import requests

import drcom
from drcom import (ENDPOINTS, PORTAL, TIMEOUT, build_params, client_ip,
                   describe_exc, fetch_status, mask_url, try_login)

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


def fmt_dur(seconds: float) -> str:
    """时长可读化：42m / 1h04m / 13h31m"""
    s = int(seconds)
    if s < 3600:
        return f"{s // 60}m"
    return f"{s // 3600}h{(s % 3600) // 60:02d}m"


# ---------- 连通性探测与复核 ----------

def probe_ok(session) -> bool:
    """轻量连通性探测：portal 说在线 ≠ 真能上网（IP 变了 / 会话僵死也会 result=1）"""
    for url in PROBE_URLS:
        try:
            resp = session.get(url, timeout=TIMEOUT, allow_redirects=False)
            if resp.status_code == 204:
                return True
            log.debug("probe %s -> HTTP %s", url, resp.status_code)
        except requests.RequestException as exc:
            log.debug("probe %s failed: %s", url, exc)
    return False


def verify_after_login(session, probe: bool) -> tuple[bool, str]:
    """重登后的复核：result=1 且（未关闭时）探测通过，才算真的回来了。"""
    try:
        again = fetch_status(session)
    except (requests.RequestException, ValueError):
        return False, "status re-check failed"
    if again.get("result") != 1:
        return False, f"result={again.get('result')}"
    if probe and not probe_ok(session):
        return False, "204 probe failed"
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
        self.state = "startup"
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
        """一行运行状况：常态只报状态+持续时长，有事件才展开计数。"""
        held = fmt_dur(time.monotonic() - self.state_since)
        events = []
        if self.drops:
            events.append(f"drop {self.drops}")
        if self.relogins:
            events.append(f"re-login OK {self.relogins}")
        if self.loginfail:
            events.append(f"login fail {self.loginfail}")
        if self.silent_probes:
            events.append(f"silent probe {self.silent_probes}")
        line = f"hourly: {self.state} for {held}; " + (
            ", ".join(events) if events else "no events")
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

    log.info("start (pid=%d) account=%s endpoints=%s interval=%ds steady=%ds "
             "campus=%s probe=%s",
             os.getpid(), user, ",".join(e.name for e in endpoints),
             args.interval, args.steady, args.campus_prefix or "off",
             "on" if args.probe else "off")

    while True:
        if time.monotonic() - last_summary >= SUMMARY_EVERY:
            last_summary = time.monotonic()
            log.info("%s", stats.summary())

        # —— 状态查询（环境门：不可达 → 静默，只重探不登录）——
        try:
            status = fetch_status(session)
        except (requests.RequestException, ValueError) as exc:
            failures += 1
            stats.silent_probes += 1
            if not silent:
                silent = True
                stable_streak = 0
                stats.set_state("silent (portal unreachable)")
                log.info("portal unreachable (%s, %s:443), silent mode: "
                         "re-probe every %ds, no login",
                         describe_exc(exc), PORTAL, args.steady)
                log.debug("portal error detail: %s", exc)
            if args.once:
                return 1
            time.sleep(args.retry_base if failures == 1 else args.steady)
            continue
        if silent:
            silent = False
            log.info("portal reachable again")

        online = status.get("result") == 1
        ip = args.ip or client_ip(status)

        # —— 在线且探测通过：正常心跳 ——
        if online and (not args.probe or probe_ok(session)):
            failures = 0
            stable_streak += 1
            stats.set_state("online")
            heartbeat("online ip=%s session=%ss traffic=%s",
                      ip, status.get("actt"), status.get("flow"))
            if args.once:
                return 0
            time.sleep(args.steady if stable_streak >= STABLE_AFTER else args.interval)
            continue

        # —— 未登录 / 探测失败：准备重登 ——
        prefix = "online but probe failed (no 204)" if online else "offline detected"

        if not ip:
            log.error("%s (client IP unavailable), skip this round", prefix)
            failures += 1
            if args.once:
                return 1
            time.sleep(backoff(args, failures))
            continue

        if networks and not args.ip:        # --ip 手动指定时视为调试，放行门闸
            verdict = ip_in_campus(ip, networks)
            if verdict is None:
                log.warning("client IP not parseable (%r), gate open", ip)
            elif not verdict:
                if not skipped:
                    skipped = True
                    log.warning("%s (client IP %s outside %s), login skipped, "
                                "observing only", prefix, ip, args.campus_prefix)
                stats.set_state("skipped (IP outside campus)")
                if args.once:
                    return 1
                time.sleep(args.steady)
                continue
            elif skipped:
                skipped = False
                log.info("client IP back in campus range (%s)", ip)

        if stats.set_state("re-login"):
            stats.drops += 1
            stable_streak = 0

        if args.dry_run:
            req = requests.Request("GET", endpoints[0].url,
                                   params=build_params(endpoints[0], user, password, ip))
            log.info("dry-run: would login %s", mask_url(str(req.prepare().url)))
            return 0

        ok, brief, detail = try_login(session, user, password, ip, endpoints)
        if ok:
            time.sleep(2)
            good, check = verify_after_login(session, args.probe)
            if good:
                failures = 0
                stable_streak = 0
                stats.relogins += 1
                stats.set_state("online")
                log.info("%s, re-login OK (%s, verified)", prefix, brief)
                if args.once:
                    return 0
                time.sleep(args.interval)
                continue
            failures += 1
            wait = backoff(args, failures)
            log.warning("%s, login accepted but re-check failed (%s), "
                        "retry in %ds", prefix, check, wait)
            log.debug("re-check detail: %s", detail)
        else:
            stats.loginfail += 1
            failures += 1
            wait = backoff(args, failures)
            log.error("%s, re-login FAILED (%s), retry in %ds", prefix, brief, wait)
            log.debug("re-login detail: %s", detail)

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
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,          # StreamHandler 每条都 flush，重定向到文件也不会丢日志
    )
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        return run(args)
    except KeyboardInterrupt:
        log.info("stopped")
        return 130


if __name__ == "__main__":
    sys.exit(main())
