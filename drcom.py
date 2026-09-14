#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TYUT 校园网认证协议（Dr.COM）。

状态查询（chkstatus）、登录端点级联（eportal 804/803、旧 CGI）、eportal 参数
XOR 加密与应答判定。校园网更换认证方式时只需替换本模块。

兼容 Python 3.4：无 f-string、无内置泛型注解，Endpoint 用 collections.namedtuple。
"""

import collections
import json
import logging
import re

import requests

PORTAL = "drcom.tyut.edu.cn"
STATUS_URL = ("https://" + PORTAL
              + "/drcom/chkstatus?callback=dr1001&jsVersion=4.X&v=8249&lang=zh")
SECRET_KEY = "drcom"        # 与 portal 的 a41.js 一致：encryption_type=1, secret_key='drcom'
TIMEOUT = (5, 10)           # (连接, 读取) 秒
JSONP_RE = re.compile(r"^[^(]*\((.*)\)\s*;?\s*$", re.S)
ONLINE_HINTS = ("已在线", "已经在线", "online")
# eportal 返回 result=0 但 msg 属于服务端/Portal侧临时故障的信号词：
# 值得换端点+退避重试，而不是当业务拒绝停住
TRANSIENT_MSGS = ("认证超时", "超时", "繁忙", "temporarily", "timeout")

log = logging.getLogger("tyut.drcom")
DUMP = False                # 由 tyut_login.py 按 --dump 设置


def dump_raw(label, resp):
    if DUMP:
        log.info("%s raw response: %s", label, resp.text.strip()[:800])


# name/url/style：eportal = 参数需 XOR 加密；legacy = 明文参数
Endpoint = collections.namedtuple("Endpoint", ("name", "url", "style"))


# 登录端点候选，按序尝试；成功的那个会被提到最前（缓存）
ENDPOINTS = [
    Endpoint("eportal:804", "https://" + PORTAL + ":804/eportal/portal/login", "eportal"),
    Endpoint("eportal:803", "http://" + PORTAL + ":803/eportal/portal/login", "eportal"),
    Endpoint("legacy:443", "https://" + PORTAL + "/drcom/login", "legacy"),
]


def xor_key(text):
    key = 0
    for ch in text:
        key ^= ord(ch)
    return key


def enc(text, key):
    return "".join("{:02x}".format(ord(c) ^ key) for c in text)


def parse_jsonp(text):
    m = JSONP_RE.match(text.strip())
    return json.loads(m.group(1) if m else text)


def build_params(ep, user, password, ip):
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


def is_success(data):
    if data.get("result") == 1:
        return True
    msg = str(data.get("msg") or data.get("msga") or "")
    return any(hint in msg for hint in ONLINE_HINTS)


def is_transient(msg):
    """服务端临时故障类应答（认证超时/系统繁忙等）：换端点或下轮重试可能成功"""
    low = msg.lower()
    return any(t in low for t in TRANSIENT_MSGS)


def mask_url(url):
    """日志里隐去密码字段（eportal 的 user_password / 旧 CGI 的 upass）"""
    return re.sub(r"(user_password=|upass=)[^&]*", r"\1***", url)


def describe_exc(exc):
    """把 requests 的长异常归成一句人话（原文降 DEBUG，日志不糊堆栈文本）。"""
    text = str(exc)
    if isinstance(exc, requests.exceptions.SSLError) or "SSL" in text:
        if "UNEXPECTED_EOF" in text:
            return "TLS connection interrupted"
        if "CERTIFICATE_VERIFY_FAILED" in text:
            return "TLS certificate verify failed"
        return "TLS error"
    if "Read timed out" in text:
        return "read timeout"
    if "Connect timed out" in text:
        return "connect timeout"
    if "Connection refused" in text:
        return "connection refused"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "connection error"
    return type(exc).__name__


def request(session, url, params=None):
    """带超时；TLS 校验失败降级重试一次（认证前 AC 可能换成自签证书）"""
    try:
        return session.get(url, params=params, timeout=TIMEOUT)
    except requests.exceptions.SSLError as exc:
        log.warning("TLS verify failed (%s), retrying with verify=False: %s",
                    describe_exc(exc), url.split("?")[0])
        return session.get(url, params=params, timeout=TIMEOUT, verify=False)


def fetch_status(session):
    resp = request(session, STATUS_URL)
    resp.raise_for_status()
    dump_raw("chkstatus", resp)
    return parse_jsonp(resp.text)


def client_ip(status):
    """取 IP 的顺序与 portal 的 a41.js 一致"""
    for key in ("v46ip", "ss5", "v4ip"):
        value = status.get(key)
        if value:
            return str(value)
    return ""


def try_login(session, user, password, ip, endpoints):
    """按序尝试登录端点。

    只有服务器给出"明确应答"（成功 或 密码错/账号限制等业务拒绝）才停止换端点；
    连不上/返回非 JSON/认证超时类服务端故障 → 换下一个端点，全部失败则保留
    最后一条说明交给外层退避重试。密码错时仍在第一个端点即停，不触发风控。
    """
    last = None
    for i, ep in enumerate(endpoints):
        try:
            resp = request(session, ep.url, params=build_params(ep, user, password, ip))
            dump_raw(ep.name, resp)
            data = parse_jsonp(resp.text)
        except (requests.RequestException, ValueError) as exc:
            log.debug("endpoint %s unavailable: %s", ep.name, exc)
            last = ("{}: {}".format(ep.name, type(exc).__name__),
                    "{} exception: {}".format(ep.name, exc))
            continue
        msg = str(data.get("msg") or data.get("msga") or "")
        code = data.get("result")
        detail = "{} result={} msg={}".format(ep.name, code, msg or "(empty)")
        brief = "{}: {}".format(ep.name, msg) if msg else "{}: result={}".format(ep.name, code)
        if is_transient(msg):
            log.debug("endpoint %s transient server fault (%s), trying next", ep.name, msg)
            last = (brief, detail)
            continue
        if i:
            endpoints.insert(0, endpoints.pop(i))      # 明确应答的端点提到最前
        if is_success(data):
            return True, ep.name, detail
        return False, brief, detail
    if last is None:
        return False, "all endpoints unavailable", "no login endpoint reachable (network / port / parse)"
    return False, last[0], last[1]
