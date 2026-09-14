#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tgfwd — 用 Telegram Bot 管理的端口转发（中转）脚本。

跑在**中转机**上，用 iptables NAT 把本机端口转发到落地机，
转发规则通过 TG bot 增删查，另外带流量统计、健康告警、限速和超额停用。

    本机:8096  ──DNAT──>  落地机(Emby):8096

零第三方依赖，只用 Python 标准库 + 系统自带的 iptables。

常用命令::

    sudo python3 tgfwd.py --init      # 交互式生成 config.json
    sudo python3 tgfwd.py --check     # 体检：root/iptables/ip_forward/token
    sudo python3 tgfwd.py             # 正式跑（前台）
    sudo python3 tgfwd.py --uninstall # 清掉本脚本下的所有 iptables/tc 规则

设计要点：
  * 所有 iptables 规则都挂在自己的 TGF_* 自定义链里，不碰用户已有规则，
    卸载时整条链删掉即可，干干净净；
  * 流量统计读 filter/FORWARD 里的计数器（nat 表计数器只算首包，不能用）；
  * 落地机写域名时会定期重新解析，IP 变了自动重建规则
    （这是裸 iptables DNAT 唯一的短板，在这里补上了）。
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import logging.handlers
import math
import os
import random
import re
import signal
import socket
import subprocess
import sys
import time
from urllib import error as urlerror
from urllib import request as urlrequest

__version__ = "1.0.0"

LOG = logging.getLogger("tgfwd")

DEFAULT_API_BASE = "https://api.telegram.org"
DEFAULT_CONFIG = "/etc/tgfwd/config.json"
DEFAULT_STORE = "/etc/tgfwd/rules.json"

POLL_TIMEOUT = 25              # long polling 挂起秒数
TRAFFIC_INTERVAL = 60          # 流量采样间隔
HEALTH_INTERVAL = 60           # 落地机健康检查间隔
DNS_INTERVAL = 300             # 域名重解析间隔
STATE_SAVE_INTERVAL = 120      # 定期落盘间隔
TEXT_LIMIT = 4096

# 自定义链名：所有规则都关在这几条链里，方便整体清理
CHAIN_PRE = "TGF_PRE"          # nat/PREROUTING  -> DNAT
CHAIN_POST = "TGF_POST"        # nat/POSTROUTING -> SNAT/MASQUERADE
CHAIN_FWD = "TGF_FWD"          # filter/FORWARD  -> 放行 + 计数
CHAIN_MANGLE = "TGF_MARK"      # mangle/POSTROUTING -> 打 fwmark 供 tc 限速

COMMENT_RE = re.compile(r'--comment "TGF:(\d+):(in|out)"')
COUNTER_RE = re.compile(r"^\[(\d+):(\d+)\]")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
                       r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")
PORT_RANGE_RE = re.compile(r"^(\d{1,5})(?:[-:](\d{1,5}))?$")

SIZE_UNITS = {"": 1, "B": 1, "K": 1024, "KB": 1024, "M": 1024 ** 2, "MB": 1024 ** 2,
              "G": 1024 ** 3, "GB": 1024 ** 3, "T": 1024 ** 4, "TB": 1024 ** 4}
RATE_UNITS = {"": 1, "K": 1000, "KBIT": 1000, "M": 1000 ** 2, "MBIT": 1000 ** 2,
              "G": 1000 ** 3, "GBIT": 1000 ** 3}


class ConfigError(Exception):
    pass


class UsageError(Exception):
    """命令参数不对，消息直接回给用户看。"""


# --------------------------------------------------------------------------- #
# 单位与校验
# --------------------------------------------------------------------------- #
def parse_size(text):
    """'500G' -> 字节数。按 1024 进制（和 df/free 一致）。0 表示不限。"""
    text = str(text).strip().upper().replace("I", "")      # GiB -> GB
    match = re.match(r"^(\d+(?:\.\d+)?)\s*([KMGT]?B?)$", text)
    if not match:
        raise UsageError("流量写法不对：%s（应形如 500G / 2T / 0 表示不限）" % text)
    return int(float(match.group(1)) * SIZE_UNITS[match.group(2)])


def parse_rate(text):
    """'100M' -> 比特/秒。带宽按 1000 进制（和运营商/tc 一致）。0 表示不限。"""
    text = str(text).strip().upper()
    match = re.match(r"^(\d+(?:\.\d+)?)\s*([KMG]?(?:BIT)?)$", text)
    if not match:
        raise UsageError("限速写法不对：%s（应形如 100M = 100Mbps，0 表示不限）" % text)
    return int(float(match.group(1)) * RATE_UNITS[match.group(2)])


def format_size(num):
    if num <= 0:
        return "0"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num < 1024 or unit == "TB":
            return ("%.2f%s" % (num, unit)).replace(".00", "")
        num /= 1024.0
    return "%.2fTB" % num


def format_rate(bits):
    if bits <= 0:
        return "不限"
    for unit in ("bps", "Kbps", "Mbps", "Gbps"):
        if bits < 1000 or unit == "Gbps":
            return ("%.1f%s" % (bits, unit)).replace(".0", "")
        bits /= 1000.0
    return "%.1fGbps" % bits


def format_duration(seconds):
    seconds = int(seconds)
    if seconds < 60:
        return "%d秒" % seconds
    if seconds < 3600:
        return "%d分钟" % (seconds // 60)
    if seconds < 86400:
        return "%d小时%d分" % (seconds // 3600, seconds % 3600 // 60)
    return "%d天%d小时" % (seconds // 86400, seconds % 86400 // 3600)


def parse_ports(text):
    """'8096' -> (8096, 8096)；'10000-20000' -> (10000, 20000)。"""
    match = PORT_RANGE_RE.match(str(text).strip())
    if not match:
        raise UsageError("端口写法不对：%s（应形如 8096 或 10000-20000）" % text)
    start = int(match.group(1))
    end = int(match.group(2)) if match.group(2) else start
    for port in (start, end):
        if not 1 <= port <= 65535:
            raise UsageError("端口超出范围：%d（应在 1~65535）" % port)
    if end < start:
        raise UsageError("端口段反了：%d-%d" % (start, end))
    return start, end


def parse_host(text):
    """返回 ('ip'|'domain', 规范化后的值)。只支持 IPv4。"""
    text = str(text).strip().lower()
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        # 顶级标签全是数字 => 本来就想写 IP，只是写错了。
        # 不拦住的话会被当成域名，最后报一句让人摸不着头脑的「解析不出 IP」。
        if re.match(r"^[\d.]+$", text):
            raise UsageError("IP 地址不合法：%s" % text)
        if DOMAIN_RE.match(text):
            return "domain", text
        raise UsageError("目标地址不对：%s（应是 IPv4 或域名）" % text)
    if addr.version != 4:
        raise UsageError("暂不支持 IPv6 目标：%s" % text)
    return "ip", str(addr)


def resolve(host):
    """域名解析成 IPv4，失败返回 None。"""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        LOG.warning("解析 %s 失败: %s", host, exc)
        return None
    return infos[0][4][0] if infos else None


def local_ip():
    """探测本机出口 IPv4（不产生实际流量，只看路由选了哪个源地址）。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("198.51.100.1", 53))     # TEST-NET-2，不会真发包
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def truncate(text, limit=TEXT_LIMIT):
    return text if len(text) <= limit else text[: limit - 1] + "…"


# --------------------------------------------------------------------------- #
# Telegram Bot API
# --------------------------------------------------------------------------- #
class ApiError(Exception):
    def __init__(self, method, code, description, parameters=None):
        super().__init__("%s 失败 (%s): %s" % (method, code, description))
        self.method = method
        self.code = code
        self.description = description or ""
        self.parameters = parameters or {}


class BotAPI:
    """极简 Bot API 客户端：JSON over HTTPS，自带 429/网络错误退避重试。"""

    def __init__(self, token, api_base=DEFAULT_API_BASE, proxy=None):
        self._url = "%s/bot%s" % (api_base.rstrip("/"), token)
        if proxy:
            handler = urlrequest.ProxyHandler({"http": proxy, "https": proxy})
            self._opener = urlrequest.build_opener(handler)
        else:
            # 默认 opener 会读 HTTP_PROXY / HTTPS_PROXY 环境变量
            self._opener = urlrequest.build_opener()

    def call(self, method, params=None, timeout=30, retries=3, raise_on_error=True):
        payload = {k: v for k, v in (params or {}).items() if v is not None}
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        url = "%s/%s" % (self._url, method)
        headers = {"Content-Type": "application/json; charset=utf-8"}

        attempt = 0
        flood_hits = 0
        while True:
            attempt += 1
            try:
                req = urlrequest.Request(url, data=data, headers=headers)
                with self._opener.open(req, timeout=timeout) as resp:
                    body = json.loads(resp.read().decode("utf-8"))
                if body.get("ok"):
                    return body.get("result")
                err = ApiError(method, body.get("error_code"),
                               body.get("description"), body.get("parameters"))
            except urlerror.HTTPError as exc:
                raw = exc.read().decode("utf-8", "replace")
                try:
                    body = json.loads(raw)
                except ValueError:
                    body = {}
                err = ApiError(method, body.get("error_code", exc.code),
                               body.get("description") or raw[:200], body.get("parameters"))
            except (urlerror.URLError, OSError, ValueError) as exc:
                err = ApiError(method, 0, "网络错误: %s" % exc)

            retry_after = err.parameters.get("retry_after")
            if retry_after and flood_hits < 5 and float(retry_after) <= 300:
                flood_hits += 1
                LOG.warning("触发限流(429)，%.1fs 后重试 %s", float(retry_after) + 0.5, method)
                time.sleep(float(retry_after) + 0.5)
                continue

            if err.code in (0, 429, 500, 502, 503, 504) and attempt <= retries:
                wait = min(2 ** attempt, 16) + random.random()
                LOG.warning("%s，%.1fs 后重试(%d/%d)", err, wait, attempt, retries)
                time.sleep(wait)
                continue

            if raise_on_error:
                raise err
            LOG.error("%s", err)
            return None


# --------------------------------------------------------------------------- #
# 规则模型与持久化
# --------------------------------------------------------------------------- #
class Rule:
    """一条「本机端口 -> 落地机」的转发规则。"""

    FIELDS = ("id", "name", "listen_start", "listen_end", "host", "host_kind",
              "target_start", "target_end", "protocol", "enabled", "quota",
              "used", "speed", "resolved_ip", "created_at", "quota_hit",
              "healthy", "latency_ms", "fail_streak")

    def __init__(self, **kwargs):
        self.id = int(kwargs["id"])
        self.name = str(kwargs.get("name") or "")
        self.listen_start = int(kwargs["listen_start"])
        self.listen_end = int(kwargs["listen_end"])
        self.host = str(kwargs["host"])
        self.host_kind = str(kwargs.get("host_kind") or "ip")
        self.target_start = int(kwargs["target_start"])
        self.target_end = int(kwargs["target_end"])
        self.protocol = str(kwargs.get("protocol") or "tcp")
        self.enabled = bool(kwargs.get("enabled", True))
        self.quota = int(kwargs.get("quota") or 0)          # 字节，0=不限
        self.used = int(kwargs.get("used") or 0)            # 累计字节
        self.speed = int(kwargs.get("speed") or 0)          # 比特/秒，0=不限
        self.resolved_ip = kwargs.get("resolved_ip") or (self.host if self.host_kind == "ip" else None)
        self.created_at = float(kwargs.get("created_at") or time.time())
        self.quota_hit = bool(kwargs.get("quota_hit", False))
        self.healthy = kwargs.get("healthy")                # None=没测过
        self.latency_ms = kwargs.get("latency_ms")
        self.fail_streak = int(kwargs.get("fail_streak") or 0)
        # 下面这些只在内存里，不落盘
        self.counter_base = {"in": 0, "out": 0}

    # -- 序列化 ----------------------------------------------------------- #
    def to_dict(self):
        return {field: getattr(self, field) for field in self.FIELDS}

    @classmethod
    def from_dict(cls, data):
        return cls(**data)

    # -- iptables 用的表达 ------------------------------------------------ #
    @property
    def protocols(self):
        return ("tcp", "udp") if self.protocol == "both" else (self.protocol,)

    @property
    def is_range(self):
        return self.listen_end > self.listen_start

    def listen_spec(self):
        """iptables --dport 用冒号表示端口段。"""
        return ("%d:%d" % (self.listen_start, self.listen_end)) if self.is_range \
            else str(self.listen_start)

    def target_spec(self):
        return ("%d:%d" % (self.target_start, self.target_end)) if self.is_range \
            else str(self.target_start)

    def dnat_dest(self):
        """--to-destination 用短横表示端口段。"""
        ports = ("%d-%d" % (self.target_start, self.target_end)) if self.is_range \
            else str(self.target_start)
        return "%s:%s" % (self.resolved_ip, ports)

    # -- 展示 ------------------------------------------------------------- #
    def arrow(self):
        target = self.host if self.host_kind == "domain" else self.resolved_ip
        same_port = (self.listen_start == self.target_start
                     and self.listen_end == self.target_end)
        tail = "" if same_port else ":%s" % self.target_spec().replace(":", "-")
        return "%s → %s%s" % (self.listen_spec().replace(":", "-"), target, tail)

    def status_icon(self):
        if self.quota_hit:
            return "🚫"       # 超配额被停
        if not self.enabled:
            return "⏸"
        if self.healthy is False:
            return "❌"
        if self.healthy is True:
            return "✅"
        return "⚪"           # 还没测过

    def summary(self):
        bits = ["%s #%d %s" % (self.status_icon(), self.id, self.arrow())]
        if self.name:
            bits.append("(%s)" % self.name)
        if self.protocol != "tcp":
            bits.append("[%s]" % self.protocol)
        used = format_size(self.used)
        if self.quota:
            used = "%s / %s (%.0f%%)" % (used, format_size(self.quota),
                                         100.0 * self.used / self.quota)
        extra = ["流量 %s" % used]
        if self.speed:
            extra.append("限速 %s" % format_rate(self.speed))
        if self.healthy is True and self.latency_ms is not None:
            extra.append("延迟 %dms" % self.latency_ms)
        return " ".join(bits) + "\n    " + "，".join(extra)


class Store:
    """规则的 JSON 持久化，负责分配 id 和原子落盘。"""

    def __init__(self, path):
        self.path = path
        self.rules = []
        self.next_id = 1
        self.load()

    def load(self):
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (ValueError, OSError) as exc:
            LOG.error("规则文件 %s 读取失败(%s)，按空规则启动（原文件不会被覆盖到下次保存）",
                      self.path, exc)
            return
        self.rules = []
        for item in data.get("rules") or []:
            try:
                self.rules.append(Rule.from_dict(item))
            except (KeyError, ValueError, TypeError) as exc:
                LOG.error("跳过一条损坏的规则 %r: %s", item, exc)
        self.next_id = int(data.get("next_id") or 0) or self._max_id() + 1

    def _max_id(self):
        return max((r.id for r in self.rules), default=0)

    def save(self):
        payload = {"next_id": self.next_id,
                   "rules": [r.to_dict() for r in self.rules],
                   "saved_at": time.time()}
        directory = os.path.dirname(os.path.abspath(self.path))
        try:
            if directory and not os.path.isdir(directory):
                os.makedirs(directory, exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=1)
            os.replace(tmp, self.path)
        except OSError as exc:
            LOG.error("规则文件保存失败: %s", exc)

    def get(self, rule_id):
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None

    def add(self, **kwargs):
        rule = Rule(id=self.next_id, **kwargs)
        self.next_id += 1
        self.rules.append(rule)
        self.save()
        return rule

    def remove(self, rule_id):
        rule = self.get(rule_id)
        if rule:
            self.rules.remove(rule)
            self.save()
        return rule

    def port_conflict(self, start, end, protocols, exclude_id=None):
        """本机监听端口不能和已有规则重叠（同协议）。"""
        for rule in self.rules:
            if rule.id == exclude_id:
                continue
            if not set(protocols) & set(rule.protocols):
                continue
            if start <= rule.listen_end and rule.listen_start <= end:
                return rule
        return None

    def active(self):
        """真正应该下到 iptables 的规则。"""
        return [r for r in self.rules
                if r.enabled and not r.quota_hit and r.resolved_ip]


# --------------------------------------------------------------------------- #
# iptables / tc 封装
# --------------------------------------------------------------------------- #
class Runner:
    """外部命令执行器。全部用参数列表调用，绝不拼 shell 字符串。"""

    def run(self, args, check=False):
        try:
            proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=30)
        except FileNotFoundError:
            if check:
                raise CommandError(args, 127, "找不到命令 %s" % args[0])
            return 127, "", "找不到命令 %s" % args[0]
        except subprocess.TimeoutExpired:
            if check:
                raise CommandError(args, 124, "命令超时")
            return 124, "", "命令超时"
        out = proc.stdout.decode("utf-8", "replace")
        err = proc.stderr.decode("utf-8", "replace")
        if check and proc.returncode != 0:
            raise CommandError(args, proc.returncode, err.strip() or out.strip())
        return proc.returncode, out, err


class CommandError(Exception):
    def __init__(self, args, code, message):
        super().__init__("%s 执行失败(%d): %s" % (" ".join(args[:3]), code, message))
        self.args_list = args
        self.code = code
        self.message = message


class Nat:
    """用 iptables 做 DNAT/SNAT 转发，规则全部关在自定义链里。"""

    def __init__(self, runner=None, snat_mode="auto", snat_ip=None, iface=None):
        self.run = (runner or Runner()).run
        self.snat_mode = snat_mode
        self.snat_ip = snat_ip
        self.iface = iface

    # -- 底层 ------------------------------------------------------------- #
    def _ipt(self, args, table=None, check=True):
        cmd = ["iptables", "-w", "5"]
        if table:
            cmd += ["-t", table]
        return self.run(cmd + args, check=check)

    def _chain_exists(self, chain, table=None):
        return self._ipt(["-L", chain, "-n"], table=table, check=False)[0] == 0

    def _rule_exists(self, args, table=None):
        return self._ipt(["-C"] + args, table=table, check=False)[0] == 0

    # -- 环境准备 --------------------------------------------------------- #
    def available(self):
        return self.run(["iptables", "-V"], check=False)[0] == 0

    def ip_forward_enabled(self):
        try:
            with open("/proc/sys/net/ipv4/ip_forward") as handle:
                return handle.read().strip() == "1"
        except OSError:
            return False

    def enable_ip_forward(self, persist=True):
        """打开内核转发；不开的话 DNAT 出去的包会被直接丢弃。"""
        if not self.ip_forward_enabled():
            try:
                with open("/proc/sys/net/ipv4/ip_forward", "w") as handle:
                    handle.write("1")
                LOG.info("已打开 net.ipv4.ip_forward")
            except OSError as exc:
                LOG.error("打不开 ip_forward: %s（转发不会生效）", exc)
                return False
        if persist:
            path = "/etc/sysctl.d/99-tgfwd.conf"
            try:
                if not os.path.exists(path):
                    with open(path, "w") as handle:
                        handle.write("# tgfwd 端口转发需要\nnet.ipv4.ip_forward = 1\n")
                    LOG.info("已写入 %s，重启后依然生效", path)
            except OSError as exc:
                LOG.warning("ip_forward 持久化失败(%s)，重启后可能需要手动开", exc)
        return True

    def ensure_chains(self):
        """建自定义链并挂到主链上，幂等。"""
        for table, chain, parent in (("nat", CHAIN_PRE, "PREROUTING"),
                                     ("nat", CHAIN_POST, "POSTROUTING"),
                                     ("filter", CHAIN_FWD, "FORWARD"),
                                     ("mangle", CHAIN_MANGLE, "POSTROUTING")):
            if not self._chain_exists(chain, table):
                self._ipt(["-N", chain], table=table)
                LOG.debug("建链 %s/%s", table, chain)
            if not self._rule_exists([parent, "-j", chain], table=table):
                # 插在最前面，避免被用户已有规则抢先处理
                self._ipt(["-I", parent, "1", "-j", chain], table=table)
                LOG.debug("挂链 %s/%s -> %s", table, parent, chain)

    # -- 规则下发 --------------------------------------------------------- #
    def _snat_target(self):
        if self.snat_mode == "masquerade":
            return ["-j", "MASQUERADE"]
        addr = self.snat_ip or local_ip()
        if addr:
            return ["-j", "SNAT", "--to-source", addr]
        LOG.warning("探测不到本机出口 IP，改用 MASQUERADE（每包多一次路由查询）")
        return ["-j", "MASQUERADE"]

    def rule_args(self, rule):
        """返回这条规则要下发的全部 iptables 命令（(table, args) 列表）。"""
        out = []
        snat = self._snat_target()
        for proto in rule.protocols:
            tag = "TGF:%d" % rule.id
            # ① DNAT：进来的包换目的地址
            out.append(("nat", ["-A", CHAIN_PRE, "-p", proto,
                                "--dport", rule.listen_spec(),
                                "-m", "comment", "--comment", tag,
                                "-j", "DNAT", "--to-destination", rule.dnat_dest()]))
            # ② SNAT：出去的包换源地址，否则落地机会直接回给真实客户端导致连接失败
            out.append(("nat", ["-A", CHAIN_POST, "-p", proto,
                                "-d", rule.resolved_ip, "--dport", rule.target_spec(),
                                "-m", "comment", "--comment", tag] + snat))
            # ③ 放行 + 计数。nat 表的计数器只算首包，流量统计必须放在 filter/FORWARD
            out.append(("filter", ["-A", CHAIN_FWD, "-p", proto,
                                   "-d", rule.resolved_ip, "--dport", rule.target_spec(),
                                   "-m", "comment", "--comment", "%s:out" % tag,
                                   "-j", "ACCEPT"]))
            out.append(("filter", ["-A", CHAIN_FWD, "-p", proto,
                                   "-s", rule.resolved_ip, "--sport", rule.target_spec(),
                                   "-m", "comment", "--comment", "%s:in" % tag,
                                   "-j", "ACCEPT"]))
            # ④ 限速用的 fwmark：回程包（落地机→用户）此时源端口已被还原成监听端口
            if rule.speed > 0:
                out.append(("mangle", ["-A", CHAIN_MANGLE, "-p", proto,
                                       "--sport", rule.listen_spec(),
                                       "-m", "comment", "--comment", tag,
                                       "-j", "MARK", "--set-mark", str(rule.id)]))
        return out

    def sync(self, rules):
        """全量重建：清空自定义链，再把所有生效规则下进去。"""
        self.ensure_chains()
        for table, chain in (("nat", CHAIN_PRE), ("nat", CHAIN_POST),
                             ("filter", CHAIN_FWD), ("mangle", CHAIN_MANGLE)):
            self._ipt(["-F", chain], table=table, check=False)

        applied, failed = 0, []
        for rule in rules:
            try:
                for table, args in self.rule_args(rule):
                    self._ipt(args, table=table)
                applied += 1
                rule.counter_base = {"in": 0, "out": 0}   # 计数器跟着清零了
            except CommandError as exc:
                failed.append((rule, exc.message))
                LOG.error("规则 #%d 下发失败: %s", rule.id, exc.message)
        LOG.info("iptables 已同步：%d 条生效%s", applied,
                 "，%d 条失败" % len(failed) if failed else "")
        return applied, failed

    # -- 流量计数 --------------------------------------------------------- #
    def read_counters(self):
        """读 filter/TGF_FWD 的字节计数器 -> {rule_id: {"in": n, "out": n}}。"""
        code, out, _ = self.run(["iptables-save", "-c", "-t", "filter"], check=False)
        if code != 0:
            return {}
        counters = {}
        for line in out.splitlines():
            if CHAIN_FWD not in line:
                continue
            tag = COMMENT_RE.search(line)
            counter = COUNTER_RE.match(line)
            if not (tag and counter):
                continue
            entry = counters.setdefault(int(tag.group(1)), {"in": 0, "out": 0})
            entry[tag.group(2)] += int(counter.group(2))
        return counters

    def zero_counters(self):
        self._ipt(["-Z", CHAIN_FWD], check=False)

    # -- 卸载 ------------------------------------------------------------- #
    def teardown(self):
        """摘链 + 清空 + 删链，把本脚本留下的痕迹清干净。"""
        removed = 0
        for table, chain, parent in (("nat", CHAIN_PRE, "PREROUTING"),
                                     ("nat", CHAIN_POST, "POSTROUTING"),
                                     ("filter", CHAIN_FWD, "FORWARD"),
                                     ("mangle", CHAIN_MANGLE, "POSTROUTING")):
            while self._rule_exists([parent, "-j", chain], table=table):
                self._ipt(["-D", parent, "-j", chain], table=table, check=False)
            if self._chain_exists(chain, table):
                self._ipt(["-F", chain], table=table, check=False)
                self._ipt(["-X", chain], table=table, check=False)
                removed += 1
        return removed


def default_iface():
    """从路由表里找默认出口网卡。"""
    try:
        with open("/proc/net/route") as handle:
            for line in handle.readlines()[1:]:
                fields = line.split()
                if len(fields) > 2 and fields[1] == "00000000":     # 目的地 0.0.0.0
                    return fields[0]
    except OSError:
        pass
    return None


class Shaper:
    """用 tc HTB + fwmark 限速。

    只限**出方向**（中转机 → 用户，也就是用户的下载速度）——对看片场景这正是
    要限的那一头。入方向要靠 ifb 虚拟网卡，复杂度和出错率都高得多，不做。
    """

    DEFAULT_CLASS = "9999"

    def __init__(self, runner=None, iface=None):
        self.run = (runner or Runner()).run
        self.iface = iface or default_iface()
        self.ready = False

    def available(self):
        return self.iface is not None and self.run(["tc", "-V"], check=False)[0] == 0

    def _root_qdisc(self):
        code, out, _ = self.run(["tc", "qdisc", "show", "dev", self.iface], check=False)
        if code != 0:
            return None
        for line in out.splitlines():
            if " root " in line:
                return line.strip()
        return None

    def ensure_root(self):
        """建 HTB 根队列。已经有别人的 qdisc 时宁可不限速，也不覆盖人家的配置。"""
        if self.ready:
            return True
        existing = self._root_qdisc()
        if existing and "htb 1:" not in existing:
            benign = any(k in existing for k in ("noqueue", "pfifo_fast", "mq", "fq_codel"))
            if not benign:
                LOG.error("网卡 %s 上已有其它 qdisc（%s），为免冲突不启用限速。"
                          "如需限速请先手动清理：tc qdisc del dev %s root",
                          self.iface, existing, self.iface)
                return False
            self.run(["tc", "qdisc", "del", "dev", self.iface, "root"], check=False)
        if not existing or "htb 1:" not in (existing or ""):
            code, _, err = self.run(["tc", "qdisc", "add", "dev", self.iface, "root",
                                     "handle", "1:", "htb", "default", self.DEFAULT_CLASS],
                                    check=False)
            if code != 0:
                LOG.error("建立 tc 根队列失败: %s", err.strip())
                return False
            # 兜底类：没打 mark 的流量走这里，不受限
            self.run(["tc", "class", "add", "dev", self.iface, "parent", "1:",
                      "classid", "1:%s" % self.DEFAULT_CLASS, "htb", "rate", "10gbit"],
                     check=False)
        self.ready = True
        return True

    def sync(self, rules):
        """按规则重建限速类。"""
        limited = [r for r in rules if r.speed > 0]
        if not limited:
            return 0
        if not self.available():
            LOG.warning("找不到 tc 命令或默认网卡，限速不生效（转发本身不受影响）。"
                        "Debian/Ubuntu 装一下：apt install -y iproute2")
            return 0
        if not self.ensure_root():
            return 0
        done = 0
        for rule in limited:
            rate = "%dbit" % rule.speed
            classid = "1:%d" % rule.id
            self.run(["tc", "class", "del", "dev", self.iface, "classid", classid],
                     check=False)
            code, _, err = self.run(["tc", "class", "add", "dev", self.iface, "parent", "1:",
                                     "classid", classid, "htb", "rate", rate, "ceil", rate],
                                    check=False)
            if code != 0:
                LOG.error("规则 #%d 限速类建立失败: %s", rule.id, err.strip())
                continue
            self.run(["tc", "filter", "add", "dev", self.iface, "parent", "1:",
                      "protocol", "ip", "prio", "1", "handle", str(rule.id), "fw",
                      "flowid", classid], check=False)
            done += 1
        if done:
            LOG.info("限速已应用到 %d 条规则（网卡 %s，仅限下行）", done, self.iface)
        return done

    def teardown(self):
        if not self.iface:
            return False
        existing = self._root_qdisc()
        if existing and "htb 1:" in existing:
            self.run(["tc", "qdisc", "del", "dev", self.iface, "root"], check=False)
            self.ready = False
            return True
        return False


# --------------------------------------------------------------------------- #
# 监控：流量采样 / 配额 / 健康检查 / 域名重解析
# --------------------------------------------------------------------------- #
class Monitor:
    def __init__(self, store, nat, notify, health_fails=3, connect_timeout=5.0):
        self.store = store
        self.nat = nat
        self.notify = notify            # callable(text)
        self.health_fails = health_fails
        self.connect_timeout = connect_timeout

    # -- 流量 ------------------------------------------------------------- #
    def sample_traffic(self):
        """读计数器累加到 used。返回因超配额而被停用的规则。"""
        counters = self.nat.read_counters()
        if not counters:
            return []
        for rule in self.store.rules:
            current = counters.get(rule.id)
            if current is None:
                continue
            for direction in ("in", "out"):
                now = current[direction]
                base = rule.counter_base.get(direction, 0)
                # 计数器被清零或规则重建过 -> 从头算，不会算出负数
                rule.used += now - base if now >= base else now
                rule.counter_base[direction] = now
        return self.enforce_quota()

    def enforce_quota(self):
        stopped = []
        for rule in self.store.rules:
            if rule.quota and not rule.quota_hit and rule.used >= rule.quota:
                rule.quota_hit = True
                stopped.append(rule)
                LOG.warning("规则 #%d 流量超额（%s/%s），已自动停用",
                            rule.id, format_size(rule.used), format_size(rule.quota))
        if stopped:
            self.store.save()
            lines = ["⚠️ 以下转发已达流量上限，自动停用："]
            lines += ["  #%d %s  %s / %s" % (r.id, r.arrow(), format_size(r.used),
                                             format_size(r.quota)) for r in stopped]
            lines.append("\n用 /reset <id> 清零流量后会自动恢复。")
            self.notify("\n".join(lines))
        return stopped

    # -- 健康检查 --------------------------------------------------------- #
    def probe(self, rule):
        """探测落地机。返回 (是否通, 延迟毫秒)。"""
        if not rule.resolved_ip:
            return False, None
        if rule.protocol == "udp":
            # UDP 没法握手，退而求其次 ping 一下主机存活
            code, _, _ = Runner().run(
                ["ping", "-c", "1", "-W", "2", rule.resolved_ip], check=False)
            return code == 0, None
        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.connect_timeout)
        try:
            sock.connect((rule.resolved_ip, rule.target_start))
            return True, int((time.time() - start) * 1000)
        except OSError:
            return False, None
        finally:
            sock.close()

    def health_check(self):
        """跑一轮探测，掉线/恢复时发 TG 告警。"""
        down, up = [], []
        for rule in self.store.rules:
            if not rule.enabled or rule.quota_hit:
                continue
            ok, latency = self.probe(rule)
            was = rule.healthy
            rule.latency_ms = latency
            if ok:
                rule.fail_streak = 0
                rule.healthy = True
                if was is False:
                    up.append(rule)
            else:
                rule.fail_streak += 1
                if rule.fail_streak >= self.health_fails:
                    rule.healthy = False
                    if was is not False:
                        down.append(rule)
        if down:
            self.notify("🔴 落地机不通了：\n" + "\n".join(
                "  #%d %s%s  连续 %d 次探测失败"
                % (r.id, r.arrow(), " (%s)" % r.name if r.name else "", r.fail_streak)
                for r in down))
        if up:
            self.notify("🟢 落地机恢复了：\n" + "\n".join(
                "  #%d %s%s  延迟 %s"
                % (r.id, r.arrow(), " (%s)" % r.name if r.name else "",
                   "%dms" % r.latency_ms if r.latency_ms is not None else "-")
                for r in up))
        if down or up:
            self.store.save()
        return down, up

    # -- 域名重解析 ------------------------------------------------------- #
    def refresh_dns(self):
        """落地机写域名时，IP 变了要重建 DNAT——这是裸 iptables 的短板，在这补上。"""
        changed = []
        for rule in self.store.rules:
            if rule.host_kind != "domain":
                continue
            addr = resolve(rule.host)
            if addr and addr != rule.resolved_ip:
                LOG.info("规则 #%d 的 %s 解析变了：%s -> %s",
                         rule.id, rule.host, rule.resolved_ip, addr)
                rule.resolved_ip = addr
                changed.append(rule)
        if changed:
            self.store.save()
            self.notify("🔄 落地机 IP 变了，已自动重建转发：\n" + "\n".join(
                "  #%d %s → %s" % (r.id, r.host, r.resolved_ip) for r in changed))
        return changed


# --------------------------------------------------------------------------- #
# Telegram 命令
# --------------------------------------------------------------------------- #
HELP_TEXT = """\
🔀 tgfwd 端口转发管理 v%s

━━ 规则 ━━
/add <本地端口> <落地IP或域名> [落地端口] [备注]
    /add 8096 1.2.3.4              本机8096 → 1.2.3.4:8096
    /add 8096 emby.abc.com 8920 主力
    /add 10000-10100 1.2.3.4       整段转发
/del <id>          删除转发
/list              列出全部规则
/info <id>         看某条的详情
/on <id>  /off <id>   启用 / 停用
/proto <id> <tcp|udp|both>   改协议

━━ 流量 / 限速 ━━
/traffic           流量排行
/quota <id> <500G> 设流量上限，超了自动停（0=不限）
/speed <id> <100M> 限速，单位 Mbps（0=不限，只限下行）
/reset <id|all>    流量清零，被超额停用的会自动恢复

━━ 运维 ━━
/check             立刻探测所有落地机
/status            系统与运行状态
/sync              强制重建 iptables 规则
/id                查当前聊天和你自己的 id
/help              这条帮助"""


class Bot:
    """把 TG 消息翻译成对规则的增删改查。"""

    PUBLIC = ("id", "start", "help")

    def __init__(self, api, cfg, store, nat, shaper, monitor):
        self.api = api
        self.cfg = cfg
        self.store = store
        self.nat = nat
        self.shaper = shaper
        self.monitor = monitor
        self.me = {}
        self.started_at = time.time()
        self._denied_at = {}
        self.pending_sync = False

    # -- 收发 ------------------------------------------------------------- #
    def send(self, chat_id, text):
        self.api.call("sendMessage",
                      {"chat_id": chat_id, "text": truncate(text),
                       "disable_web_page_preview": True},
                      raise_on_error=False)

    def notify(self, text):
        """主动告警发给所有管理员（以及可选的通知群）。"""
        targets = list(self.cfg.admins)
        if self.cfg.notify_chat:
            targets.append(self.cfg.notify_chat)
        for target in targets:
            self.send(target, text)

    # -- 分发 ------------------------------------------------------------- #
    def handle(self, msg):
        text = (msg.get("text") or "").strip()
        if not text.startswith("/"):
            return
        chat = msg.get("chat") or {}
        user = msg.get("from") or {}
        parts = text.split()
        command = parts[0][1:].split("@")[0].lower()
        if "@" in parts[0]:
            addressed = parts[0].split("@")[-1].lower()
            if addressed != (self.me.get("username") or "").lower():
                return
        args = parts[1:]

        if command in self.PUBLIC:
            self.send(chat["id"], self._public(command, chat, user))
            return

        if user.get("id") not in self.cfg.admins:
            LOG.warning("拒绝越权命令 /%s，来自 user_id=%s", command, user.get("id"))
            # 限一分钟回一次，免得被人当探测工具刷
            if time.time() - self._denied_at.get(user.get("id"), 0) > 60:
                self._denied_at[user.get("id")] = time.time()
                self.send(chat["id"], "⛔ 你没有权限操作转发。\n"
                                      "如果这台机器是你的，把 %s 填进 config.json 的 admins 里。"
                          % user.get("id"))
            return

        handler = getattr(self, "cmd_" + command, None)
        if handler is None:
            self.send(chat["id"], "没有 /%s 这个命令，/help 看看有哪些。" % command)
            return
        try:
            reply = handler(args)
        except UsageError as exc:
            reply = "⚠️ %s" % exc
        except CommandError as exc:
            LOG.error("命令 /%s 执行系统命令失败: %s", command, exc)
            reply = "❌ 系统命令执行失败：%s" % exc.message
        except Exception as exc:                        # noqa: BLE001
            LOG.exception("命令 /%s 出错", command)
            reply = "❌ 内部错误：%s" % exc
        if reply:
            self.send(chat["id"], reply)

    def _public(self, command, chat, user):
        if command == "id":
            return ("chat_id：%s\n你的 user_id：%s\n\n把 user_id 填进 config.json 的 "
                    "admins 里才能管理转发。" % (chat.get("id"), user.get("id", "-")))
        return HELP_TEXT % __version__

    # -- 工具 ------------------------------------------------------------- #
    def _rule(self, args, what="规则"):
        if not args:
            raise UsageError("要指定%s编号，比如 /del 1" % what)
        try:
            rule_id = int(args[0].lstrip("#"))
        except ValueError:
            raise UsageError("编号得是数字：%s" % args[0])
        rule = self.store.get(rule_id)
        if not rule:
            raise UsageError("没有 #%d 这条规则，/list 看看现有的。" % rule_id)
        return rule

    def apply(self):
        """规则变动后重建 iptables + tc。"""
        applied, failed = self.nat.sync(self.store.active())
        self.shaper.sync(self.store.active())
        self.pending_sync = False
        if failed:
            return "\n⚠️ 有 %d 条下发失败：\n%s" % (
                len(failed), "\n".join("  #%d %s" % (r.id, m) for r, m in failed))
        return ""

    # -- 规则命令 --------------------------------------------------------- #
    def cmd_add(self, args):
        if len(args) < 2:
            raise UsageError("用法：/add <本地端口> <落地IP或域名> [落地端口] [备注]\n"
                             "例：/add 8096 1.2.3.4 8096 Emby")
        listen_start, listen_end = parse_ports(args[0])
        host_kind, host = parse_host(args[1])

        rest = args[2:]
        if rest and PORT_RANGE_RE.match(rest[0]):
            target_start, target_end = parse_ports(rest[0])
            rest = rest[1:]
        else:
            target_start, target_end = listen_start, listen_end
        if (target_end - target_start) != (listen_end - listen_start):
            raise UsageError("端口段长度要一致：本地 %d 个，落地 %d 个"
                             % (listen_end - listen_start + 1, target_end - target_start + 1))
        name = " ".join(rest)[:64]

        clash = self.store.port_conflict(listen_start, listen_end, ("tcp",))
        if clash:
            raise UsageError("本地端口 %s 和 #%d(%s) 冲突了"
                             % (args[0], clash.id, clash.arrow()))

        resolved = host if host_kind == "ip" else resolve(host)
        if not resolved:
            raise UsageError("域名 %s 解析不出 IP，先确认 DNS 没问题。" % host)

        rule = self.store.add(name=name, listen_start=listen_start, listen_end=listen_end,
                              host=host, host_kind=host_kind, target_start=target_start,
                              target_end=target_end, resolved_ip=resolved)
        warn = self.apply()
        ok, latency = self.monitor.probe(rule)
        rule.healthy = ok
        rule.latency_ms = latency
        self.store.save()
        probe = ("✅ 落地机可达，延迟 %dms" % latency) if ok and latency is not None else \
                ("✅ 落地机可达" if ok else "⚠️ 落地机现在连不上，规则已加，注意检查防火墙")
        return "已添加 #%d  %s\n%s%s" % (rule.id, rule.arrow(), probe, warn)

    def cmd_del(self, args):
        rule = self._rule(args)
        self.store.remove(rule.id)
        warn = self.apply()
        return "已删除 #%d  %s（累计跑了 %s）%s" % (
            rule.id, rule.arrow(), format_size(rule.used), warn)

    def cmd_list(self, args):
        if not self.store.rules:
            return "还没有转发规则。\n/add 8096 1.2.3.4 加一条试试。"
        lines = ["共 %d 条转发：" % len(self.store.rules), ""]
        lines += [r.summary() for r in sorted(self.store.rules, key=lambda r: r.id)]
        lines.append("\n✅可达 ❌不通 ⏸停用 🚫超额 ⚪未探测")
        return "\n".join(lines)

    def cmd_info(self, args):
        rule = self._rule(args)
        lines = [
            "#%d %s %s" % (rule.id, rule.status_icon(), rule.name or "(无备注)"),
            "本机端口：%s" % rule.listen_spec().replace(":", "-"),
            "落地机：%s%s:%s" % (rule.host,
                                 "" if rule.host_kind == "ip" else " (%s)" % rule.resolved_ip,
                                 rule.target_spec().replace(":", "-")),
            "协议：%s" % rule.protocol,
            "状态：%s" % ("超额停用" if rule.quota_hit else
                          "已启用" if rule.enabled else "已停用"),
            "流量：%s%s" % (format_size(rule.used),
                            " / %s" % format_size(rule.quota) if rule.quota else "（不限）"),
            "限速：%s%s" % (format_rate(rule.speed),
                             "（⚠️ tc 不可用，实际未生效）"
                             if rule.speed and not self.shaper.available() else ""),
            "健康：%s" % ("可达 %dms" % rule.latency_ms
                          if rule.healthy and rule.latency_ms is not None else
                          "可达" if rule.healthy else
                          "不通（连续失败 %d 次）" % rule.fail_streak if rule.healthy is False
                          else "未探测"),
            "创建于：%s前" % format_duration(time.time() - rule.created_at),
        ]
        return "\n".join(lines)

    def cmd_on(self, args):
        rule = self._rule(args)
        rule.enabled = True
        if rule.quota_hit and (not rule.quota or rule.used < rule.quota):
            rule.quota_hit = False
        self.store.save()
        return "已启用 #%d %s%s" % (rule.id, rule.arrow(), self.apply())

    def cmd_off(self, args):
        rule = self._rule(args)
        rule.enabled = False
        self.store.save()
        return "已停用 #%d %s%s" % (rule.id, rule.arrow(), self.apply())

    def cmd_proto(self, args):
        rule = self._rule(args)
        if len(args) < 2 or args[1].lower() not in ("tcp", "udp", "both"):
            raise UsageError("用法：/proto <id> <tcp|udp|both>")
        rule.protocol = args[1].lower()
        self.store.save()
        return "#%d 协议改为 %s%s" % (rule.id, rule.protocol, self.apply())

    # -- 流量命令 --------------------------------------------------------- #
    def cmd_traffic(self, args):
        self.monitor.sample_traffic()
        if not self.store.rules:
            return "还没有转发规则。"
        ranked = sorted(self.store.rules, key=lambda r: r.used, reverse=True)
        total = sum(r.used for r in self.store.rules)
        lines = ["流量排行（累计 %s）：" % format_size(total), ""]
        for rule in ranked:
            bar = ""
            if rule.quota:
                filled = int(min(1.0, float(rule.used) / rule.quota) * 10)
                bar = "  [%s%s]" % ("█" * filled, "░" * (10 - filled))
            lines.append("#%-3d %-28s %s%s" % (rule.id, rule.arrow(),
                                               format_size(rule.used), bar))
            if rule.quota:
                lines.append("     上限 %s%s" % (format_size(rule.quota),
                                                 "  ⚠️已超额停用" if rule.quota_hit else ""))
        return "\n".join(lines)

    def cmd_quota(self, args):
        rule = self._rule(args)
        if len(args) < 2:
            raise UsageError("用法：/quota <id> <500G>（0 表示不限）")
        rule.quota = parse_size(args[1])
        if rule.quota_hit and (not rule.quota or rule.used < rule.quota):
            rule.quota_hit = False
        self.store.save()
        extra = self.apply() if not rule.quota_hit else ""
        if rule.quota:
            return "#%d 流量上限设为 %s（已用 %s）%s" % (
                rule.id, format_size(rule.quota), format_size(rule.used), extra)
        return "#%d 已取消流量限制%s" % (rule.id, extra)

    def cmd_speed(self, args):
        rule = self._rule(args)
        if len(args) < 2:
            raise UsageError("用法：/speed <id> <100M>，单位 Mbps（0 表示不限）")
        rule.speed = parse_rate(args[1])
        self.store.save()
        warn = self.apply()
        if rule.speed and not self.shaper.available():
            warn += "\n⚠️ 这台机器上 tc 不可用，限速没生效（转发正常）。"
        return "#%d 限速设为 %s（只限下行）%s" % (rule.id, format_rate(rule.speed), warn)

    def cmd_reset(self, args):
        if args and args[0].lower() == "all":
            targets = list(self.store.rules)
        else:
            targets = [self._rule(args)]
        self.nat.zero_counters()
        for rule in targets:
            rule.used = 0
            rule.counter_base = {"in": 0, "out": 0}
            rule.quota_hit = False
        self.store.save()
        return "已清零 %s 的流量%s" % (
            "全部 %d 条规则" % len(targets) if len(targets) > 1 else "#%d" % targets[0].id,
            self.apply())

    # -- 运维命令 --------------------------------------------------------- #
    def cmd_check(self, args):
        self.monitor.health_check()
        if not self.store.rules:
            return "还没有转发规则。"
        lines = ["落地机探测结果：", ""]
        for rule in sorted(self.store.rules, key=lambda r: r.id):
            if not rule.enabled:
                lines.append("⏸ #%d %s  已停用，跳过" % (rule.id, rule.arrow()))
            elif rule.healthy:
                lines.append("✅ #%d %s  %s" % (
                    rule.id, rule.arrow(),
                    "%dms" % rule.latency_ms if rule.latency_ms is not None else "通"))
            else:
                lines.append("❌ #%d %s  不通" % (rule.id, rule.arrow()))
        return "\n".join(lines)

    def cmd_status(self, args):
        self.monitor.sample_traffic()
        active = self.store.active()
        lines = [
            "🖥 tgfwd 运行状态",
            "",
            "已运行：%s" % format_duration(time.time() - self.started_at),
            "转发规则：%d 条（生效 %d）" % (len(self.store.rules), len(active)),
            "累计流量：%s" % format_size(sum(r.used for r in self.store.rules)),
            "ip_forward：%s" % ("已开" if self.nat.ip_forward_enabled() else "❌ 没开！转发不会生效"),
            "限速(tc)：%s" % ("可用，网卡 %s" % self.shaper.iface
                              if self.shaper.available() else "不可用"),
        ]
        try:
            load = os.getloadavg()
            lines.append("负载：%.2f %.2f %.2f" % load)
        except OSError:
            pass
        down = [r for r in self.store.rules if r.healthy is False]
        if down:
            lines.append("\n❌ 不通的落地机：" + "、".join("#%d" % r.id for r in down))
        return "\n".join(lines)

    def cmd_sync(self, args):
        warn = self.apply()
        return "已重建 %d 条 iptables 规则%s" % (len(self.store.active()), warn)


# --------------------------------------------------------------------------- #
# 配置
# --------------------------------------------------------------------------- #
class Config:
    def __init__(self, data, path):
        if not isinstance(data, dict):
            raise ConfigError("配置文件最外层必须是一个对象 {...}")
        self.path = path
        self.token = self._token(data.get("bot_token", ""))
        if not self.token:
            raise ConfigError(
                "没有找到 bot_token。在 config.json 里填，或设环境变量 TG_BOT_TOKEN。\n"
                "token 找 Telegram 上的 @BotFather 用 /newbot 拿。")
        self.admins = [int(x) for x in (data.get("admins") or [])]
        if not self.admins:
            raise ConfigError(
                "admins 不能为空——这个 bot 能改 iptables，必须限定谁能用。\n"
                "先跑 `tgfwd.py --init`，或者把机器人拉进对话发 /id 拿到你的 user_id。")
        self.notify_chat = data.get("notify_chat") or None
        self.api_base = str(data.get("api_base") or DEFAULT_API_BASE)
        self.proxy = data.get("proxy") or os.environ.get("TG_PROXY") or None
        self.rules_file = data.get("rules_file") or DEFAULT_STORE
        self.log_level = str(data.get("log_level") or "INFO").upper()
        self.log_file = data.get("log_file") or None
        self.snat_mode = str(data.get("snat_mode") or "auto").lower()
        if self.snat_mode not in ("auto", "snat", "masquerade"):
            raise ConfigError("snat_mode 只能是 auto / snat / masquerade")
        self.snat_ip = data.get("snat_ip") or None
        self.iface = data.get("iface") or None
        self.traffic_interval = int(data.get("traffic_interval") or TRAFFIC_INTERVAL)
        self.health_interval = int(data.get("health_interval") or HEALTH_INTERVAL)
        self.health_fails = int(data.get("health_fails") or 3)
        self.dns_interval = int(data.get("dns_interval") or DNS_INTERVAL)
        self.startup_notify = bool(data.get("startup_notify", True))

    @staticmethod
    def _token(value):
        token = str(value or "").strip()
        if token.startswith("env:"):
            token = os.environ.get(token[4:], "").strip()
        if not token or token.upper().startswith("PUT_YOUR"):
            token = (os.environ.get("TG_BOT_TOKEN") or os.environ.get("BOT_TOKEN") or "").strip()
        return token

    @classmethod
    def load(cls, path):
        if not os.path.exists(path):
            raise ConfigError("找不到配置文件 %s。\n先跑 `sudo python3 %s --init` 生成一份。"
                              % (path, os.path.basename(sys.argv[0])))
        try:
            with open(path, "r", encoding="utf-8-sig") as handle:
                data = json.load(handle)
        except ValueError as exc:
            raise ConfigError("%s 不是合法 JSON：%s\n"
                              "常见原因：中文引号“”、最后一项多了逗号。" % (path, exc))
        except OSError as exc:
            raise ConfigError("读不了 %s：%s" % (path, exc))
        return cls(data, path)


# --------------------------------------------------------------------------- #
# 主程序
# --------------------------------------------------------------------------- #
class App:
    def __init__(self, cfg):
        self.cfg = cfg
        self.api = BotAPI(cfg.token, cfg.api_base, cfg.proxy)
        self.store = Store(cfg.rules_file)
        self.nat = Nat(snat_mode=cfg.snat_mode, snat_ip=cfg.snat_ip, iface=cfg.iface)
        self.shaper = Shaper(iface=cfg.iface)
        self.bot = Bot(self.api, cfg, self.store, self.nat, self.shaper, None)
        self.monitor = Monitor(self.store, self.nat, self.bot.notify, cfg.health_fails)
        self.bot.monitor = self.monitor
        self.offset = 0
        self.running = True
        self.tasks = [
            ["traffic", cfg.traffic_interval, self._task_traffic],
            ["health", cfg.health_interval, self._task_health],
            ["dns", cfg.dns_interval, self._task_dns],
            ["save", STATE_SAVE_INTERVAL, self._task_save],
        ]
        now = time.time()
        self.due = {name: now + interval for name, interval, _ in self.tasks}

    # -- 定时任务 --------------------------------------------------------- #
    def _task_traffic(self):
        if self.monitor.sample_traffic():
            self.nat.sync(self.store.active())       # 有规则被停，重建

    def _task_health(self):
        self.monitor.health_check()

    def _task_dns(self):
        if self.monitor.refresh_dns():
            self.nat.sync(self.store.active())       # 落地机 IP 变了，重建
            self.shaper.sync(self.store.active())

    def _task_save(self):
        self.store.save()

    # -- 启动 ------------------------------------------------------------- #
    def prepare(self):
        self.bot.me = self.api.call("getMe")
        LOG.info("机器人已连接：@%s", self.bot.me.get("username"))

        hook = self.api.call("getWebhookInfo", raise_on_error=False) or {}
        if hook.get("url"):
            LOG.warning("该 bot 设了 webhook(%s)，与轮询冲突，自动删除", hook["url"])
            self.api.call("deleteWebhook", {"drop_pending_updates": False},
                          raise_on_error=False)

        self.nat.enable_ip_forward()
        self.monitor.refresh_dns()
        applied, failed = self.nat.sync(self.store.active())
        self.shaper.sync(self.store.active())
        self.monitor.health_check()

        LOG.info("共 %d 条规则，%d 条已生效", len(self.store.rules), applied)
        if self.cfg.startup_notify:
            down = [r for r in self.store.rules if r.healthy is False]
            self.bot.notify("🚀 tgfwd 已启动\n转发规则 %d 条，生效 %d 条%s%s"
                            % (len(self.store.rules), applied,
                               "\n⚠️ %d 条下发失败" % len(failed) if failed else "",
                               "\n❌ %d 台落地机不通" % len(down) if down else ""))

    # -- 主循环 ----------------------------------------------------------- #
    def run(self):
        self.prepare()
        LOG.info("开始监听命令，Ctrl+C 退出")
        while self.running:
            timeout = self._poll_timeout()
            updates = self.api.call(
                "getUpdates",
                {"offset": self.offset, "timeout": timeout,
                 "allowed_updates": ["message"]},
                timeout=timeout + 20, raise_on_error=False)
            if updates is None:
                time.sleep(3)
            else:
                for update in updates:
                    self.offset = max(self.offset, update["update_id"] + 1)
                    message = update.get("message")
                    if not message:
                        continue
                    try:
                        self.bot.handle(message)
                    except Exception:                 # noqa: BLE001
                        LOG.exception("处理命令时出现未预期的异常")
            self._run_due_tasks()
        self.store.save()
        LOG.info("已退出（iptables 规则保留，需要清理跑 --uninstall）")

    def _poll_timeout(self):
        """挂起到下一个定时任务到期为止，最多 25 秒。单线程、不空转。"""
        now = time.time()
        nearest = min(self.due.values()) if self.due else now + POLL_TIMEOUT
        return max(0, min(POLL_TIMEOUT, int(math.ceil(nearest - now))))

    def _run_due_tasks(self):
        now = time.time()
        for name, interval, func in self.tasks:
            if now < self.due.get(name, 0):
                continue
            self.due[name] = now + interval
            try:
                func()
            except Exception:                         # noqa: BLE001
                LOG.exception("定时任务 %s 出错", name)

    def stop(self, *_args):
        if self.running:
            LOG.info("收到退出信号…")
        self.running = False


# --------------------------------------------------------------------------- #
# --check / --init / --uninstall
# --------------------------------------------------------------------------- #
def require_root():
    if os.geteuid() != 0:
        LOG.error("需要 root 权限才能操作 iptables，请用 sudo 运行。")
        return False
    return True


def run_check(cfg):
    print("== 体检开始 ==")
    problems = 0

    if os.geteuid() == 0:
        print("✓ 以 root 运行")
    else:
        print("✗ 不是 root，iptables 操作会失败——请加 sudo")
        problems += 1

    nat = Nat(snat_mode=cfg.snat_mode, snat_ip=cfg.snat_ip)
    if nat.available():
        print("✓ iptables 可用")
    else:
        print("✗ 找不到 iptables：Debian/Ubuntu 装 `apt install -y iptables`")
        problems += 1

    if nat.ip_forward_enabled():
        print("✓ net.ipv4.ip_forward 已开启")
    else:
        print("! net.ipv4.ip_forward 没开，启动时会自动打开（转发必需）")

    shaper = Shaper(iface=cfg.iface)
    if shaper.available():
        print("✓ tc 可用（网卡 %s），限速功能可用" % shaper.iface)
    else:
        print("! 找不到 tc 或默认网卡，限速不可用（转发本身不受影响）")

    addr = cfg.snat_ip or local_ip()
    print("✓ 本机出口 IP：%s（SNAT 源地址）" % addr if addr
          else "! 探测不到本机出口 IP，将用 MASQUERADE")

    try:
        me = BotAPI(cfg.token, cfg.api_base, cfg.proxy).call("getMe")
        print("✓ bot token 有效：@%s" % me.get("username"))
    except ApiError as exc:
        if exc.code == 0:
            print("✗ 连不上 Telegram：%s" % exc.description)
            print("  国内机器需要代理：config.json 里加 \"proxy\": \"http://127.0.0.1:7890\"，")
            print("  或设环境变量 HTTPS_PROXY。")
        else:
            print("✗ bot token 无效：%s" % exc.description)
        problems += 1

    print("✓ 管理员：%s" % "、".join(str(a) for a in cfg.admins))

    store = Store(cfg.rules_file)
    print("\n-- 规则 %d 条 --" % len(store.rules))
    for rule in store.rules:
        print("  " + rule.summary().replace("\n    ", "  |  "))

    print("\n== 体检结束：%s ==" % ("发现 %d 个问题" % problems if problems else "一切正常"))
    return 1 if problems else 0


def run_init(path):
    if os.path.exists(path):
        if input("%s 已存在，覆盖吗？(y/N) " % path).strip().lower() != "y":
            print("已取消。")
            return 1

    print("== tgfwd 交互式配置 ==\n")
    token = ""
    while not token:
        token = input("1) 粘贴 @BotFather 给的 bot token：").strip()
        if not token:
            continue
        try:
            me = BotAPI(token).call("getMe")
            print("   ✓ 验证通过：@%s\n" % me.get("username"))
        except ApiError as exc:
            print("   ✗ 验证失败：%s\n" % exc)
            token = ""

    print("2) 你的 Telegram user_id（只有这些人能管理转发）")
    print("   不知道就先给机器人发一条 /id，它会告诉你。")
    admins = []
    while not admins:
        raw = input("   user_id（多个用逗号分隔）：").strip()
        admins = [int(x) for x in re.split(r"[,，\s]+", raw) if x.strip().isdigit()]
        if not admins:
            print("   ✗ 至少要填一个数字 id，这关系到谁能改你的防火墙。")

    config = {
        "bot_token": token,
        "admins": admins,
        "rules_file": DEFAULT_STORE,
        "log_level": "INFO",
        "snat_mode": "auto",
        "traffic_interval": TRAFFIC_INTERVAL,
        "health_interval": HEALTH_INTERVAL,
        "health_fails": 3,
        "dns_interval": DNS_INTERVAL,
    }
    directory = os.path.dirname(os.path.abspath(path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(config, handle, ensure_ascii=False, indent=2)
    os.chmod(path, 0o600)
    print("\n✓ 已写入 %s（权限 600）" % path)
    print("下一步：sudo python3 %s --check，没问题就 sudo python3 %s"
          % (sys.argv[0], sys.argv[0]))
    return 0


def run_uninstall(cfg):
    if not require_root():
        return 2
    nat = Nat(snat_mode=cfg.snat_mode if cfg else "auto")
    removed = nat.teardown()
    shaper = Shaper(iface=cfg.iface if cfg else None)
    tc_done = shaper.teardown()
    print("已删除 %d 条自定义链%s。" % (removed, "，并清理了 tc 限速" if tc_done else ""))
    print("规则文件和配置没动，重新启动脚本就会恢复转发。")
    return 0


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #
def setup_logging(level, log_file=None):
    root = logging.getLogger()
    root.setLevel(getattr(logging, level, logging.INFO))
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%m-%d %H:%M:%S")
    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(fmt)
    root.handlers = [stream]
    if log_file:
        try:
            handler = logging.handlers.RotatingFileHandler(
                log_file, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
            handler.setFormatter(fmt)
            root.addHandler(handler)
        except OSError as exc:
            root.warning("日志文件 %s 打不开: %s", log_file, exc)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="tgfwd.py",
        description="TG bot 管理的 iptables 端口转发（中转）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例：\n"
               "  sudo python3 tgfwd.py --init       生成配置\n"
               "  sudo python3 tgfwd.py --check      体检\n"
               "  sudo python3 tgfwd.py             开始运行\n"
               "  sudo python3 tgfwd.py --uninstall  清掉所有转发规则\n")
    parser.add_argument("-c", "--config", default=DEFAULT_CONFIG,
                        help="配置文件路径（默认 %s）" % DEFAULT_CONFIG)
    parser.add_argument("--init", action="store_true", help="交互式生成配置")
    parser.add_argument("--check", action="store_true", help="检查环境和 token 后退出")
    parser.add_argument("--uninstall", action="store_true",
                        help="清掉本脚本下发的所有 iptables/tc 规则")
    parser.add_argument("-v", "--verbose", action="store_true", help="调试日志")
    parser.add_argument("--version", action="version", version="tgfwd %s" % __version__)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.init:
        setup_logging("INFO")
        try:
            return run_init(args.config)
        except (KeyboardInterrupt, EOFError):
            print("\n已取消。")
            return 1

    try:
        cfg = Config.load(args.config)
    except ConfigError as exc:
        setup_logging("INFO")
        if args.uninstall:          # 没配置也得能清理
            return run_uninstall(None)
        LOG.error("%s", exc)
        return 2

    setup_logging("DEBUG" if args.verbose else cfg.log_level, cfg.log_file)

    if args.uninstall:
        return run_uninstall(cfg)
    if args.check:
        return run_check(cfg)
    if not require_root():
        return 2

    app = App(cfg)
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, app.stop)
        except (ValueError, AttributeError):
            pass
    try:
        app.run()
    except ApiError as exc:
        if exc.code == 409:
            LOG.error("另一个实例正在用同一个 token 轮询，先停掉它。")
        elif exc.code == 401:
            LOG.error("bot token 无效或已被重置。")
        elif exc.code == 0:
            LOG.error("连不上 Telegram：%s", exc.description)
            LOG.error("需要代理就在 config.json 里配 proxy，或设 HTTPS_PROXY。")
        else:
            LOG.error("启动失败：%s", exc)
        return 2
    except KeyboardInterrupt:
        app.store.save()
    return 0


if __name__ == "__main__":
    sys.exit(main())
