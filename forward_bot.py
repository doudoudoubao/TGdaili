#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TG Bot 一键转发 / 搬运脚本。

零第三方依赖，只用 Python 标准库，通过 Telegram Bot API 的 long polling
把「源聊天」的新消息按规则转发到「目标聊天」。

常用命令::

    python3 forward_bot.py --init        # 交互式生成 config.json
    python3 forward_bot.py --discover    # 只打印收到消息的 chat_id，方便抄配置
    python3 forward_bot.py --check       # 体检：token、频道权限、是否能发言
    python3 forward_bot.py               # 正式跑

注意 Bot API 的能力边界：
  * 机器人只能收到「它自己所在聊天」里的新消息（源频道需把它设为管理员，
    群里需要在 @BotFather 用 /setprivacy 关闭隐私模式，或直接给管理员）；
  * 机器人读不到历史消息，只能从脚本运行的那一刻开始搬；
  * 源频道开启了「禁止转发/保存内容」时，转发接口会被 Telegram 拒绝。
  以上三条都绕不过去，需要的话得改用用户账号方案（Telethon/Pyrogram）。
"""

from __future__ import annotations

import argparse
import json
import logging
import logging.handlers
import math
import os
import random
import re
import signal
import sys
import time
from urllib import error as urlerror
from urllib import request as urlrequest

__version__ = "1.0.0"

LOG = logging.getLogger("tgforward")

DEFAULT_API_BASE = "https://api.telegram.org"
DEFAULT_CONFIG = "config.json"
DEFAULT_STATE = "state.json"

POLL_TIMEOUT = 25          # long polling 挂起秒数
ALBUM_WAIT = 2.0           # 相册(媒体组)聚合等待秒数
MAX_SEEN = 5000            # 去重记录上限
MAX_EDIT_MAP = 2000        # 「原消息 -> 已发副本」映射上限
TEXT_LIMIT = 4096
CAPTION_LIMIT = 1024

ALLOWED_UPDATES = [
    "message",
    "edited_message",
    "channel_post",
    "edited_channel_post",
    "my_chat_member",
]

# 判断消息类型时的检查顺序：animation 必须排在 document/video 前面，
# 因为 GIF 消息同时带 animation 和 document 两个字段。
MEDIA_KEYS = (
    "animation",
    "photo",
    "video",
    "video_note",
    "audio",
    "voice",
    "sticker",
    "document",
    "poll",
    "dice",
    "contact",
    "location",
    "venue",
    "story",
    "game",
    "invoice",
    "paid_media",
)

# 入群/改标题/置顶之类的系统消息，一律不搬
SERVICE_KEYS = (
    "new_chat_members", "left_chat_member", "new_chat_title", "new_chat_photo",
    "delete_chat_photo", "group_chat_created", "supergroup_chat_created",
    "channel_chat_created", "message_auto_delete_timer_changed",
    "migrate_to_chat_id", "migrate_from_chat_id", "pinned_message",
    "successful_payment", "users_shared", "chat_shared", "write_access_allowed",
    "proximity_alert_triggered", "forum_topic_created", "forum_topic_edited",
    "forum_topic_closed", "forum_topic_reopened", "video_chat_scheduled",
    "video_chat_started", "video_chat_ended", "video_chat_participants_invited",
    "web_app_data", "giveaway_created", "giveaway_completed", "boost_added",
)

# sendMediaGroup 只接受这四种
ALBUM_SENDABLE = {"photo": "photo", "video": "video", "audio": "audio", "document": "document"}

URL_RE = re.compile(r"(?i)(?:https?://|www\.)\S+|(?<![\w.])t\.me/\S+")
USERNAME_RE = re.compile(r"(?<![\w/@])@[A-Za-z][A-Za-z0-9_]{3,31}")
HASHTAG_RE = re.compile(r"(?<!\w)#\w+")
LINE_COMMENT_RE = re.compile(r"^\s*//.*$", re.M)
TOKEN_RE = re.compile(r"^\d{5,}:[A-Za-z0-9_-]{30,}$")


# --------------------------------------------------------------------------- #
# 小工具
# --------------------------------------------------------------------------- #
def chat_label(chat):
    """把 chat 对象渲染成人能看懂的一行字。"""
    if not isinstance(chat, dict):
        return str(chat)
    name = chat.get("title") or " ".join(
        x for x in (chat.get("first_name"), chat.get("last_name")) if x
    ) or "(无标题)"
    username = chat.get("username")
    at = " @%s" % username if username else ""
    return "%s%s [%s]" % (name, at, chat.get("id"))


def truncate(text, limit):
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def message_type(msg):
    """返回消息类型：text / photo / video / ... / service / other。"""
    for key in SERVICE_KEYS:
        if key in msg:
            return "service"
    for key in MEDIA_KEYS:
        if key in msg:
            return key
    if msg.get("text") is not None:
        return "text"
    return "other"


def message_text(msg):
    return msg.get("text") or msg.get("caption") or ""


def load_jsonc(path):
    """读带 // 注释的 JSON（注释只在整行开头生效，不会破坏 URL 里的 //）。"""
    with open(path, "r", encoding="utf-8-sig") as handle:
        raw = handle.read()
    try:
        return json.loads(LINE_COMMENT_RE.sub("", raw))
    except ValueError as exc:
        raise ConfigError(
            "%s 不是合法的 JSON：%s\n"
            "最常见的原因：用了中文引号“”、最后一项多了逗号、或者少了括号。" % (path, exc)
        )


class ConfigError(Exception):
    pass


# --------------------------------------------------------------------------- #
# Bot API
# --------------------------------------------------------------------------- #
class ApiError(Exception):
    def __init__(self, method, code, description, parameters=None):
        super().__init__("%s 失败 (%s): %s" % (method, code, description))
        self.method = method
        self.code = code
        self.description = description or ""
        self.parameters = parameters or {}


class BotAPI:
    """极简 Bot API 客户端：JSON over HTTPS，自带 429/网络错误重试。"""

    def __init__(self, token, api_base=DEFAULT_API_BASE, proxy=None):
        self._url = "%s/bot%s" % (api_base.rstrip("/"), token)
        if proxy:
            handler = urlrequest.ProxyHandler({"http": proxy, "https": proxy})
            self._opener = urlrequest.build_opener(handler)
        else:
            # 默认 opener 会读取 HTTP_PROXY / HTTPS_PROXY 环境变量
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
                               body.get("description") or raw[:200],
                               body.get("parameters"))
            except (urlerror.URLError, OSError, ValueError) as exc:
                err = ApiError(method, 0, "网络错误: %s" % exc)

            retry_after = err.parameters.get("retry_after")
            if retry_after and flood_hits < 5 and float(retry_after) <= 300:
                flood_hits += 1
                wait = float(retry_after) + 0.5
                LOG.warning("触发限流(429)，%.1fs 后重试 %s", wait, method)
                time.sleep(wait)
                continue

            retriable = err.code in (0, 429, 500, 502, 503, 504)
            if retriable and attempt <= retries:
                wait = min(2 ** attempt, 16) + random.random()
                LOG.warning("%s，%.1fs 后重试(%d/%d)", err, wait, attempt, retries)
                time.sleep(wait)
                continue

            if raise_on_error:
                raise err
            LOG.error("%s", err)
            return None


# --------------------------------------------------------------------------- #
# 规则
# --------------------------------------------------------------------------- #
class Rule:
    """一条「从哪些聊天搬到哪些聊天」的规则。"""

    def __init__(self, raw, index, defaults):
        if not isinstance(raw, dict):
            raise ConfigError("rules[%d] 必须是一个对象 {...}" % index)

        def opt(key, fallback):
            if key in raw:
                return raw[key]
            return defaults.get(key, fallback)

        self.index = index
        self.name = raw.get("name") or "规则#%d" % (index + 1)
        self.enabled = bool(opt("enabled", True))
        self.sources = self._chat_list(raw.get("from"), "rules[%d].from" % index)
        self.targets = self._chat_list(raw.get("to"), "rules[%d].to" % index)
        if not self.sources:
            raise ConfigError("%s: from 不能为空（源聊天 id 或 @用户名）" % self.name)
        if not self.targets:
            raise ConfigError("%s: to 不能为空（目标聊天 id 或 @用户名）" % self.name)

        self.mode = str(opt("mode", "copy")).lower()
        if self.mode not in ("copy", "forward"):
            raise ConfigError("%s: mode 只能是 copy 或 forward" % self.name)

        self.send_delay = float(opt("send_delay", 0.5))
        self.silent = bool(opt("silent", False))
        self.no_preview = bool(opt("disable_web_page_preview", False))
        self.on_edit = str(opt("on_edit", "ignore")).lower()
        if self.on_edit not in ("ignore", "edit", "resend"):
            raise ConfigError("%s: on_edit 只能是 ignore / edit / resend" % self.name)

        self.allow_types = [str(t).lower() for t in opt("allow_types", []) or []]
        self.block_types = [str(t).lower() for t in opt("block_types", []) or []]

        self.include_keywords = self._keywords(opt("include_keywords", []), "include_keywords")
        self.exclude_keywords = self._keywords(opt("exclude_keywords", []), "exclude_keywords")

        self.remove_links = bool(opt("remove_links", False))
        self.remove_usernames = bool(opt("remove_usernames", False))
        self.remove_hashtags = bool(opt("remove_hashtags", False))
        self.header = str(opt("header", "") or "")
        self.footer = str(opt("footer", "") or "")
        self.replacements = self._replacements(opt("replace", []))

        self.sent = 0
        self.skipped = 0

    # -- 解析 ------------------------------------------------------------- #
    @staticmethod
    def _chat_list(value, where):
        if value is None:
            return []
        if not isinstance(value, list):
            value = [value]
        out = []
        for item in value:
            if isinstance(item, bool):
                raise ConfigError("%s 里出现了 true/false，应该是 chat id 或 @用户名" % where)
            if isinstance(item, int):
                out.append(item)
                continue
            text = str(item).strip()
            if not text:
                continue
            if re.match(r"^-?\d+$", text):
                out.append(int(text))
            elif text.startswith("@"):
                out.append(text.lower())
            else:
                out.append("@" + text.lstrip("@").lower())
        return out

    @staticmethod
    def _keywords(value, where):
        if not value:
            return []
        if not isinstance(value, list):
            value = [value]
        out = []
        for item in value:
            text = str(item)
            if text.startswith("re:"):
                try:
                    out.append(("re", re.compile(text[3:], re.I | re.S)))
                except re.error as exc:
                    raise ConfigError("%s 里的正则 %r 无效: %s" % (where, text[3:], exc))
            else:
                out.append(("plain", text.lower()))
        return out

    @staticmethod
    def _replacements(value):
        if not value:
            return []
        out = []
        for item in value:
            if isinstance(item, (list, tuple)):
                item = {"from": item[0], "to": item[1] if len(item) > 1 else ""}
            if not isinstance(item, dict):
                raise ConfigError("replace 的每一项应为 {\"from\": ..., \"to\": ...}")
            src = str(item.get("from", ""))
            dst = str(item.get("to", ""))
            if not src:
                continue
            if item.get("regex"):
                try:
                    out.append({"regex": True, "re": re.compile(src, re.I | re.S), "to": dst})
                except re.error as exc:
                    raise ConfigError("replace 里的正则 %r 无效: %s" % (src, exc))
            else:
                out.append({"regex": False, "from": src, "to": dst})
        return out

    # -- 匹配 ------------------------------------------------------------- #
    @staticmethod
    def _chat_hit(chat, patterns):
        chat_id = chat.get("id")
        username = ("@" + chat["username"].lower()) if chat.get("username") else None
        for pattern in patterns:
            if isinstance(pattern, int):
                if pattern == chat_id:
                    return True
            elif username and pattern == username:
                return True
        return False

    def matches_source(self, chat):
        return self._chat_hit(chat, self.sources)

    def allows_type(self, kinds):
        """kinds 是一组类型（单条消息一个，相册可能多个 + media_group）。"""
        kinds = set(kinds)
        if self.block_types and kinds & set(self.block_types):
            return False
        if self.allow_types and not (kinds & set(self.allow_types)):
            return False
        return True

    def _kw_hit(self, keywords, text):
        low = text.lower()
        for kind, value in keywords:
            if kind == "re":
                if value.search(text):
                    return True
            elif value in low:
                return True
        return False

    def keyword_ok(self, text):
        if self.include_keywords and not self._kw_hit(self.include_keywords, text):
            return False
        if self.exclude_keywords and self._kw_hit(self.exclude_keywords, text):
            return False
        return True

    @property
    def rewrites_text(self):
        return bool(self.replacements or self.remove_links or self.remove_usernames
                    or self.remove_hashtags or self.header or self.footer)

    def transform(self, text):
        out = text or ""
        for rep in self.replacements:
            out = rep["re"].sub(rep["to"], out) if rep["regex"] else out.replace(rep["from"], rep["to"])
        if self.remove_links:
            out = URL_RE.sub("", out)
        if self.remove_usernames:
            out = USERNAME_RE.sub("", out)
        if self.remove_hashtags:
            out = HASHTAG_RE.sub("", out)
        out = re.sub(r"[ \t]+(\n|$)", r"\1", out)
        out = re.sub(r"\n{3,}", "\n\n", out).strip()
        if self.header:
            out = self.header + ("\n" + out if out else "")
        if self.footer:
            out = (out + "\n" if out else "") + self.footer
        return out

    def describe(self):
        return "%s: %s → %s [%s]%s" % (
            self.name,
            ", ".join(str(s) for s in self.sources),
            ", ".join(str(t) for t in self.targets),
            "搬运" if self.mode == "copy" else "转发",
            "" if self.enabled else " (已停用)",
        )


# --------------------------------------------------------------------------- #
# 配置
# --------------------------------------------------------------------------- #
class Config:
    def __init__(self, data, path):
        self.path = path
        self.raw = data
        if not isinstance(data, dict):
            raise ConfigError("配置文件最外层必须是一个对象 {...}")

        self.token = self._resolve_token(data.get("bot_token", ""))
        if not self.token:
            raise ConfigError(
                "没有找到 bot_token。请在 config.json 里填写，或设置环境变量 TG_BOT_TOKEN。\n"
                "token 从 Telegram 的 @BotFather 用 /newbot 获取。"
            )
        if not TOKEN_RE.match(self.token):
            LOG.warning("bot_token 看起来不像标准格式（应形如 123456789:AAE...），先按填写的值尝试")

        self.api_base = str(data.get("api_base") or DEFAULT_API_BASE)
        self.proxy = data.get("proxy") or os.environ.get("TG_PROXY") or None
        self.admins = [int(x) for x in (data.get("admins") or [])]
        self.log_level = str(data.get("log_level") or "INFO").upper()
        self.log_file = data.get("log_file") or None
        self.album_wait = float(data.get("album_wait", ALBUM_WAIT))
        self.state_file = data.get("state_file") or None

        defaults = data.get("default") or data.get("defaults") or {}
        if not isinstance(defaults, dict):
            raise ConfigError("default 必须是一个对象 {...}")

        raw_rules = data.get("rules")
        if raw_rules is None:
            raise ConfigError("配置里缺少 rules（转发规则列表）")
        if not isinstance(raw_rules, list):
            raise ConfigError("rules 必须是一个数组 [...]")
        self.rules = [Rule(raw, i, defaults) for i, raw in enumerate(raw_rules)]
        if not self.rules:
            raise ConfigError("rules 是空的，至少要配一条转发规则")

    @staticmethod
    def _resolve_token(value):
        token = str(value or "").strip()
        if token.startswith("env:"):
            token = os.environ.get(token[4:], "").strip()
        if not token or token.upper().startswith("PUT_YOUR") or token == "123456:ABC":
            token = (os.environ.get("TG_BOT_TOKEN") or os.environ.get("BOT_TOKEN") or "").strip()
        return token

    @classmethod
    def load(cls, path):
        if not os.path.exists(path):
            raise ConfigError(
                "找不到配置文件 %s。\n先跑 `python3 %s --init` 生成一份，"
                "或者把 config.example.json 复制成 config.json 再改。"
                % (path, os.path.basename(__file__))
            )
        return cls(load_jsonc(path), path)


# --------------------------------------------------------------------------- #
# 主逻辑
# --------------------------------------------------------------------------- #
class Forwarder:
    def __init__(self, config, state_path, discover_only=False):
        self.cfg = config
        self.api = BotAPI(config.token, config.api_base, config.proxy)
        self.state_path = state_path
        self.discover_only = discover_only
        self.state = self._load_state()
        self.albums = {}            # (chat_id, media_group_id) -> {msgs, ts}
        self.seen = list(self.state.get("seen") or [])
        self.seen_set = set(self.seen)
        self.copies = dict(self.state.get("copies") or {})
        self.paused = bool(self.state.get("paused"))
        self.running = True
        self.dirty = False
        self.me = {}
        self.started_at = time.time()
        self.total_sent = 0
        self.total_failed = 0
        self.last_error = ""
        self._announced = set()
        self._last_send = 0.0

    # -- 状态存取 --------------------------------------------------------- #
    def _load_state(self):
        if not os.path.exists(self.state_path):
            return {"offset": 0}
        try:
            with open(self.state_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            return data if isinstance(data, dict) else {"offset": 0}
        except (ValueError, OSError) as exc:
            LOG.warning("状态文件 %s 读取失败(%s)，按全新启动处理", self.state_path, exc)
            return {"offset": 0}

    def save_state(self, force=False):
        if not (self.dirty or force):
            return
        self.state["seen"] = self.seen[-MAX_SEEN:]
        self.state["copies"] = self.copies
        self.state["paused"] = self.paused
        tmp = self.state_path + ".tmp"
        try:
            directory = os.path.dirname(os.path.abspath(self.state_path))
            if directory and not os.path.isdir(directory):
                os.makedirs(directory, exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as handle:
                json.dump(self.state, handle, ensure_ascii=False)
            os.replace(tmp, self.state_path)
            self.dirty = False
        except OSError as exc:
            LOG.warning("状态文件写入失败: %s", exc)

    def _mark_seen(self, key):
        self.seen.append(key)
        self.seen_set.add(key)
        if len(self.seen) > MAX_SEEN * 2:
            dropped = self.seen[:-MAX_SEEN]
            self.seen = self.seen[-MAX_SEEN:]
            for item in dropped:
                self.seen_set.discard(item)

    def _remember_copy(self, src_key, chat_id, message_id):
        entry = self.copies.setdefault(src_key, [])
        entry.append([chat_id, message_id])
        if len(self.copies) > MAX_EDIT_MAP:
            for key in list(self.copies)[: len(self.copies) - MAX_EDIT_MAP]:
                self.copies.pop(key, None)

    # -- 启动 ------------------------------------------------------------- #
    def prepare(self):
        self.me = self.api.call("getMe")
        LOG.info("机器人已连接：@%s (%s)", self.me.get("username"), self.me.get("id"))

        info = self.api.call("getWebhookInfo", raise_on_error=False) or {}
        if info.get("url"):
            LOG.warning("检测到该 bot 已设置 webhook(%s)，与轮询冲突，正在自动删除", info["url"])
            self.api.call("deleteWebhook", {"drop_pending_updates": False}, raise_on_error=False)

        if self.discover_only:
            LOG.info("== 发现模式 ==：只打印 chat_id，不会转发任何消息")
        else:
            for rule in self.cfg.rules:
                LOG.info("规则 %s", rule.describe())
        if self.paused:
            LOG.warning("当前处于暂停状态（/resume 可恢复）")

    # -- 主循环 ----------------------------------------------------------- #
    def run(self):
        self.prepare()
        LOG.info("开始监听新消息，Ctrl+C 退出")
        while self.running:
            timeout = self._poll_timeout()
            updates = self.api.call(
                "getUpdates",
                {
                    "offset": self.state.get("offset", 0),
                    "timeout": timeout,
                    "allowed_updates": ALLOWED_UPDATES,
                },
                timeout=timeout + 20,
                raise_on_error=False,
            )
            if updates is None:
                time.sleep(3)
                continue
            for update in updates:
                self.state["offset"] = max(self.state.get("offset", 0), update["update_id"] + 1)
                self.dirty = True
                try:
                    self.handle_update(update)
                except ApiError as exc:
                    self.total_failed += 1
                    self.last_error = str(exc)
                    LOG.error("处理更新失败: %s", exc)
                except Exception:  # noqa: BLE001 - 单条消息出错不能弄崩整个进程
                    self.total_failed += 1
                    LOG.exception("处理更新时出现未预期的异常")
            self._flush_albums()
            self.save_state()
        self.save_state(force=True)
        LOG.info("已退出。累计转发 %d 条，失败 %d 条", self.total_sent, self.total_failed)

    def _poll_timeout(self):
        """有相册在缓冲时缩短挂起时间，保证它能及时被拼好发出去。"""
        if not self.albums:
            return POLL_TIMEOUT
        now = time.time()
        due = min(item["ts"] + self.cfg.album_wait for item in self.albums.values())
        return max(0, min(POLL_TIMEOUT, int(math.ceil(due - now))))

    def stop(self, *_args):
        if self.running:
            LOG.info("收到退出信号，正在保存状态…")
        self.running = False

    # -- 分发 ------------------------------------------------------------- #
    def handle_update(self, update):
        if "my_chat_member" in update:
            self._on_membership(update["my_chat_member"])
            return

        for key in ("message", "channel_post"):
            if key in update:
                self.on_message(update[key], edited=False)
                return
        for key in ("edited_message", "edited_channel_post"):
            if key in update:
                self.on_message(update[key], edited=True)
                return

    def _on_membership(self, event):
        chat = event.get("chat") or {}
        status = (event.get("new_chat_member") or {}).get("status", "?")
        LOG.info("机器人在 %s 的身份变为「%s」——如需转发，请把 %s 填进配置的 from/to",
                 chat_label(chat), status, chat.get("id"))

    def on_message(self, msg, edited):
        chat = msg.get("chat") or {}
        if message_type(msg) == "service":
            return

        if not edited and self._handle_command(msg):
            return

        if self.discover_only:
            LOG.info("收到消息：%s  类型=%s", chat_label(chat), message_type(msg))
            return

        matched = [r for r in self.cfg.rules if r.enabled and r.matches_source(chat)]
        if not matched:
            self._announce_unknown(chat)
            return
        if self.paused:
            LOG.debug("已暂停，丢弃来自 %s 的消息", chat.get("id"))
            return

        if edited:
            for rule in matched:
                self._handle_edit(rule, msg)
            return

        key = "%s:%s" % (chat.get("id"), msg.get("message_id"))
        if key in self.seen_set:
            LOG.debug("消息 %s 已处理过，跳过", key)
            return
        self._mark_seen(key)
        self.dirty = True

        group_id = msg.get("media_group_id")
        if group_id:
            bucket = self.albums.setdefault((chat.get("id"), group_id), {"msgs": [], "ts": 0.0})
            bucket["msgs"].append(msg)
            bucket["ts"] = time.time()
            if len(bucket["msgs"]) >= 10:       # 相册最多 10 项，收满就直接发
                self._flush_album((chat.get("id"), group_id))
            return

        for rule in matched:
            self.deliver(rule, [msg])

    def _announce_unknown(self, chat):
        chat_id = chat.get("id")
        if chat_id in self._announced:
            return
        self._announced.add(chat_id)
        LOG.info("收到未配置来源的消息：%s —— 若要搬运它，把 %s 填进某条规则的 from",
                 chat_label(chat), chat_id)

    # -- 相册 ------------------------------------------------------------- #
    def _flush_albums(self):
        now = time.time()
        for key in [k for k, v in self.albums.items() if now - v["ts"] >= self.cfg.album_wait]:
            self._flush_album(key)

    def _flush_album(self, key):
        bucket = self.albums.pop(key, None)
        if not bucket or not bucket["msgs"]:
            return
        msgs = sorted(bucket["msgs"], key=lambda m: m["message_id"])
        chat = msgs[0].get("chat") or {}
        for rule in self.cfg.rules:
            if rule.enabled and rule.matches_source(chat):
                try:
                    self.deliver(rule, msgs)
                except ApiError as exc:
                    self.total_failed += 1
                    self.last_error = str(exc)
                    LOG.error("相册转发失败: %s", exc)

    # -- 投递 ------------------------------------------------------------- #
    def deliver(self, rule, msgs):
        is_album = len(msgs) > 1
        kinds = {message_type(m) for m in msgs}
        if is_album:
            kinds.add("media_group")
        if not rule.allows_type(kinds):
            rule.skipped += 1
            LOG.debug("[%s] 类型 %s 被过滤", rule.name, ",".join(sorted(kinds)))
            return

        text = ""
        for msg in msgs:
            if message_text(msg):
                text = message_text(msg)
                break
        if not rule.keyword_ok(text):
            rule.skipped += 1
            LOG.info("[%s] 关键词过滤，跳过消息 %s", rule.name, msgs[0].get("message_id"))
            return

        new_text = rule.transform(text) if rule.rewrites_text else text
        if not new_text and not (kinds - {"text", "media_group"}):
            rule.skipped += 1
            LOG.info("[%s] 处理后内容为空，跳过", rule.name)
            return

        src_chat = msgs[0]["chat"]["id"]
        src_key = "%s:%s" % (src_chat, msgs[0]["message_id"])
        for target in rule.targets:
            self._pace(rule)
            try:
                sent = self._send(rule, msgs, target, text, new_text)
            except ApiError as exc:
                self.total_failed += 1
                self.last_error = str(exc)
                LOG.error("[%s] 发往 %s 失败: %s%s", rule.name, target, exc,
                          self._hint_for(exc))
                continue
            rule.sent += 1
            self.total_sent += 1
            for item in (sent if isinstance(sent, list) else [sent]):
                if isinstance(item, dict) and item.get("message_id"):
                    self._remember_copy(src_key, target, item["message_id"])
            self.dirty = True
            LOG.info("[%s] %s → %s 完成%s", rule.name, src_chat, target,
                     "（相册 %d 张）" % len(msgs) if len(msgs) > 1 else "")

    def _pace(self, rule):
        wait = rule.send_delay - (time.time() - self._last_send)
        if wait > 0:
            time.sleep(wait)
        self._last_send = time.time()

    def _send(self, rule, msgs, target, old_text, new_text):
        src = msgs[0]["chat"]["id"]
        ids = [m["message_id"] for m in msgs]
        changed = new_text != old_text

        if len(msgs) > 1:
            return self._send_album(rule, msgs, target, new_text, changed)

        msg = msgs[0]
        base = {
            "chat_id": target,
            "from_chat_id": src,
            "message_id": ids[0],
            "disable_notification": rule.silent or None,
        }
        if rule.mode == "forward":
            if changed:
                LOG.debug("[%s] forward 模式下无法改写文案，按原样转发", rule.name)
            return self.api.call("forwardMessage", base)

        if changed:
            if message_type(msg) == "text":
                return self.api.call("sendMessage", {
                    "chat_id": target,
                    "text": truncate(new_text, TEXT_LIMIT),
                    "disable_notification": rule.silent or None,
                    "disable_web_page_preview": rule.no_preview or None,
                })
            base["caption"] = truncate(new_text, CAPTION_LIMIT)

        try:
            return self.api.call("copyMessage", base)
        except ApiError as exc:
            desc = exc.description.lower()
            if exc.code in (400, 403) and ("copied" in desc or "copy" in desc):
                LOG.warning("[%s] copyMessage 无法复制该消息(%s)，改用 forwardMessage",
                            rule.name, exc.description)
                base.pop("caption", None)
                return self.api.call("forwardMessage", base)
            raise

    def _send_album(self, rule, msgs, target, new_text, changed):
        src = msgs[0]["chat"]["id"]
        ids = [m["message_id"] for m in msgs]
        batch = {
            "chat_id": target,
            "from_chat_id": src,
            "message_ids": ids,
            "disable_notification": rule.silent or None,
        }
        if rule.mode == "forward":
            return self._album_fallback(rule, msgs, target, "forwardMessages", batch)

        # 文案没变时直接整组复制，能原样保留格式与按钮
        if not changed:
            return self._album_fallback(rule, msgs, target, "copyMessages", batch)

        # 文案改了：用 file_id 重新组一个 media group，把新文案挂在第一项上
        media = []
        for msg in msgs:
            kind = message_type(msg)
            api_type = ALBUM_SENDABLE.get(kind)
            if not api_type:
                media = []
                break
            file_id = (msg["photo"][-1]["file_id"] if kind == "photo" else msg[kind]["file_id"])
            media.append({"type": api_type, "media": file_id})
        if media:
            media[0]["caption"] = truncate(new_text, CAPTION_LIMIT)
            try:
                return self.api.call("sendMediaGroup", {
                    "chat_id": target,
                    "media": media,
                    "disable_notification": rule.silent or None,
                })
            except ApiError as exc:
                LOG.warning("[%s] sendMediaGroup 失败(%s)，退回整组复制", rule.name, exc.description)
        return self._album_fallback(rule, msgs, target, "copyMessages", batch)

    def _album_fallback(self, rule, msgs, target, method, batch):
        """copyMessages/forwardMessages 不可用时，逐条发（相册会被拆开）。"""
        try:
            return self.api.call(method, batch)
        except ApiError as exc:
            if exc.code not in (400, 404):
                raise
            LOG.warning("[%s] %s 不可用(%s)，改为逐条发送", rule.name, method, exc.description)
            single = "forwardMessage" if method == "forwardMessages" else "copyMessage"
            results = []
            for msg in msgs:
                results.append(self.api.call(single, {
                    "chat_id": target,
                    "from_chat_id": msg["chat"]["id"],
                    "message_id": msg["message_id"],
                    "disable_notification": rule.silent or None,
                }))
                self._pace(rule)
            return results

    @staticmethod
    def _hint_for(exc):
        desc = (exc.description or "").lower()
        if "chat not found" in desc:
            return "（提示：目标 chat_id 写错了，或机器人还没被加进这个聊天）"
        if "not enough rights" in desc or "need administrator" in desc:
            return "（提示：机器人在目标频道需要管理员 + 发布消息权限）"
        if "bot was blocked" in desc or "bot was kicked" in desc:
            return "（提示：机器人被踢出或被拉黑了）"
        if "message can't be copied" in desc or "forward" in desc and "restrict" in desc:
            return "（提示：源频道开启了「禁止转发/保存内容」，Bot API 无法绕过）"
        return ""

    # -- 编辑同步 --------------------------------------------------------- #
    def _handle_edit(self, rule, msg):
        if rule.on_edit == "ignore":
            return
        src_key = "%s:%s" % (msg["chat"]["id"], msg["message_id"])
        if rule.on_edit == "resend":
            self.deliver(rule, [msg])
            return

        copies = self.copies.get(src_key) or []
        if not copies:
            LOG.debug("[%s] 找不到 %s 的副本，无法同步编辑", rule.name, src_key)
            return
        text = message_text(msg)
        new_text = rule.transform(text) if rule.rewrites_text else text
        is_text = message_type(msg) == "text"
        for chat_id, message_id in copies:
            params = {"chat_id": chat_id, "message_id": message_id}
            if is_text:
                params["text"] = truncate(new_text, TEXT_LIMIT)
                method = "editMessageText"
            else:
                params["caption"] = truncate(new_text, CAPTION_LIMIT)
                method = "editMessageCaption"
            if self.api.call(method, params, raise_on_error=False) is not None:
                LOG.info("[%s] 已同步编辑到 %s/%s", rule.name, chat_id, message_id)

    # -- 机器人命令 ------------------------------------------------------- #
    def _handle_command(self, msg):
        text = msg.get("text") or ""
        if not text.startswith("/"):
            return False
        entities = msg.get("entities") or []
        if not any(e.get("type") == "bot_command" and e.get("offset") == 0 for e in entities):
            return False

        parts = text.split()
        command = parts[0][1:].split("@")[0].lower()
        mention = "@" in parts[0]
        if mention and parts[0].split("@")[-1].lower() != (self.me.get("username") or "").lower():
            return False

        chat = msg.get("chat") or {}
        user = msg.get("from") or {}
        is_admin = user.get("id") in self.cfg.admins

        if command in ("start", "help"):
            self._reply(chat["id"], self._help_text(is_admin))
        elif command == "id":
            self._reply(chat["id"],
                        "聊天名称：%s\nchat_id：%s\n类型：%s\n你的 user_id：%s\n\n"
                        "把 chat_id 填到 config.json 的 from / to 里即可。"
                        % (chat.get("title") or chat.get("first_name") or "-",
                           chat.get("id"), chat.get("type"), user.get("id", "-")))
        elif command in ("status", "rules", "pause", "resume", "reload"):
            if not is_admin:
                if self.cfg.admins:
                    self._reply(chat["id"], "只有管理员能用这个命令。")
                else:
                    self._reply(chat["id"],
                                "管理命令未启用：请把你的 user_id 填进 config.json 的 admins 里。\n"
                                "你的 user_id 是 %s" % user.get("id", "-"))
                return True
            getattr(self, "_cmd_" + command)(chat["id"])
        else:
            return False
        return True

    def _help_text(self, is_admin):
        lines = [
            "TG 一键转发机器人 v%s" % __version__,
            "",
            "/id — 显示当前聊天的 chat_id（配置时用得到）",
            "/help — 显示这条帮助",
        ]
        if is_admin or not self.cfg.admins:
            lines += [
                "",
                "管理员命令：",
                "/status — 运行状态与统计",
                "/rules — 查看当前生效的规则",
                "/pause — 暂停转发",
                "/resume — 恢复转发",
                "/reload — 重新加载 config.json",
            ]
        return "\n".join(lines)

    def _cmd_status(self, chat_id):
        uptime = int(time.time() - self.started_at)
        lines = [
            "状态：%s" % ("已暂停" if self.paused else "运行中"),
            "已运行：%d 小时 %d 分" % (uptime // 3600, uptime % 3600 // 60),
            "累计转发：%d 条，失败 %d 条" % (self.total_sent, self.total_failed),
            "规则数：%d" % len(self.cfg.rules),
        ]
        for rule in self.cfg.rules:
            lines.append("  · %s 已发 %d / 过滤 %d" % (rule.name, rule.sent, rule.skipped))
        if self.last_error:
            lines.append("最近一次错误：%s" % truncate(self.last_error, 300))
        self._reply(chat_id, "\n".join(lines))

    def _cmd_rules(self, chat_id):
        self._reply(chat_id, "\n".join(r.describe() for r in self.cfg.rules))

    def _cmd_pause(self, chat_id):
        self.paused = True
        self.dirty = True
        self.save_state(force=True)
        self._reply(chat_id, "已暂停转发，/resume 恢复。")

    def _cmd_resume(self, chat_id):
        self.paused = False
        self.dirty = True
        self.save_state(force=True)
        self._reply(chat_id, "已恢复转发。")

    def _cmd_reload(self, chat_id):
        try:
            self.cfg = Config.load(self.cfg.path)
        except ConfigError as exc:
            self._reply(chat_id, "重新加载失败，仍在用旧配置：\n%s" % exc)
            return
        self._reply(chat_id, "配置已重新加载，当前 %d 条规则：\n%s"
                    % (len(self.cfg.rules), "\n".join(r.describe() for r in self.cfg.rules)))

    def _reply(self, chat_id, text):
        self.api.call("sendMessage",
                      {"chat_id": chat_id, "text": truncate(text, TEXT_LIMIT),
                       "disable_web_page_preview": True},
                      raise_on_error=False)


# --------------------------------------------------------------------------- #
# --check / --init
# --------------------------------------------------------------------------- #
def run_check(config):
    api = BotAPI(config.token, config.api_base, config.proxy)
    print("== 体检开始 ==")
    try:
        me = api.call("getMe")
    except ApiError as exc:
        if exc.code == 0:
            print("✗ 连不上 Telegram：%s" % exc.description)
            print("  服务器在国内/被墙时需要代理：在 config.json 里加 \"proxy\": \"http://127.0.0.1:7890\"，")
            print("  或设置环境变量 HTTPS_PROXY。先用 curl https://api.telegram.org 确认网络通不通。")
        else:
            print("✗ token 无效：%s" % exc)
            print("  请确认 config.json 里的 bot_token 来自 @BotFather，且没有多余空格。")
        return 1
    print("✓ token 有效：@%s (id=%s)" % (me.get("username"), me.get("id")))

    hook = api.call("getWebhookInfo", raise_on_error=False) or {}
    if hook.get("url"):
        print("! 该 bot 设了 webhook（%s），启动时会自动删除以便轮询" % hook["url"])

    problems = 0
    checked = {}
    for rule in config.rules:
        print("\n-- %s --" % rule.describe())
        for role, chats in (("源", rule.sources), ("目标", rule.targets)):
            for chat in chats:
                key = (role, str(chat))
                if key in checked:
                    continue
                checked[key] = True
                problems += _check_chat(api, me, role, chat)

    print("\n== 体检结束：%s ==" % ("发现 %d 个问题，按上面的提示修" % problems if problems else "一切正常"))
    return 1 if problems else 0


def _check_chat(api, me, role, chat):
    try:
        info = api.call("getChat", {"chat_id": chat})
    except ApiError as exc:
        print("  ✗ %s %s 读取失败：%s" % (role, chat, exc.description))
        print("    多半是 id 写错了，或者机器人还没被加进这个聊天。")
        return 1
    print("  ✓ %s %s" % (role, chat_label(info)))

    try:
        member = api.call("getChatMember", {"chat_id": chat, "user_id": me["id"]})
    except ApiError as exc:
        print("    ! 无法查询机器人身份：%s" % exc.description)
        return 1

    status = member.get("status")
    if role == "源":
        if info.get("type") == "channel" and status != "administrator":
            print("    ✗ 机器人在源频道不是管理员，收不到频道消息")
            return 1
        if status in ("left", "kicked"):
            print("    ✗ 机器人已不在该聊天里")
            return 1
        if info.get("type") in ("group", "supergroup") and status != "administrator":
            print("    ! 机器人不是群管理员：请在 @BotFather 用 /setprivacy 关闭隐私模式，"
                  "否则只能收到 @它 的消息")
    else:
        if status != "administrator" and info.get("type") == "channel":
            print("    ✗ 机器人在目标频道不是管理员，发不了消息")
            return 1
        if status == "administrator" and member.get("can_post_messages") is False:
            print("    ✗ 机器人缺少「发布消息」权限")
            return 1
        if status in ("left", "kicked"):
            print("    ✗ 机器人已不在该聊天里")
            return 1
    return 0


def run_init(path):
    if os.path.exists(path):
        answer = input("%s 已存在，覆盖吗？(y/N) " % path).strip().lower()
        if answer != "y":
            print("已取消。")
            return 1

    print("== 交互式配置 ==（直接回车可用默认值）\n")
    token = ""
    while not token:
        token = input("1) 粘贴 @BotFather 给你的 bot token：").strip()
        if not token:
            continue
        try:
            me = BotAPI(token).call("getMe")
            print("   ✓ 验证通过：@%s\n" % me.get("username"))
        except ApiError as exc:
            print("   ✗ token 验证失败：%s\n" % exc)
            token = ""

    print("2) 源聊天（从哪搬）——填 chat_id，多个用逗号分隔。")
    print("   不知道 id？先把机器人加进频道当管理员，然后跑：")
    print("   python3 %s --discover\n" % os.path.basename(__file__))
    sources = _split_ids(input("   源 chat_id：").strip())

    print("\n3) 目标聊天（搬到哪）——机器人必须是那里的管理员。")
    targets = _split_ids(input("   目标 chat_id：").strip())

    mode = input("\n4) 模式：1=搬运(不显示来源，默认) 2=转发(显示「转发自」)：").strip()
    admin = input("5) 你自己的 user_id（可留空，填了才能用 /status 等命令）：").strip()
    footer = input("6) 每条消息末尾要加的小尾巴（可留空）：").strip()

    config = {
        "bot_token": token,
        "admins": [int(admin)] if admin.isdigit() else [],
        "log_level": "INFO",
        "default": {
            "mode": "forward" if mode == "2" else "copy",
            "send_delay": 0.5,
        },
        "rules": [{
            "name": "默认规则",
            "enabled": True,
            "from": sources,
            "to": targets,
            "exclude_keywords": [],
            "footer": footer,
        }],
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(config, handle, ensure_ascii=False, indent=2)
    os.chmod(path, 0o600)
    print("\n✓ 已写入 %s（权限 600，里面有 token 别外传）" % path)
    print("下一步：python3 %s --check   然后   python3 %s"
          % (os.path.basename(__file__), os.path.basename(__file__)))
    return 0


def _split_ids(text):
    out = []
    for item in re.split(r"[,，\s]+", text or ""):
        item = item.strip()
        if not item:
            continue
        out.append(int(item) if re.match(r"^-?\d+$", item) else item)
    return out


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
        handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
        handler.setFormatter(fmt)
        root.addHandler(handler)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="forward_bot.py",
        description="TG Bot 一键转发 / 搬运脚本（零依赖）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例：\n"
               "  python3 forward_bot.py --init       生成配置\n"
               "  python3 forward_bot.py --discover   查 chat_id\n"
               "  python3 forward_bot.py --check      检查权限\n"
               "  python3 forward_bot.py              开始转发\n",
    )
    parser.add_argument("-c", "--config", default=DEFAULT_CONFIG, help="配置文件路径（默认 config.json）")
    parser.add_argument("-s", "--state", default=None, help="状态文件路径（默认 state.json）")
    parser.add_argument("--init", action="store_true", help="交互式生成配置文件")
    parser.add_argument("--check", action="store_true", help="检查 token 与频道权限后退出")
    parser.add_argument("--discover", action="store_true", help="只打印收到消息的 chat_id，不转发")
    parser.add_argument("-v", "--verbose", action="store_true", help="输出调试日志")
    parser.add_argument("--version", action="version", version="tgforward %s" % __version__)
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
        config = Config.load(args.config)
    except ConfigError as exc:
        setup_logging("INFO")
        LOG.error("%s", exc)
        return 2

    setup_logging("DEBUG" if args.verbose else config.log_level, config.log_file)

    if args.check:
        try:
            return run_check(config)
        except ApiError as exc:
            LOG.error("体检中断：%s", exc)
            return 2

    state_path = args.state or config.state_file or DEFAULT_STATE
    forwarder = Forwarder(config, state_path, discover_only=args.discover)
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, forwarder.stop)
        except (ValueError, AttributeError):
            pass
    try:
        forwarder.run()
    except ApiError as exc:
        if exc.code == 409:
            LOG.error("有另一个实例正在用同一个 token 轮询，请先停掉它再启动。")
        elif exc.code == 401:
            LOG.error("token 无效或已被 @BotFather 重置，请重新获取。")
        elif exc.code == 0:
            LOG.error("连不上 Telegram：%s", exc.description)
            LOG.error("需要代理的话，在 config.json 里配 proxy 或设置环境变量 HTTPS_PROXY。")
        else:
            LOG.error("启动失败：%s", exc)
        forwarder.save_state(force=True)
        return 2
    except KeyboardInterrupt:
        forwarder.save_state(force=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
