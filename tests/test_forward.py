#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""不需要真实 token 的离线测试：用假 API 记录调用，验证过滤/改写/相册/命令。

    python3 tests/test_forward.py
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forward_bot import ApiError, Config, ConfigError, Forwarder, Rule, message_type  # noqa: E402

SRC = -1001111111111
DST = -1002222222222


class FakeAPI(object):
    """把每次 API 调用记下来，不发任何网络请求。"""

    def __init__(self):
        self.calls = []
        self.fail_with = {}
        self._next_id = 1000

    def call(self, method, params=None, timeout=30, retries=3, raise_on_error=True):
        self.calls.append((method, params or {}))
        if method in self.fail_with:
            error = self.fail_with[method]
            if raise_on_error:
                raise error
            return None
        if method == "getMe":
            return {"id": 42, "username": "test_bot", "first_name": "Test"}
        self._next_id += 1
        return {"message_id": self._next_id}

    def methods(self):
        return [m for m, _ in self.calls]

    def last(self, method):
        for name, params in reversed(self.calls):
            if name == method:
                return params
        raise AssertionError("没有调用过 %s，实际调用：%s" % (method, self.methods()))


def make_forwarder(rule_overrides=None, admins=None):
    config = Config({
        "bot_token": "123456789:AAEabcdefghijklmnopqrstuvwxyz123456789",
        "admins": admins or [],
        "rules": [dict({"name": "测试", "from": [SRC], "to": [DST],
                        "send_delay": 0}, **(rule_overrides or {}))],
    }, "config.json")
    state = os.path.join(tempfile.mkdtemp(), "state.json")
    forwarder = Forwarder(config, state)
    forwarder.api = FakeAPI()
    forwarder.me = {"id": 42, "username": "test_bot"}
    return forwarder


def text_msg(text, msg_id=1, chat_id=SRC, **extra):
    msg = {"message_id": msg_id, "chat": {"id": chat_id, "type": "channel", "title": "源频道"},
           "text": text}
    msg.update(extra)
    return msg


def photo_msg(msg_id=1, caption=None, group=None, chat_id=SRC):
    msg = {"message_id": msg_id, "chat": {"id": chat_id, "type": "channel", "title": "源频道"},
           "photo": [{"file_id": "small%d" % msg_id}, {"file_id": "big%d" % msg_id}]}
    if caption is not None:
        msg["caption"] = caption
    if group is not None:
        msg["media_group_id"] = group
    return msg


class TestMessageType(unittest.TestCase):
    def test_basic_types(self):
        self.assertEqual(message_type(text_msg("hi")), "text")
        self.assertEqual(message_type(photo_msg()), "photo")

    def test_animation_wins_over_document(self):
        # GIF 消息同时带 animation 和 document，必须识别成 animation
        msg = {"animation": {"file_id": "a"}, "document": {"file_id": "d"}}
        self.assertEqual(message_type(msg), "animation")

    def test_service_message(self):
        self.assertEqual(message_type({"new_chat_members": []}), "service")


class TestRule(unittest.TestCase):
    def rule(self, **kwargs):
        return Rule(dict({"from": [SRC], "to": [DST]}, **kwargs), 0, {})

    def test_source_matching_by_id_and_username(self):
        rule = Rule({"from": [SRC, "@news"], "to": [DST]}, 0, {})
        self.assertTrue(rule.matches_source({"id": SRC}))
        self.assertTrue(rule.matches_source({"id": 999, "username": "News"}))
        self.assertFalse(rule.matches_source({"id": 999, "username": "other"}))

    def test_username_normalised(self):
        rule = Rule({"from": ["News"], "to": ["@Target"]}, 0, {})
        self.assertEqual(rule.sources, ["@news"])
        self.assertEqual(rule.targets, ["@target"])

    def test_keyword_include_exclude(self):
        rule = self.rule(include_keywords=["福利"], exclude_keywords=["广告", "re:加\\s*微信"])
        self.assertTrue(rule.keyword_ok("今天有福利"))
        self.assertFalse(rule.keyword_ok("今天没内容"))
        self.assertFalse(rule.keyword_ok("福利 广告"))
        self.assertFalse(rule.keyword_ok("福利 加 微信"))

    def test_type_filter(self):
        rule = self.rule(allow_types=["photo", "video"], block_types=["sticker"])
        self.assertTrue(rule.allows_type({"photo"}))
        self.assertFalse(rule.allows_type({"text"}))
        self.assertFalse(rule.allows_type({"photo", "sticker"}))

    def test_transform_pipeline(self):
        rule = self.rule(remove_links=True, remove_usernames=True,
                         replace=[{"from": "旧名", "to": "新名"}],
                         footer="—— 关注 @mine")
        out = rule.transform("旧名上新 https://t.me/spam 联系 @someguy")
        self.assertIn("新名上新", out)
        self.assertNotIn("t.me/spam", out)
        self.assertNotIn("@someguy", out)
        self.assertTrue(out.endswith("—— 关注 @mine"))  # footer 里的 @ 不受影响

    def test_regex_replace(self):
        rule = self.rule(replace=[{"from": r"\d{4,}", "to": "***", "regex": True}])
        self.assertEqual(rule.transform("电话 13800138000"), "电话 ***")

    def test_no_rewrite_when_nothing_configured(self):
        self.assertFalse(self.rule().rewrites_text)
        self.assertTrue(self.rule(footer="x").rewrites_text)

    def test_bad_regex_is_reported(self):
        with self.assertRaises(ConfigError):
            self.rule(exclude_keywords=["re:[unclosed"])


class TestConfig(unittest.TestCase):
    def test_missing_token(self):
        os.environ.pop("TG_BOT_TOKEN", None)
        os.environ.pop("BOT_TOKEN", None)
        with self.assertRaises(ConfigError):
            Config({"rules": []}, "c.json")

    def test_token_from_env(self):
        os.environ["TG_BOT_TOKEN"] = "1:" + "x" * 35
        try:
            cfg = Config({"bot_token": "env:TG_BOT_TOKEN",
                          "rules": [{"from": [SRC], "to": [DST]}]}, "c.json")
            self.assertTrue(cfg.token.startswith("1:"))
        finally:
            os.environ.pop("TG_BOT_TOKEN")

    def test_defaults_apply_to_rules(self):
        cfg = Config({"bot_token": "1:" + "x" * 35,
                      "default": {"mode": "forward", "footer": "尾巴"},
                      "rules": [{"from": [SRC], "to": [DST]},
                                {"from": [SRC], "to": [DST], "mode": "copy"}]}, "c.json")
        self.assertEqual(cfg.rules[0].mode, "forward")
        self.assertEqual(cfg.rules[0].footer, "尾巴")
        self.assertEqual(cfg.rules[1].mode, "copy")

    def test_empty_rules_rejected(self):
        with self.assertRaises(ConfigError):
            Config({"bot_token": "1:" + "x" * 35, "rules": []}, "c.json")

    def test_missing_target_rejected(self):
        with self.assertRaises(ConfigError):
            Config({"bot_token": "1:" + "x" * 35, "rules": [{"from": [SRC]}]}, "c.json")


class TestForwarding(unittest.TestCase):
    def test_plain_copy_keeps_formatting(self):
        fwd = make_forwarder()
        fwd.on_message(text_msg("原样搬运"), edited=False)
        params = fwd.api.last("copyMessage")
        self.assertEqual(params["chat_id"], DST)
        self.assertEqual(params["from_chat_id"], SRC)
        self.assertNotIn("caption", params)      # 不改文案时不带 caption，保留原格式

    def test_forward_mode_uses_forward_message(self):
        fwd = make_forwarder({"mode": "forward"})
        fwd.on_message(text_msg("转发"), edited=False)
        self.assertIn("forwardMessage", fwd.api.methods())

    def test_rewritten_text_uses_send_message(self):
        fwd = make_forwarder({"footer": "来自本频道"})
        fwd.on_message(text_msg("正文"), edited=False)
        params = fwd.api.last("sendMessage")
        self.assertEqual(params["text"], "正文\n来自本频道")

    def test_rewritten_caption_uses_copy_with_caption(self):
        fwd = make_forwarder({"footer": "小尾巴"})
        fwd.on_message(photo_msg(caption="图说"), edited=False)
        self.assertEqual(fwd.api.last("copyMessage")["caption"], "图说\n小尾巴")

    def test_unmatched_source_is_ignored(self):
        fwd = make_forwarder()
        fwd.on_message(text_msg("别人的频道", chat_id=-100999), edited=False)
        self.assertEqual(fwd.api.methods(), [])

    def test_keyword_filtered_message_not_sent(self):
        fwd = make_forwarder({"exclude_keywords": ["广告"]})
        fwd.on_message(text_msg("这是广告"), edited=False)
        self.assertEqual(fwd.api.methods(), [])

    def test_duplicate_message_sent_once(self):
        fwd = make_forwarder()
        fwd.on_message(text_msg("只发一次", msg_id=7), edited=False)
        fwd.on_message(text_msg("只发一次", msg_id=7), edited=False)
        self.assertEqual(fwd.api.methods().count("copyMessage"), 1)

    def test_service_message_skipped(self):
        fwd = make_forwarder()
        fwd.on_message({"message_id": 3, "chat": {"id": SRC, "type": "channel"},
                        "new_chat_title": "改名了"}, edited=False)
        self.assertEqual(fwd.api.methods(), [])

    def test_multiple_targets(self):
        fwd = make_forwarder({"to": [DST, -1003333333333]})
        fwd.on_message(text_msg("广播"), edited=False)
        targets = [p["chat_id"] for m, p in fwd.api.calls if m == "copyMessage"]
        self.assertEqual(targets, [DST, -1003333333333])

    def test_paused_forwarder_sends_nothing(self):
        fwd = make_forwarder()
        fwd.paused = True
        fwd.on_message(text_msg("暂停中"), edited=False)
        self.assertEqual(fwd.api.methods(), [])

    def test_copy_failure_falls_back_to_forward(self):
        fwd = make_forwarder()
        fwd.api.fail_with["copyMessage"] = ApiError(
            "copyMessage", 400, "Bad Request: message can't be copied")
        fwd.on_message(text_msg("不可复制"), edited=False)
        self.assertIn("forwardMessage", fwd.api.methods())

    def test_target_error_does_not_stop_other_targets(self):
        fwd = make_forwarder({"to": [DST, -1003333333333]})
        original = fwd.api.call
        state = {"first": True}

        def flaky(method, params=None, **kwargs):
            if method == "copyMessage" and state["first"]:
                state["first"] = False
                fwd.api.calls.append((method, params))
                raise ApiError(method, 400, "Bad Request: chat not found")
            return original(method, params, **kwargs)

        fwd.api.call = flaky
        fwd.on_message(text_msg("一个坏一个好"), edited=False)
        sent = [p["chat_id"] for m, p in fwd.api.calls if m == "copyMessage"]
        self.assertEqual(sent, [DST, -1003333333333])
        self.assertEqual(fwd.total_sent, 1)
        self.assertEqual(fwd.total_failed, 1)


class TestAlbums(unittest.TestCase):
    def feed_album(self, fwd, caption=None, count=3):
        for i in range(count):
            fwd.on_message(photo_msg(msg_id=10 + i, group="G1",
                                     caption=caption if i == 0 else None), edited=False)

    def test_album_is_buffered_then_copied_as_group(self):
        fwd = make_forwarder()
        self.feed_album(fwd)
        self.assertEqual(fwd.api.methods(), [])          # 还在缓冲，没发
        fwd._flush_album((SRC, "G1"))
        params = fwd.api.last("copyMessages")
        self.assertEqual(params["message_ids"], [10, 11, 12])

    def test_album_with_rewrite_uses_send_media_group(self):
        fwd = make_forwarder({"footer": "小尾巴"})
        self.feed_album(fwd, caption="图集")
        fwd._flush_album((SRC, "G1"))
        params = fwd.api.last("sendMediaGroup")
        self.assertEqual(len(params["media"]), 3)
        self.assertEqual(params["media"][0]["media"], "big10")   # 取最大尺寸的 file_id
        self.assertEqual(params["media"][0]["caption"], "图集\n小尾巴")
        self.assertNotIn("caption", params["media"][1])

    def test_full_album_flushes_immediately(self):
        fwd = make_forwarder()
        self.feed_album(fwd, count=10)
        self.assertIn("copyMessages", fwd.api.methods())
        self.assertEqual(fwd.albums, {})

    def test_album_falls_back_to_one_by_one(self):
        fwd = make_forwarder()
        fwd.api.fail_with["copyMessages"] = ApiError("copyMessages", 404, "Not Found")
        self.feed_album(fwd)
        fwd._flush_album((SRC, "G1"))
        self.assertEqual(fwd.api.methods().count("copyMessage"), 3)

    def test_album_blocked_by_type_filter(self):
        fwd = make_forwarder({"block_types": ["media_group"]})
        self.feed_album(fwd)
        fwd._flush_album((SRC, "G1"))
        self.assertEqual(fwd.api.methods(), [])


class TestEdits(unittest.TestCase):
    def test_edit_ignored_by_default(self):
        fwd = make_forwarder()
        fwd.on_message(text_msg("原文", msg_id=5), edited=False)
        fwd.on_message(text_msg("改过", msg_id=5), edited=True)
        self.assertEqual(fwd.api.methods().count("copyMessage"), 1)

    def test_edit_syncs_to_copy(self):
        fwd = make_forwarder({"on_edit": "edit", "footer": "尾"})
        fwd.on_message(text_msg("原文", msg_id=5), edited=False)
        fwd.on_message(text_msg("改过", msg_id=5), edited=True)
        params = fwd.api.last("editMessageText")
        self.assertEqual(params["chat_id"], DST)
        self.assertEqual(params["text"], "改过\n尾")

    def test_edit_resend(self):
        fwd = make_forwarder({"on_edit": "resend"})
        fwd.on_message(text_msg("原文", msg_id=5), edited=False)
        fwd.on_message(text_msg("改过", msg_id=5), edited=True)
        self.assertEqual(fwd.api.methods().count("copyMessage"), 2)


class TestCommands(unittest.TestCase):
    @staticmethod
    def command(text, user_id=7, chat_id=SRC):
        return text_msg(text, msg_id=99, chat_id=chat_id,
                        entities=[{"type": "bot_command", "offset": 0, "length": len(text)}],
                        **{"from": {"id": user_id}})

    def test_id_command_replies_with_chat_id(self):
        fwd = make_forwarder()
        fwd.on_message(self.command("/id"), edited=False)
        self.assertIn(str(SRC), fwd.api.last("sendMessage")["text"])
        self.assertNotIn("copyMessage", fwd.api.methods())   # 命令不会被转发

    def test_command_addressed_to_other_bot_is_forwarded(self):
        fwd = make_forwarder()
        fwd.on_message(self.command("/id@someone_else"), edited=False)
        self.assertIn("copyMessage", fwd.api.methods())

    def test_admin_only_commands_require_admin(self):
        fwd = make_forwarder()
        fwd.on_message(self.command("/pause", user_id=7), edited=False)
        self.assertFalse(fwd.paused)
        self.assertIn("user_id", fwd.api.last("sendMessage")["text"])

    def test_admin_can_pause_and_resume(self):
        fwd = make_forwarder(admins=[7])
        fwd.on_message(self.command("/pause", user_id=7), edited=False)
        self.assertTrue(fwd.paused)
        fwd.on_message(self.command("/resume", user_id=7), edited=False)
        self.assertFalse(fwd.paused)

    def test_unknown_command_is_forwarded_as_content(self):
        fwd = make_forwarder()
        fwd.on_message(self.command("/随便写的"), edited=False)
        self.assertIn("copyMessage", fwd.api.methods())


class TestState(unittest.TestCase):
    def test_state_roundtrip(self):
        fwd = make_forwarder()
        fwd.on_message(text_msg("存一下", msg_id=3), edited=False)
        fwd.state["offset"] = 555
        fwd.save_state(force=True)

        revived = Forwarder(fwd.cfg, fwd.state_path)
        revived.api = FakeAPI()
        self.assertEqual(revived.state.get("offset"), 555)
        revived.on_message(text_msg("存一下", msg_id=3), edited=False)
        self.assertEqual(revived.api.methods(), [])   # 重启后不会重复发


if __name__ == "__main__":
    unittest.main(verbosity=2)
