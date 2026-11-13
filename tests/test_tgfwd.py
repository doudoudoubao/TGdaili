#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tgfwd 测试。不需要 bot token；iptables 集成测试在非 root 环境下自动跳过。

    python3 tests/test_tgfwd.py
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tgfwd  # noqa: E402
from tgfwd import (Bot, Config, ConfigError, Monitor, Nat, Rule,  # noqa: E402
                   Shaper, Store, UsageError, format_size, parse_host,
                   parse_ports, parse_rate, parse_size)

HAVE_IPTABLES = (os.geteuid() == 0 and shutil.which("iptables") is not None)


class FakeRunner:
    """记录所有外部命令，不真的执行。"""

    def __init__(self, responses=None):
        self.calls = []
        self.responses = responses or {}

    def run(self, args, check=False):
        self.calls.append(list(args))
        for key, value in self.responses.items():
            if key in " ".join(args):
                return value
        return 0, "", ""

    def find(self, *fragments):
        out = []
        for call in self.calls:
            joined = " ".join(call)
            if all(f in joined for f in fragments):
                out.append(joined)
        return out


class FakeAPI:
    def __init__(self):
        self.sent = []

    def call(self, method, params=None, timeout=30, retries=3, raise_on_error=True):
        if method == "getMe":
            return {"id": 1, "username": "test_bot"}
        if method in ("getWebhookInfo",):
            return {"url": ""}
        self.sent.append((method, params or {}))
        return {"message_id": len(self.sent)}

    def texts(self):
        return [p.get("text", "") for m, p in self.sent if m == "sendMessage"]

    def last(self):
        return self.texts()[-1] if self.texts() else ""


def make_rule(**kwargs):
    base = dict(id=1, listen_start=8096, listen_end=8096, host="1.2.3.4",
                target_start=8096, target_end=8096)
    base.update(kwargs)
    return Rule(**base)


class TestUnits(unittest.TestCase):
    def test_size(self):
        self.assertEqual(parse_size("500G"), 500 * 1024 ** 3)
        self.assertEqual(parse_size("2T"), 2 * 1024 ** 4)
        self.assertEqual(parse_size("1GB"), 1024 ** 3)
        self.assertEqual(parse_size("1GiB"), 1024 ** 3)
        self.assertEqual(parse_size("0"), 0)

    def test_rate_is_decimal(self):
        # 带宽按 1000 进制，和运营商/tc 一致
        self.assertEqual(parse_rate("100M"), 100 * 1000 ** 2)
        self.assertEqual(parse_rate("1G"), 1000 ** 3)

    def test_bad_units_rejected(self):
        for bad in ("abc", "500X", "", "-5G"):
            with self.assertRaises(UsageError):
                parse_size(bad)

    def test_format_size(self):
        self.assertEqual(format_size(0), "0")
        self.assertEqual(format_size(1024 ** 3), "1GB")

    def test_ports(self):
        self.assertEqual(parse_ports("8096"), (8096, 8096))
        self.assertEqual(parse_ports("10000-20000"), (10000, 20000))
        for bad in ("0", "70000", "abc", "200-100"):
            with self.assertRaises(UsageError):
                parse_ports(bad)

    def test_host(self):
        self.assertEqual(parse_host("1.2.3.4"), ("ip", "1.2.3.4"))
        self.assertEqual(parse_host("Emby.Example.COM"), ("domain", "emby.example.com"))
        # 打错的 IP 必须当场拒绝，不能悄悄当成域名去解析
        for bad in ("999.1.1.1", "192.168.1.300", "1.2.3"):
            with self.assertRaises(UsageError):
                parse_host(bad)
        with self.assertRaises(UsageError):
            parse_host("::1")          # IPv6 明确不支持，不能静默当成域名


class TestRule(unittest.TestCase):
    def test_roundtrip(self):
        rule = make_rule(name="Emby", quota=100, used=50, speed=1000)
        self.assertEqual(Rule.from_dict(rule.to_dict()).to_dict(), rule.to_dict())

    def test_port_range_specs(self):
        rule = make_rule(listen_start=10000, listen_end=10010,
                         target_start=20000, target_end=20010)
        self.assertEqual(rule.listen_spec(), "10000:10010")     # iptables 用冒号
        self.assertEqual(rule.dnat_dest(), "1.2.3.4:20000-20010")  # DNAT 用短横
        self.assertTrue(rule.is_range)

    def test_protocols(self):
        self.assertEqual(make_rule(protocol="both").protocols, ("tcp", "udp"))
        self.assertEqual(make_rule().protocols, ("tcp",))

    def test_domain_rule_keeps_host_and_ip_apart(self):
        rule = make_rule(host="a.com", host_kind="domain", resolved_ip="5.6.7.8")
        self.assertIn("a.com", rule.arrow())          # 展示给人看的是域名
        self.assertIn("5.6.7.8", rule.dnat_dest())    # 下到 iptables 的是 IP


class TestStore(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "rules.json")
        self.store = Store(self.path)

    def add(self, **kwargs):
        base = dict(listen_start=8096, listen_end=8096, host="1.2.3.4",
                    target_start=8096, target_end=8096, resolved_ip="1.2.3.4")
        base.update(kwargs)
        return self.store.add(**base)

    def test_ids_increment_and_persist(self):
        self.add()
        self.add(listen_start=8097, listen_end=8097)
        revived = Store(self.path)
        self.assertEqual([r.id for r in revived.rules], [1, 2])
        self.assertEqual(revived.next_id, 3)

    def test_id_not_reused_after_delete(self):
        self.add()
        self.store.remove(1)
        self.assertEqual(self.add().id, 2)

    def test_port_conflict_detects_overlap(self):
        self.add(listen_start=10000, listen_end=10010)
        self.assertIsNotNone(self.store.port_conflict(10005, 10005, ("tcp",)))
        self.assertIsNotNone(self.store.port_conflict(9000, 10001, ("tcp",)))
        self.assertIsNone(self.store.port_conflict(10011, 10020, ("tcp",)))

    def test_no_conflict_across_protocols(self):
        self.add(protocol="tcp")
        self.assertIsNone(self.store.port_conflict(8096, 8096, ("udp",)))

    def test_active_excludes_disabled_and_over_quota(self):
        self.add()
        self.add(listen_start=8097, listen_end=8097, enabled=False)
        self.add(listen_start=8098, listen_end=8098, quota_hit=True)
        self.assertEqual([r.id for r in self.store.active()], [1])

    def test_corrupt_file_does_not_crash(self):
        with open(self.path, "w") as handle:
            handle.write("{ 这不是 json")
        self.assertEqual(Store(self.path).rules, [])


class TestNatRules(unittest.TestCase):
    def setUp(self):
        self.runner = FakeRunner()
        self.nat = Nat(runner=self.runner, snat_mode="snat", snat_ip="10.0.0.1")

    def test_generates_dnat_snat_and_counters(self):
        args = self.nat.rule_args(make_rule())
        tables = [t for t, _ in args]
        self.assertEqual(tables, ["nat", "nat", "filter", "filter"])
        joined = [" ".join(a) for _, a in args]
        self.assertIn("--to-destination 1.2.3.4:8096", joined[0])
        self.assertIn("--to-source 10.0.0.1", joined[1])
        self.assertIn("TGF:1:out", joined[2])
        self.assertIn("TGF:1:in", joined[3])

    def test_counting_rules_go_in_filter_not_nat(self):
        # nat 表计数器只统计首包，流量统计必须落在 filter/FORWARD
        for table, args in self.nat.rule_args(make_rule()):
            if "TGF:1:out" in " ".join(args) or "TGF:1:in" in " ".join(args):
                self.assertEqual(table, "filter")

    def test_both_protocol_doubles_rules(self):
        self.assertEqual(len(self.nat.rule_args(make_rule(protocol="both"))), 8)

    def test_mark_rule_only_when_speed_set(self):
        self.assertEqual(len(self.nat.rule_args(make_rule())), 4)
        args = self.nat.rule_args(make_rule(speed=1000))
        self.assertEqual(len(args), 5)
        self.assertEqual(args[4][0], "mangle")
        self.assertIn("--set-mark 1", " ".join(args[4][1]))

    def test_masquerade_when_no_ip(self):
        nat = Nat(runner=self.runner, snat_mode="masquerade")
        self.assertIn("-j MASQUERADE", " ".join(nat.rule_args(make_rule())[1][1]))

    def test_never_uses_shell(self):
        # 所有命令都必须是参数列表；一旦有人改成字符串拼接这里会挂
        self.nat.sync([make_rule(name="; rm -rf /")])
        for call in self.runner.calls:
            self.assertIsInstance(call, list)
            self.assertTrue(all(isinstance(a, str) for a in call))

    def test_sync_flushes_before_adding(self):
        self.nat.sync([make_rule()])
        flushes = self.runner.find("-F", "TGF_")
        self.assertEqual(len(flushes), 4)     # 四条自定义链都清过

    def test_read_counters_parses_iptables_save(self):
        saved = (
            '[10:2048] -A TGF_FWD -d 1.2.3.4/32 -p tcp -m tcp --dport 8096 '
            '-m comment --comment "TGF:1:out" -j ACCEPT\n'
            '[20:8192] -A TGF_FWD -s 1.2.3.4/32 -p tcp -m tcp --sport 8096 '
            '-m comment --comment "TGF:1:in" -j ACCEPT\n'
            '[5:100] -A OTHER -j ACCEPT\n')
        nat = Nat(runner=FakeRunner({"iptables-save": (0, saved, "")}))
        self.assertEqual(nat.read_counters(), {1: {"out": 2048, "in": 8192}})


class TestTrafficAccounting(unittest.TestCase):
    def setUp(self):
        self.store = Store(os.path.join(tempfile.mkdtemp(), "r.json"))
        self.rule = self.store.add(listen_start=8096, listen_end=8096, host="1.2.3.4",
                                   target_start=8096, target_end=8096, resolved_ip="1.2.3.4")
        self.counters = {1: {"in": 0, "out": 0}}
        self.alerts = []
        nat = Nat(runner=FakeRunner())
        nat.read_counters = lambda: self.counters
        self.monitor = Monitor(self.store, nat, self.alerts.append)

    def test_accumulates_deltas_not_totals(self):
        self.counters[1] = {"in": 1000, "out": 100}
        self.monitor.sample_traffic()
        self.assertEqual(self.rule.used, 1100)
        self.counters[1] = {"in": 1500, "out": 150}
        self.monitor.sample_traffic()
        self.assertEqual(self.rule.used, 1650)      # 只加增量，不是重复累计 2750

    def test_counter_reset_does_not_lose_or_double_count(self):
        self.counters[1] = {"in": 1000, "out": 0}
        self.monitor.sample_traffic()
        self.counters[1] = {"in": 50, "out": 0}     # 规则重建后计数器归零
        self.monitor.sample_traffic()
        self.assertEqual(self.rule.used, 1050)

    def test_quota_stops_rule_and_alerts(self):
        self.rule.quota = 1000
        self.counters[1] = {"in": 1200, "out": 0}
        stopped = self.monitor.sample_traffic()
        self.assertEqual([r.id for r in stopped], [1])
        self.assertTrue(self.rule.quota_hit)
        self.assertNotIn(self.rule, self.store.active())
        self.assertIn("流量上限", self.alerts[0])

    def test_quota_alert_fires_only_once(self):
        self.rule.quota = 1000
        self.counters[1] = {"in": 1200, "out": 0}
        self.monitor.sample_traffic()
        self.counters[1] = {"in": 5000, "out": 0}
        self.monitor.sample_traffic()
        self.assertEqual(len(self.alerts), 1)


class TestHealthCheck(unittest.TestCase):
    def setUp(self):
        self.store = Store(os.path.join(tempfile.mkdtemp(), "r.json"))
        self.rule = self.store.add(listen_start=8096, listen_end=8096, host="1.2.3.4",
                                   target_start=8096, target_end=8096, resolved_ip="1.2.3.4")
        self.alerts = []
        self.monitor = Monitor(self.store, Nat(runner=FakeRunner()),
                               self.alerts.append, health_fails=3)
        self.up = True
        self.monitor.probe = lambda r: (self.up, 42 if self.up else None)

    def test_alert_only_after_consecutive_failures(self):
        self.up = False
        for _ in range(2):
            self.monitor.health_check()
        self.assertEqual(self.alerts, [])        # 抖一两下不告警
        self.monitor.health_check()
        self.assertIn("落地机不通", self.alerts[0])

    def test_recovery_alert(self):
        self.up = False
        for _ in range(3):
            self.monitor.health_check()
        self.up = True
        self.monitor.health_check()
        self.assertIn("恢复", self.alerts[1])

    def test_no_repeat_alerts_while_still_down(self):
        self.up = False
        for _ in range(10):
            self.monitor.health_check()
        self.assertEqual(len(self.alerts), 1)

    def test_disabled_rules_not_probed(self):
        self.rule.enabled = False
        self.up = False
        for _ in range(5):
            self.monitor.health_check()
        self.assertEqual(self.alerts, [])


class TestDns(unittest.TestCase):
    def test_ip_change_triggers_rebuild(self):
        store = Store(os.path.join(tempfile.mkdtemp(), "r.json"))
        rule = store.add(listen_start=8096, listen_end=8096, host="a.com",
                         host_kind="domain", target_start=8096, target_end=8096,
                         resolved_ip="1.1.1.1")
        alerts = []
        monitor = Monitor(store, Nat(runner=FakeRunner()), alerts.append)
        tgfwd.resolve = lambda host: "2.2.2.2"
        try:
            changed = monitor.refresh_dns()
        finally:
            tgfwd.resolve = tgfwd.__dict__["resolve"]
        self.assertEqual([r.id for r in changed], [1])
        self.assertEqual(rule.resolved_ip, "2.2.2.2")
        self.assertIn("落地机 IP 变了", alerts[0])


class TestBotCommands(unittest.TestCase):
    def setUp(self):
        self.api = FakeAPI()
        self.cfg = Config({"bot_token": "1:" + "x" * 35, "admins": [7]}, "c.json")
        self.store = Store(os.path.join(tempfile.mkdtemp(), "r.json"))
        self.runner = FakeRunner()
        nat = Nat(runner=self.runner, snat_mode="snat", snat_ip="10.0.0.1")
        nat.read_counters = lambda: {}
        shaper = Shaper(runner=self.runner, iface="eth0")
        shaper.available = lambda: True
        self.monitor = Monitor(self.store, nat, lambda t: None)
        self.monitor.probe = lambda r: (True, 12)
        self.bot = Bot(self.api, self.cfg, self.store, nat, shaper, self.monitor)
        self.bot.me = {"username": "test_bot"}

    def send(self, text, user_id=7):
        self.bot.handle({"message_id": 1, "text": text,
                         "chat": {"id": 7, "type": "private"},
                         "from": {"id": user_id}})
        return self.api.last()

    # -- 权限 --------------------------------------------------------- #
    def test_non_admin_cannot_add(self):
        reply = self.send("/add 8096 1.2.3.4", user_id=999)
        self.assertIn("没有权限", reply)
        self.assertEqual(self.store.rules, [])

    def test_non_admin_denial_is_throttled(self):
        self.send("/add 8096 1.2.3.4", user_id=999)
        before = len(self.api.sent)
        self.send("/del 1", user_id=999)
        self.assertEqual(len(self.api.sent), before)   # 一分钟内不重复回

    def test_id_command_is_public(self):
        self.assertIn("user_id", self.send("/id", user_id=999))

    def test_command_for_another_bot_ignored(self):
        self.bot.handle({"text": "/add@other_bot 8096 1.2.3.4",
                         "chat": {"id": 7}, "from": {"id": 7}})
        self.assertEqual(self.api.sent, [])

    # -- 增删改查 ----------------------------------------------------- #
    def test_add_then_list(self):
        self.assertIn("已添加 #1", self.send("/add 8096 1.2.3.4 Emby"))
        self.assertEqual(len(self.store.rules), 1)
        self.assertIn("8096 → 1.2.3.4", self.send("/list"))

    def test_add_defaults_target_port_to_listen_port(self):
        self.send("/add 8096 1.2.3.4")
        self.assertEqual(self.store.get(1).target_start, 8096)

    def test_add_with_explicit_target_port_and_name(self):
        self.send("/add 8096 1.2.3.4 8920 我的 Emby")
        rule = self.store.get(1)
        self.assertEqual(rule.target_start, 8920)
        self.assertEqual(rule.name, "我的 Emby")

    def test_add_treats_non_port_third_arg_as_name(self):
        self.send("/add 8096 1.2.3.4 Emby主力")
        self.assertEqual(self.store.get(1).target_start, 8096)
        self.assertEqual(self.store.get(1).name, "Emby主力")

    def test_add_rejects_port_conflict(self):
        self.send("/add 8096 1.2.3.4")
        self.assertIn("冲突", self.send("/add 8096 5.6.7.8"))
        self.assertEqual(len(self.store.rules), 1)

    def test_add_rejects_mismatched_range_length(self):
        self.assertIn("长度要一致", self.send("/add 10000-10010 1.2.3.4 20000-20005"))

    def test_add_pushes_iptables_rules(self):
        self.send("/add 8096 1.2.3.4")
        self.assertTrue(self.runner.find("-A TGF_PRE", "--to-destination 1.2.3.4:8096"))

    def test_del_removes_rule_and_resyncs(self):
        self.send("/add 8096 1.2.3.4")
        self.runner.calls = []
        self.assertIn("已删除 #1", self.send("/del 1"))
        self.assertEqual(self.store.rules, [])
        self.assertTrue(self.runner.find("-F", "TGF_PRE"))

    def test_del_unknown_id(self):
        self.assertIn("没有 #9", self.send("/del 9"))

    def test_off_removes_from_iptables_but_keeps_rule(self):
        self.send("/add 8096 1.2.3.4")
        self.send("/off 1")
        self.assertFalse(self.store.get(1).enabled)
        self.assertEqual(self.store.active(), [])

    def test_proto_change(self):
        self.send("/add 8096 1.2.3.4")
        self.send("/proto 1 both")
        self.assertEqual(self.store.get(1).protocol, "both")
        self.assertIn("tcp|udp|both", self.send("/proto 1 sctp"))

    # -- 流量 / 限速 -------------------------------------------------- #
    def test_quota_and_reset(self):
        self.send("/add 8096 1.2.3.4")
        self.assertIn("500GB", self.send("/quota 1 500G"))
        rule = self.store.get(1)
        rule.used = 600 * 1024 ** 3
        self.monitor.enforce_quota()
        self.assertTrue(rule.quota_hit)
        self.send("/reset 1")
        self.assertEqual(rule.used, 0)
        self.assertFalse(rule.quota_hit)       # 清零后自动恢复

    def test_quota_zero_removes_limit(self):
        self.send("/add 8096 1.2.3.4")
        self.send("/quota 1 500G")
        self.assertIn("取消流量限制", self.send("/quota 1 0"))

    def test_speed_sets_tc_and_mark(self):
        self.send("/add 8096 1.2.3.4")
        self.runner.calls = []
        self.assertIn("100Mbps", self.send("/speed 1 100M"))
        self.assertTrue(self.runner.find("tc", "class", "add", "rate", "100000000bit"))
        self.assertTrue(self.runner.find("-A TGF_MARK", "--set-mark 1"))

    def test_bad_unit_gives_usage_error(self):
        self.send("/add 8096 1.2.3.4")
        self.assertIn("写法不对", self.send("/quota 1 500X"))

    def test_reset_all(self):
        self.send("/add 8096 1.2.3.4")
        self.send("/add 8097 1.2.3.4")
        self.store.get(1).used = 999
        self.send("/reset all")
        self.assertEqual([r.used for r in self.store.rules], [0, 0])

    # -- 运维 --------------------------------------------------------- #
    def test_status_and_help(self):
        self.assertIn("tgfwd 运行状态", self.send("/status"))
        self.assertIn("/add", self.send("/help"))

    def test_unknown_command(self):
        self.assertIn("没有 /nope", self.send("/nope"))

    def test_handler_exception_is_reported_not_crashed(self):
        self.send("/add 8096 1.2.3.4")
        self.bot.nat.sync = lambda rules: (_ for _ in ()).throw(RuntimeError("炸了"))
        self.assertIn("内部错误", self.send("/del 1"))


class TestConfig(unittest.TestCase):
    def test_admins_required(self):
        # 这个 bot 能改防火墙，不允许空白名单
        with self.assertRaises(ConfigError):
            Config({"bot_token": "1:" + "x" * 35, "admins": []}, "c.json")

    def test_token_required(self):
        os.environ.pop("TG_BOT_TOKEN", None)
        os.environ.pop("BOT_TOKEN", None)
        with self.assertRaises(ConfigError):
            Config({"admins": [1]}, "c.json")

    def test_bad_snat_mode(self):
        with self.assertRaises(ConfigError):
            Config({"bot_token": "1:x", "admins": [1], "snat_mode": "nope"}, "c.json")


@unittest.skipUnless(HAVE_IPTABLES, "需要 root + iptables")
class TestIptablesIntegration(unittest.TestCase):
    """真刀真枪下发到内核，再读回来核对。"""

    def setUp(self):
        self.nat = Nat(snat_mode="snat", snat_ip="10.0.0.1")
        self.nat.teardown()

    def tearDown(self):
        self.nat.teardown()

    @staticmethod
    def dump():
        return subprocess.run(["iptables-save"], capture_output=True, text=True).stdout

    def test_sync_creates_real_rules(self):
        rules = [make_rule(id=1), make_rule(id=2, listen_start=443, listen_end=443,
                                            host="5.6.7.8", target_start=443,
                                            target_end=443, protocol="both")]
        applied, failed = self.nat.sync(rules)
        self.assertEqual((applied, failed), (2, []))
        dump = self.dump()
        self.assertIn("--to-destination 1.2.3.4:8096", dump)
        self.assertIn('--comment "TGF:2"', dump)
        self.assertIn("-p udp", dump)

    def test_port_range_syntax_accepted_by_kernel(self):
        applied, failed = self.nat.sync([make_rule(listen_start=10000, listen_end=10010,
                                                   target_start=10000, target_end=10010)])
        self.assertEqual(failed, [])
        self.assertIn("--to-destination 1.2.3.4:10000-10010", self.dump())

    def test_sync_is_idempotent(self):
        rules = [make_rule()]
        self.nat.sync(rules)
        self.nat.sync(rules)
        self.nat.sync(rules)
        self.assertEqual(self.dump().count("-A TGF_PRE "), 1)
        self.assertEqual(self.dump().count("-j TGF_PRE"), 1)

    def test_counters_readable_after_sync(self):
        self.nat.sync([make_rule(id=3)])
        self.assertEqual(self.nat.read_counters(), {3: {"in": 0, "out": 0}})

    def test_teardown_leaves_nothing(self):
        self.nat.sync([make_rule()])
        self.nat.teardown()
        self.assertNotIn("TGF_", self.dump())

    def test_teardown_is_safe_when_nothing_installed(self):
        self.nat.teardown()
        self.assertEqual(self.nat.teardown(), 0)

    def test_bad_rule_reported_not_raised(self):
        # 目标 IP 非法，iptables 会拒绝；应该被收集成 failed 而不是抛出来
        bad = make_rule(id=9)
        bad.resolved_ip = "999.999.999.999"
        applied, failed = self.nat.sync([bad])
        self.assertEqual(applied, 0)
        self.assertEqual(len(failed), 1)


if __name__ == "__main__":
    if not HAVE_IPTABLES:
        print("注意：非 root 或没有 iptables，集成测试会被跳过\n")
    unittest.main(verbosity=2)
