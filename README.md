# TGdaili — TG bot 一键端口转发

跑在**中转机**上，用 iptables NAT 把本机端口转发到落地机，转发规则全部通过
**Telegram bot** 增删查，顺带流量统计、落地机掉线告警、限速和超额自动停用。

```
   用户  ──>  中转机:8096  ──DNAT──>  落地机(Emby):8096
                  ↑
             TG bot 管理
```

零第三方依赖，只要有 Python 3.7+ 和系统自带的 iptables。

```bash
git clone <本仓库> && cd TGdaili
sudo bash install.sh
```

装完去 Telegram 给机器人发一句就能加转发：

```
/add 8096 1.2.3.4          本机 8096 → 1.2.3.4:8096
```

---

## 为什么用 iptables

| 方案 | 适合 | 代价 |
| --- | --- | --- |
| **iptables NAT**（本脚本） | 大带宽中转（Emby/Jellyfin、下载、游戏），线路本身通 | 不加密；落地机看到的客户端 IP 是中转机 |
| realm / gost | 线路被 QoS 干扰，需要 TLS/WS 伪装或加密 | 用户态转发，同带宽下更吃 CPU |
| socat | 临时调试 | 性能差，别拿来跑生产 |

Emby 这类视频流单路就能吃到 100+ Mbps，**iptables 走内核转发，几乎不占 CPU**，
1 核小鸡也能跑满网卡；流量统计还能直接用 iptables 的计数器，不用另外造轮子。

### 三个必须知道的前提

1. **落地机看到的客户端 IP 会变成中转机的 IP。** 这是所有 NAT/中继方案的通病
   （realm、gost 一样）。Emby 后台里所有用户都会显示成中转机地址，按 IP 做的
   限制、统计、封号策略都会失效。
2. **落地机防火墙要放行中转机的 IP**，否则加完规则探测就是 ❌。
3. **落地机写域名时 IP 会变。** 裸 iptables 的 DNAT 只在下规则时解析一次域名，
   IP 一换转发就废了 —— 本脚本会定期重新解析并自动重建规则（默认 5 分钟），
   这是相对手搓 iptables 脚本最实际的一个改进。

---

## 安装

```bash
sudo bash install.sh
```

脚本会：装到 `/opt/tgfwd` → 打开 `net.ipv4.ip_forward`（并写进 `/etc/sysctl.d/`）
→ 引导你填 bot token 和管理员 id → 装 systemd 服务并启动。

**手动装**也行：

```bash
sudo python3 tgfwd.py --init      # 生成 /etc/tgfwd/config.json
sudo python3 tgfwd.py --check     # 体检
sudo python3 tgfwd.py             # 前台跑
```

拿 bot token：Telegram 找 **@BotFather** → `/newbot`。
拿自己的 user_id：把机器人拉进对话发 `/id`。

---

## 机器人命令

```
━━ 规则 ━━
/add <本地端口> <落地IP或域名> [落地端口] [备注]
      /add 8096 1.2.3.4                 本机8096 → 1.2.3.4:8096
      /add 8096 emby.abc.com 8920 主力   落地写域名，IP 变了自动跟
      /add 10000-10100 1.2.3.4          整段转发
/del <id>                    删除
/list                        列出全部
/info <id>                   详情
/on <id>  /off <id>          启用 / 停用
/proto <id> <tcp|udp|both>   改协议（默认 tcp）

━━ 流量 / 限速 ━━
/traffic            流量排行（带进度条）
/quota <id> 500G    流量上限，超了自动停用并告警（0=不限）
/speed <id> 100M    限速，单位 Mbps（0=不限）
/reset <id|all>     流量清零，被超额停用的自动恢复

━━ 运维 ━━
/check     立刻探测所有落地机
/status    运行状态、ip_forward、负载
/sync      强制重建 iptables 规则
/id        查 chat_id 和你的 user_id
/help      帮助
```

> **只有 `config.json` 里 `admins` 列出的 user_id 能操作转发。** 这个 bot 能改你的
> 防火墙，所以白名单是硬性的 —— 留空脚本会直接拒绝启动。非管理员发命令会被拒绝
> 并记进日志。

---

## 配置

`/etc/tgfwd/config.json`，完整示例见 [`config.example.json`](config.example.json)。

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `bot_token` | — | @BotFather 给的 token。也可写 `"env:TG_BOT_TOKEN"` 或留空用环境变量 |
| `admins` | — | **必填**，能操作转发的 user_id 列表 |
| `notify_chat` | `null` | 除管理员外，额外把告警发到这个 chat（比如运维群） |
| `snat_mode` | `auto` | `auto`/`snat`/`masquerade`。auto 会探测本机出口 IP 用 SNAT，探不到退回 MASQUERADE |
| `snat_ip` | `null` | 多 IP 机器上指定用哪个 IP 做源地址 |
| `iface` | `null` | 限速用的网卡，默认取默认路由的出口网卡 |
| `traffic_interval` | `60` | 流量采样间隔（秒） |
| `health_interval` | `60` | 落地机探测间隔（秒） |
| `health_fails` | `3` | 连续失败几次才告警，防抖 |
| `dns_interval` | `300` | 域名重解析间隔（秒） |
| `proxy` | `null` | 连不上 Telegram 时填，如 `http://127.0.0.1:7890`；也认 `HTTPS_PROXY` |
| `rules_file` | `/etc/tgfwd/rules.json` | 转发规则存这，**别手删** |

单位约定：**流量按 1024 进制**（`500G` = 500 GiB），**带宽按 1000 进制**
（`100M` = 100 Mbps），和运营商/`tc` 的习惯一致。

---

## 它在系统里干了什么

所有规则都关在自己的 `TGF_*` 自定义链里，**不碰你已有的任何规则**，卸载时整条链
删掉即可：

```
nat/PREROUTING   → TGF_PRE    DNAT，把进来的包改到落地机
nat/POSTROUTING  → TGF_POST   SNAT，不改源地址的话落地机会直接回给真实客户端，连接建不起来
filter/FORWARD   → TGF_FWD    放行 + 双向字节计数（流量统计的来源）
mangle/POSTROUTING → TGF_MARK 打 fwmark 给 tc 限速用（只在设了限速时才加）
```

想看实际下发了什么：

```bash
iptables-save | grep TGF
```

**流量统计为什么放在 filter 而不是 nat**：nat 表的计数器只统计每条连接的第一个包，
拿它算流量会差几个数量级。真正的字节数必须在 `filter/FORWARD` 上数。

清理干净：

```bash
sudo python3 /opt/tgfwd/tgfwd.py --uninstall
```

---

## 常用运维

```bash
systemctl status tgfwd        # 状态
systemctl restart tgfwd       # 重启
journalctl -u tgfwd -f        # 实时日志
```

规则存在 `/etc/tgfwd/rules.json`，**重启机器后 systemd 拉起脚本会自动把规则重新
下发**，不需要 iptables-persistent。

---

## 常见问题

**加了转发但连不上**
按顺序查：① `/check` 看落地机通不通 ② 落地机防火墙有没有放行中转机 IP
③ `sudo python3 tgfwd.py --check` 确认 `ip_forward` 已开 ④ 云服务商的安全组
（阿里云/腾讯云/AWS）有没有放行中转机的这个端口 —— 这一条最容易漏。

**Emby 里所有用户都显示成同一个 IP**
NAT 转发的固有行为，见上面「三个必须知道的前提」。Emby 不支持 Proxy Protocol，
拿不到真实 IP。

**流量统计和服务商面板对不上**
脚本只数被转发的流量，不含系统本身的其它流量；另外服务商多按 1000 进制算，
这里按 1024 进制，1TB 会差约 10%。

**限速没生效**
`/status` 看「限速(tc)」那行。没有 tc 就 `apt install -y iproute2`。
注意**只限下行**（中转机→用户，也就是用户的下载速度）；上行要靠 ifb 虚拟网卡，
复杂度高，没做。另外网卡上已有别人的 qdisc 时脚本会主动放弃限速而不是覆盖它。

**机器重启后转发没了**
`systemctl enable tgfwd` 有没有执行过？服务起来会自动重建规则。

**连不上 Telegram / `Tunnel connection failed`**
国内机器要代理：config.json 里加 `"proxy": "http://127.0.0.1:7890"`，或者在
systemd unit 里加 `Environment=HTTPS_PROXY=...`。

**`Conflict: terminated by other getUpdates request` (409)**
同一个 token 被两个进程轮询了，先停掉其中一个。

**能转发 IPv6 吗**
不能，目前只处理 IPv4（`ip6tables` 没做）。

---

## 开发

```bash
sudo python3 tests/test_tgfwd.py     # 66 个测试
```

其中 7 个是**真实 iptables 集成测试**（下发到内核再读回来核对，非 root 环境自动
跳过），其余用假的命令执行器和假 API，不需要 token、不联网。

已验证：规则下发/幂等/卸载零残留、端口段语法、流量增量累加（计数器归零不重复计
数）、配额停用只告警一次、健康检查防抖、越权命令拦截、所有外部命令都以参数列表
调用（不存在 shell 注入面）。

**没在真实中转环境端到端跑过转发流量** —— 开发环境里没有第二台机器和 `tc`，
限速部分只验证了命令构造。上生产前先用 `--check` 体检，加完规则用 `/check` 确认
落地机可达。

## 免责声明

仅供管理自有服务器使用。使用者需自行确保用途符合当地法律法规与服务商条款。
