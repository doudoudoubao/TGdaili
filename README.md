# TGdaili — TG Bot 一键转发

用 Telegram Bot 把**源频道/群**的新消息自动搬到**你自己的频道/群**。
单文件、零第三方依赖，有 Python 3.7+ 就能跑。

```bash
git clone <本仓库> && cd TGdaili
./start.sh          # Windows 双击 start.bat
```

`start.sh` 会自动引导你填 token、检查权限，然后开始转发。

---

## 先看这里：Bot API 能做什么、不能做什么

这个脚本走的是官方 Bot API，有三条硬限制，**改代码也绕不过去**：

| 限制 | 说明 |
| --- | --- |
| 机器人必须在源聊天里 | 源频道要把它加成**管理员**；群里要么给管理员，要么在 @BotFather 用 `/setprivacy` 关闭隐私模式，否则它只收得到 @它 的消息 |
| 读不到历史消息 | 只能从脚本跑起来那一刻开始搬，之前的消息搬不了 |
| 源频道开了「禁止转发/保存内容」就失败 | Telegram 在服务端拦截，任何 bot 都做不到 |

**如果你要搬的是「别人的、你没权限的频道」**，Bot API 方案不适用，只能用**用户账号方案**
（Telethon / Pyrogram + api_id/api_hash + 手机号登录），那种方式能搬任何你看得见的频道、
能拉历史消息，但属于第三方客户端，账号有被封的风险。这个仓库目前只实现 Bot 方案。

---

## 三步跑起来

### 1. 建一个机器人

Telegram 里找 **@BotFather** → `/newbot` → 起个名字 → 它会给你一串 token，形如
`123456789:AAE-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`。

### 2. 把机器人加进两边的聊天

- **源频道**：频道设置 → 管理员 → 添加机器人（读消息用，权限给最小的就行）
- **目标频道**：同样加成管理员，**必须勾「发布消息」**

### 3. 配置并启动

```bash
python3 forward_bot.py --init      # 交互式生成 config.json
python3 forward_bot.py --check     # 体检：token 对不对、权限够不够
python3 forward_bot.py             # 开始转发
```

**不知道 chat_id？** 两个办法，随便挑一个：

```bash
python3 forward_bot.py --discover  # 往源频道随便发条消息，终端会打印它的 chat_id
```

或者把机器人拉进那个聊天，发一条 `/id`，它会直接回复 chat_id。

---

## 配置说明

配置文件是 `config.json`（可以写 `//` 整行注释），完整示例见
[`config.example.json`](config.example.json)。最小可用配置：

```json
{
  "bot_token": "123456789:AAE-xxxxxxxx",
  "rules": [
    { "from": [-1001234567890], "to": [-1009876543210] }
  ]
}
```

### 顶层字段

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `bot_token` | — | @BotFather 给的 token。也可以写 `"env:TG_BOT_TOKEN"` 或直接留空改用环境变量 `TG_BOT_TOKEN`，避免 token 落在文件里 |
| `admins` | `[]` | 能用 `/status` `/pause` `/reload` 的人的 user_id（发 `/id` 可查） |
| `default` | `{}` | 所有规则共用的默认值，规则里写同名字段可覆盖 |
| `rules` | — | 转发规则列表，见下 |
| `proxy` | — | 形如 `http://127.0.0.1:7890`；也认 `HTTPS_PROXY` 环境变量 |
| `log_level` / `log_file` | `INFO` | 日志级别与日志文件（自动按 5MB 轮转） |
| `state_file` | `state.json` | 断点位置、去重记录存在这里，**别删**，删了可能重复搬 |
| `album_wait` | `2.0` | 相册聚合等待秒数，网络差可以调大 |

### 规则字段

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `from` / `to` | — | 源 / 目标，填 chat_id（频道多是 `-100` 开头）或 `@公开用户名`，都可以写多个 |
| `name` / `enabled` | — / `true` | 规则名（日志里显示）、是否启用 |
| `mode` | `copy` | `copy` = 搬运，不显示「转发自」；`forward` = 原生转发，带来源角标 |
| `send_delay` | `0.5` | 每条之间间隔秒数，防限流。目标多、消息密时建议调大 |
| `silent` | `false` | 静默发送，不给订阅者响铃 |
| `on_edit` | `ignore` | 源消息被编辑时：`ignore` 忽略 / `edit` 同步改已发的那条 / `resend` 重发一条 |
| `allow_types` / `block_types` | `[]` | 类型白/黑名单：`text` `photo` `video` `animation` `document` `audio` `voice` `video_note` `sticker` `poll` `dice` `contact` `location` `media_group` |
| `include_keywords` | `[]` | 命中任意一个才搬，留空=不限制。`re:` 开头按正则 |
| `exclude_keywords` | `[]` | 命中任意一个就丢弃 |
| `remove_links` / `remove_usernames` / `remove_hashtags` | `false` | 清掉链接 / `@用户名` / `#话题` |
| `replace` | `[]` | `[{"from":"甲","to":"乙"}]`，加 `"regex": true` 则按正则 |
| `header` / `footer` | `""` | 在正文前/后各加一段（小尾巴） |

> **关于格式**：不做任何文案改写时走 `copyMessage`，粗体、链接、按钮原样保留。
> 一旦用了 `replace` / `footer` / `remove_*`，改写后的文案会以**纯文本**发出，原有的富文本格式会丢失。

### 常用配方

```jsonc
// 去广告 + 换成自己的小尾巴
{
  "from": [-1001111111111], "to": [-1002222222222],
  "exclude_keywords": ["广告", "招商", "re:加\\s*微信"],
  "remove_links": true, "remove_usernames": true,
  "footer": "\n\n—— 更多内容 @my_channel"
}

// 只搬图片和视频，不要文字和贴纸
{ "from": [-100111], "to": [-100222], "allow_types": ["photo", "video", "media_group"] }

// 一个源，分发到多个目标
{ "from": [-100111], "to": [-100222, -100333, "@my_public_channel"] }

// 多个源，汇聚到一个目标
{ "from": [-100111, -100222, -100333], "to": [-100999] }
```

---

## 机器人命令

在任意聊天里对机器人发：

| 命令 | 谁能用 | 作用 |
| --- | --- | --- |
| `/id` | 所有人 | 显示当前聊天的 chat_id 和你的 user_id（配置时用） |
| `/help` | 所有人 | 帮助 |
| `/status` | `admins` | 运行时长、每条规则搬了多少条、最近一次错误 |
| `/rules` | `admins` | 当前生效的规则 |
| `/pause` `/resume` | `admins` | 暂停 / 恢复转发 |
| `/reload` | `admins` | 改完 config.json 后热加载，不用重启 |

---

## 长期运行

**systemd（推荐，VPS 上开机自启 + 崩溃自动重启）**

```bash
sudo cp -r . /opt/tgdaili
sudo cp tgforward.service /etc/systemd/system/   # 里面的路径按需改
sudo systemctl daemon-reload
sudo systemctl enable --now tgforward
journalctl -u tgforward -f                       # 看日志
```

**临时挂后台**

```bash
nohup python3 forward_bot.py > tgforward.log 2>&1 &
# 或 screen -S tg  /  tmux new -s tg
```

---

## 常见问题

**跑起来了但一条都不转**
八成是机器人没收到消息。先 `python3 forward_bot.py --check` 看权限，再 `--discover` 往源频道发条消息，
看终端有没有打印。频道必须把机器人设为**管理员**；群里必须关隐私模式或给管理员。

**`connection refused` / `Tunnel connection failed` / 卡住不动**
连不上 `api.telegram.org`，需要代理：config.json 里加 `"proxy": "http://127.0.0.1:7890"`，
或 `export HTTPS_PROXY=http://127.0.0.1:7890`。systemd 则在 unit 里加 `Environment=HTTPS_PROXY=...`。

**`Conflict: terminated by other getUpdates request` (409)**
同一个 token 被两个进程同时轮询了。先 `ps aux | grep forward_bot` 把旧的杀掉。

**`Bad Request: chat not found`**
chat_id 写错，或机器人还没被加进那个聊天。频道 id 一般是 `-100` 开头的长数字，别漏了 `-100`。

**`message can't be copied`**
源频道开了「禁止转发/保存内容」，Bot API 无解，只能改用用户账号方案。

**相册（多图）被拆成了一张张**
正常情况会整组发。若日志里出现 `copyMessages 不可用`，多半是在用旧版本的自建 Bot API server，
升到支持 Bot API 7.0+ 的版本即可。

**转发太快被限流**
日志会出现 `触发限流(429)`，脚本会自动等待重试。持续出现就把 `send_delay` 调大到 1~3 秒。

**重启后会不会重复搬？**
不会。断点和已处理消息记在 `state.json` 里。反过来说，别手删它。

---

## 开发

```bash
python3 tests/test_forward.py    # 42 个离线测试，不需要真实 token
```

测试用假的 API 客户端记录调用，覆盖了类型识别、关键词/类型过滤、文案改写、相册聚合、
编辑同步、去重、命令权限和状态持久化。

## 免责声明

仅供学习与自有频道内容同步使用。转发他人内容请自行确认版权与合规问题，
使用本脚本产生的一切后果由使用者自行承担。
