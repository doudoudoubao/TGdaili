#!/usr/bin/env bash
# tgfwd 一键安装：装到 /opt/tgfwd，配置在 /etc/tgfwd，systemd 托管开机自启。
#   sudo bash install.sh
set -euo pipefail

INSTALL_DIR=/opt/tgfwd
CONFIG_DIR=/etc/tgfwd
SERVICE=tgfwd
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

die() { echo "错误：$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "需要 root，请用 sudo bash install.sh"

PY=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1 &&
     "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 7) else 1)' 2>/dev/null; then
    PY="$(command -v "$candidate")"
    break
  fi
done
[ -n "$PY" ] || die "找不到 Python 3.7+。Debian/Ubuntu: apt install -y python3"

if ! command -v iptables >/dev/null 2>&1; then
  echo "没装 iptables，尝试自动安装……"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq iptables
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q iptables
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache iptables
  else
    die "请先自行安装 iptables"
  fi
fi

command -v tc >/dev/null 2>&1 || \
  echo "提示：没有 tc 命令，限速功能不可用（转发正常）。装一下：apt install -y iproute2"

echo "==> 安装到 $INSTALL_DIR"
install -d -m 755 "$INSTALL_DIR"
install -m 755 "$SRC_DIR/tgfwd.py" "$INSTALL_DIR/tgfwd.py"
install -d -m 700 "$CONFIG_DIR"

echo "==> 打开内核转发"
if [ ! -f /etc/sysctl.d/99-tgfwd.conf ]; then
  printf '# tgfwd 端口转发需要\nnet.ipv4.ip_forward = 1\n' > /etc/sysctl.d/99-tgfwd.conf
fi
sysctl -q -w net.ipv4.ip_forward=1

if [ ! -f "$CONFIG_DIR/config.json" ]; then
  echo "==> 生成配置"
  "$PY" "$INSTALL_DIR/tgfwd.py" --config "$CONFIG_DIR/config.json" --init
else
  echo "==> 已有配置 $CONFIG_DIR/config.json，跳过生成"
fi

echo "==> 安装 systemd 服务"
sed -e "s#__PYTHON__#$PY#g" -e "s#__INSTALL_DIR__#$INSTALL_DIR#g" \
    -e "s#__CONFIG_DIR__#$CONFIG_DIR#g" "$SRC_DIR/$SERVICE.service" \
    > "/etc/systemd/system/$SERVICE.service"
systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null 2>&1 || true

echo "==> 启动前体检"
"$PY" "$INSTALL_DIR/tgfwd.py" --config "$CONFIG_DIR/config.json" --check || true

echo "==> 启动服务"
systemctl restart "$SERVICE"
sleep 2
systemctl --no-pager --lines=15 status "$SERVICE" || true

cat <<TIP

安装完成。常用操作：
  systemctl status  $SERVICE       查看状态
  systemctl restart $SERVICE       重启
  journalctl -u $SERVICE -f        实时日志
  $PY $INSTALL_DIR/tgfwd.py --uninstall   清掉所有转发规则

现在去 Telegram 给你的机器人发 /help 试试，加一条转发：
  /add 8096 落地机IP
TIP
