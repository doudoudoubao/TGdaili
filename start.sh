#!/usr/bin/env bash
# 一键启动：检查环境 -> 没配置就先引导生成 -> 体检 -> 跑起来
set -euo pipefail
cd "$(dirname "$0")"

PY=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1; then
    if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 7) else 1)' 2>/dev/null; then
      PY="$candidate"
      break
    fi
  fi
done

if [ -z "$PY" ]; then
  echo "找不到 Python 3.7+，请先安装：" >&2
  echo "  Debian/Ubuntu: sudo apt update && sudo apt install -y python3" >&2
  echo "  CentOS/RHEL:   sudo yum install -y python3" >&2
  echo "  macOS:         brew install python3" >&2
  exit 1
fi

CONFIG="${TG_CONFIG:-config.json}"

if [ ! -f "$CONFIG" ]; then
  echo "没找到 $CONFIG，进入交互式配置……"
  "$PY" forward_bot.py --config "$CONFIG" --init
fi

echo
echo "== 启动前体检 =="
if ! "$PY" forward_bot.py --config "$CONFIG" --check; then
  echo
  read -r -p "体检发现问题，仍然启动吗？(y/N) " answer
  case "$answer" in
    y | Y) ;;
    *) exit 1 ;;
  esac
fi

echo
echo "== 开始转发（Ctrl+C 退出）=="
exec "$PY" forward_bot.py --config "$CONFIG" "$@"
