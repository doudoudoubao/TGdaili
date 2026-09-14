@echo off
chcp 65001 >nul
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
  echo 找不到 Python，请先从 https://www.python.org/downloads/ 安装（安装时勾选 Add to PATH）
  pause
  exit /b 1
)

if not exist config.json (
  echo 没找到 config.json，进入交互式配置……
  python forward_bot.py --init
)

echo.
echo == 启动前体检 ==
python forward_bot.py --check

echo.
echo == 开始转发（Ctrl+C 退出）==
python forward_bot.py %*
pause
