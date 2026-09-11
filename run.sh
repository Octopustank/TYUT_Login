#!/usr/bin/env bash
# TYUT 校园网保活启动脚本
# 日志默认写入本项目目录 logs.txt。
#   前台运行：./run.sh
#   后台运行：setsid nohup ./run.sh </dev/null &
#   解释器：  默认 python3，可用 PYTHON=... 覆盖
set -eu
cd "$(dirname "$0")"
PYTHON="${PYTHON:-python3}"
exec "$PYTHON" tyut_login.py "$@" >>logs.txt 2>&1
