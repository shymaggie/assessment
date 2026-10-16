#!/usr/bin/env bash
# 一键启动可视化工作台（默认端口 8899）。
#   ./start-web.sh                 # 本机访问，有真实结果用真实，否则演示数据，并打开浏览器
#   ./start-web.sh --demo          # 强制演示数据
#   ./start-web.sh --tv            # 直接进入大屏模式
#   ./start-web.sh --lan 口令      # 局域网大屏投放（监听 0.0.0.0，必须带口令）
#   ./start-web.sh --no-open       # 不自动打开浏览器
#   ./start-web.sh --no-run        # 关闭页面上的“开始复测”（纯展示大屏）
# 环境变量：PORT 改端口（默认 8899）；RETEST_DATA_DIR 指定数据目录。
set -euo pipefail

cd "$(dirname "$0")"
PORT="${PORT:-8899}"
HOST="127.0.0.1"
ARGS=()
OPEN=1
TV=0
TOKEN=""

while [ $# -gt 0 ]; do
  case "$1" in
    --demo)    ARGS+=(--source demo) ;;
    --tv)      TV=1 ;;
    --no-open) OPEN=0 ;;
    --no-run)  ARGS+=(--no-run) ;;
    --lan)
      if [ $# -lt 2 ] || [ -z "${2:-}" ]; then echo "--lan 需要带一个访问口令，例如：./start-web.sh --lan 我的口令" >&2; exit 2; fi
      HOST="0.0.0.0"; TOKEN="$2"; shift ;;
    -h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "未知参数：$1（见 ./start-web.sh --help）" >&2; exit 2 ;;
  esac
  shift
done

case "$PORT" in ''|*[!0-9]*) echo "PORT 必须是数字：$PORT" >&2; exit 2 ;; esac

# 选择 Python>=3.10：优先 uv，其次 python3.13..3.10，最后 python3
if command -v uv >/dev/null 2>&1; then
  PYRUN=(uv run python)
else
  PYRUN=()
  for c in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null; then
      PYRUN=("$c"); break
    fi
  done
  if [ ${#PYRUN[@]} -eq 0 ]; then
    echo "未找到 Python 3.10 或更高版本。请安装 uv（https://docs.astral.sh/uv/）或 Python 3.10+。" >&2
    exit 1
  fi
fi

# 端口占用检查
if command -v lsof >/dev/null 2>&1 && lsof -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "端口 $PORT 已被占用。可换端口：PORT=9000 ./start-web.sh" >&2
  exit 1
fi

ARGS+=(--host "$HOST" --port "$PORT")
[ -n "$TOKEN" ] && ARGS+=(--token "$TOKEN")

SHOW="127.0.0.1"
URL="http://$SHOW:$PORT/"
[ "$TV" -eq 1 ] && URL="${URL}?tv=1"

if [ "$HOST" = "0.0.0.0" ]; then
  LAN_IP="$( (ipconfig getifaddr en0 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}') || true)"
  echo "局域网访问：http://${LAN_IP:-<本机IP>}:$PORT/?token=<口令>$([ "$TV" -eq 1 ] && echo '&tv=1')"
fi

if [ "$OPEN" -eq 1 ]; then
  # 以 Python 内置逻辑打开，带口令时由其拼接地址；这里仅在无口令时用系统命令
  if [ -z "$TOKEN" ]; then
    ( sleep 1; { command -v open >/dev/null 2>&1 && open "$URL"; } || { command -v xdg-open >/dev/null 2>&1 && xdg-open "$URL"; } || true ) >/dev/null 2>&1 &
  else
    ARGS+=(--open)
  fi
fi

echo "启动：${PYRUN[*]} -m webui ${ARGS[*]//$TOKEN/***}"
echo "地址：$URL    （Ctrl+C 退出）"
exec "${PYRUN[@]}" -m webui "${ARGS[@]}"
