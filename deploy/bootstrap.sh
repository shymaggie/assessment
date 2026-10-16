#!/usr/bin/env bash
# 一键部署：把 README 4.5 节的十步手工流程收敛为一个可重复执行的脚本。
#
# 用法（在项目根目录、有 docker 与 sudo 权限的服务器上）：
#   CALCULATOR_PKG=/path/to/octobus/examples/calculator-js deploy/bootstrap.sh
#   DRY_RUN=1 CALCULATOR_PKG=... deploy/bootstrap.sh      # 只打印将执行的命令
#
# 可配置项（环境变量，均有默认值，不再把 172.17.0.1 硬编码在流程里）：
#   OCTOBUS_IMAGE        OctoBus 镜像（默认按摘要锁定，与 README 一致）
#   BIND_ADDR            docker0 网关地址（默认 172.17.0.1）
#   TARGET_HOSTPORT      探针出口白名单目标（默认 $BIND_ADDR:8081）
#   ALLOWED_CIDRS        探针解析地址白名单 CIDR（默认 172.17.0.0/16）
#   CALCULATOR_PKG       上游 calculator-js 示例包目录（必填）
#   NPM_REGISTRY         容器内 npm 源（默认 https://registry.npmmirror.com；设为空则不改）
#   ENV_FILE             令牌写入位置（默认 ./.env，权限 600；建议放到工作区之外，见 docs/SECURITY.md）
#
# 幂等：已存在的容器/服务/实例/capset 会被跳过而不是报错；令牌仅在 ENV_FILE 尚无时生成。
set -euo pipefail

DRY_RUN="${DRY_RUN:-0}"
OCTOBUS_IMAGE="${OCTOBUS_IMAGE:-ghcr.io/chaitin/octobus@sha256:377409360a3d54f8e058340a7fb4874a994f18d11d35ba8f7cae0bec23a724a6}"
BIND_ADDR="${BIND_ADDR:-172.17.0.1}"
TARGET_HOSTPORT="${TARGET_HOSTPORT:-${BIND_ADDR}:8081}"
ALLOWED_CIDRS="${ALLOWED_CIDRS:-172.17.0.0/16}"
NPM_REGISTRY="${NPM_REGISTRY-https://registry.npmmirror.com}"
ENV_FILE="${ENV_FILE:-./.env}"
CALCULATOR_PKG="${CALCULATOR_PKG:-}"

run() {
  if [ "$DRY_RUN" = "1" ]; then printf '[dry-run] %s\n' "$*"; else "$@"; fi
}
oct() { run docker exec octobus octobus "$@"; }
exists() { [ "$DRY_RUN" = "1" ] && return 1; "$@" >/dev/null 2>&1; }
# 仅依赖 README/RUNBOOK 中已验证存在的 list 子命令做幂等判断：<子命令...> -- <名称>
listed() {
  [ "$DRY_RUN" = "1" ] && return 1
  local name="${*: -1}"; local args=("${@:1:$#-1}")
  docker exec octobus octobus "${args[@]}" 2>/dev/null | grep -Eqw -- "$name"
}

[ -n "$CALCULATOR_PKG" ] || { echo "ERROR: 必须设置 CALCULATOR_PKG（上游 examples/calculator-js 目录）" >&2; exit 2; }
[ -d "$(dirname "$0")/../services/retest-probe" ] || { echo "ERROR: 请在项目内运行" >&2; exit 2; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> ① OctoBus daemon"
if exists docker inspect octobus; then echo "已存在，跳过"; else
  run docker run -d --name octobus --restart=always -p "${BIND_ADDR}:9000:9000" \
    -v octobus-data:/var/lib/octobus "$OCTOBUS_IMAGE"
fi

echo "==> ② npm 源"
[ -z "$NPM_REGISTRY" ] || run docker exec octobus npm config set registry "$NPM_REGISTRY"

echo "==> ③ 导入 retest-probe（探针 v1.1：DNS 重绑定防护 / 响应体上限 / 限速 / 全文检索）"
run chmod 755 "$ROOT/services/retest-probe/bin/probe.js"   # supervisor 直接 exec 入口脚本，必须有 x 位（RUNBOOK Phase 3）
run docker cp "$ROOT/services/retest-probe" octobus:/tmp/retest-probe
listed service list retest-probe || oct service import retest-probe /tmp/retest-probe

echo "==> ④ 创建探针实例（出口白名单 fail-closed）"
CONFIG_JSON="{\"allowedHosts\":[\"${TARGET_HOSTPORT}\"],\"allowedCidrs\":[\"${ALLOWED_CIDRS}\"],\"maxBodyBytes\":1048576,\"maxRequestsPerMinute\":120}"
listed instance list retest-test || \
  oct instance create retest-test --service retest-probe --config-json "$CONFIG_JSON" --no-start
oct instance start retest-test

echo "==> ⑤ calculator 链路（上游示例包）"
run docker cp "$CALCULATOR_PKG" octobus:/tmp/calculator-js
listed service list calculator || oct service import calculator /tmp/calculator-js
listed instance list calculator-test || \
  oct instance create calculator-test --service calculator \
    --config-json '{"label":"primary"}' --secret-json '{"apiToken":"runtime-secret"}' --no-start
oct instance start calculator-test

echo "==> ⑥ capset：方法级最小授权"
if listed capset list retester; then echo "capset 已存在，跳过授权"; else
  oct capset create retester --name "Retest Agent"
  oct capset add-instance retester retest-test --no-all-methods
  oct capset select-method retester retest-test retest.v1.RetestService/ProbeHttp
  oct capset add-instance retester calculator-test --no-all-methods
  oct capset select-method retester calculator-test calculator.v1.CalculatorService/Subtract
fi
oct capset list-methods retester

echo "==> ⑦ 访问令牌（stdin 传入，不落 shell history，不回显）"
if [ -f "$ENV_FILE" ] && grep -q '^OCTOBUS_TOKEN_RETESTER=.\+' "$ENV_FILE" 2>/dev/null; then
  echo "$ENV_FILE 已含令牌，跳过（如需轮换请手工 add-token 并更新该文件）"
elif [ "$DRY_RUN" = "1" ]; then
  echo "[dry-run] openssl rand -hex 24 | docker exec -i octobus octobus capset add-token retester retester-agent --token-stdin  → 写入 $ENV_FILE (chmod 600)"
else
  umask 077
  TOKEN="$(openssl rand -hex 24)"
  printf '%s' "$TOKEN" | docker exec -i octobus octobus capset add-token retester retester-agent \
    --name "assessment agent" --token-stdin
  {
    echo "OCTOBUS_BASE_URL=http://octobus:9000"
    echo "OCTOBUS_TOKEN_RETESTER=${TOKEN}"
    echo "RETEST_TARGET_BASE=http://${TARGET_HOSTPORT}"
    echo "RETEST_SESSION_A=session=demo-token-a"
    echo "RETEST_SESSION_B=session=demo-token-b"
    echo "RETEST_PINNED_MANIFEST_SHA256="
  } > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  unset TOKEN
  echo "已写入 $ENV_FILE（权限 600）"
fi

echo "==> ⑧ 靶场（宿主机 systemd）"
run sudo mkdir -p /opt/vulnlab
run sudo cp "$ROOT/vulnlab/vulnlab.py" /opt/vulnlab/vulnlab.py
run sudo cp "$ROOT/vulnlab/vulnlab.service" /etc/systemd/system/
run sudo systemctl daemon-reload
run sudo systemctl enable --now vulnlab

echo "==> ⑧.5 运行数据目录（guest 的 /var/lib/retest 对应宿主机 ./runtime）"
run mkdir -p "$ROOT/runtime"

echo "==> ⑨ 固定判定代码摘要（建议把输出的值写入 ENV_FILE 的 RETEST_PINNED_MANIFEST_SHA256）"
run python3 "$ROOT/tools/pin_integrity.py"

echo "==> ⑩ 应用项目"
echo "请执行：cd \"$ROOT\" && ac up"
