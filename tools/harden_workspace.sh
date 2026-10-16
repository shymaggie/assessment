#!/usr/bin/env bash
# 把判定代码与判据目录设为只读（宿主机侧，尽力而为的纵深防御）。
#
# 局限：若 guest 以 root 运行，文件权限对其无效；此时应依赖 RETEST_PINNED_MANIFEST_SHA256
# 带外固定值与 tools/verify_integrity.py 宿主机复核（见 docs/SECURITY.md）。
#
# 用法：tools/harden_workspace.sh [--undo]
set -euo pipefail
cd "$(dirname "$0")/.."
DIRS=(src knowledge data integrity deploy tools)

if [ "${1:-}" = "--undo" ]; then
  chmod -R u+w "${DIRS[@]}"
  echo "已恢复写权限（维护者修改代码后记得重新运行 tools/pin_integrity.py）"
  exit 0
fi

chmod -R a-w "${DIRS[@]}"
mkdir -p outputs evidence
chmod -R u+w outputs evidence
echo "已设为只读：${DIRS[*]}；可写：outputs/ evidence/"
