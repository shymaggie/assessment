#!/usr/bin/env python3
"""重新生成 integrity/pins.json（R-INT-01）。

仅在【人工评审过】对 src/*.py、knowledge/rules.json、data/vulns.json 的改动之后运行。
打印的摘要同时可作为部署侧固定值：

    RETEST_PINNED_MANIFEST_SHA256=<摘要>   # 写进 .env / 宿主机环境，Agent 改不到

用法：python3 tools/pin_integrity.py
"""

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

import integrity  # noqa: E402


def main() -> int:
    pins = integrity.write_pins(REPO)
    print(f"已写入 {integrity.PINS_RELPATH}（{len(pins['files'])} 个文件）")
    print(f"RETEST_PINNED_MANIFEST_SHA256={pins['manifest_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
