#!/usr/bin/env python3
"""宿主机侧独立复核判定代码完整性（R-INT-01），不依赖 Agent 工作区内的任何自述。

建议由宿主机 cron / systemd timer 在 Agent 运行之外执行；退出码可直接接监控：
  0 = OK   2 = DRIFT   3 = TAMPERED   4 = UNPINNED

用法：
  python3 tools/verify_integrity.py                      # 与 integrity/pins.json 比对
  python3 tools/verify_integrity.py --pinned <sha256>    # 与带外保存的固定值比对（推荐）
"""

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

import integrity  # noqa: E402

EXIT = {"OK": 0, "DRIFT": 2, "TAMPERED": 3, "UNPINNED": 4}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pinned", help="带外保存的清单摘要（优先于 integrity/pins.json）")
    ap.add_argument("--repo", default=str(REPO))
    args = ap.parse_args(argv)
    env = {integrity.PIN_ENV: args.pinned} if args.pinned else {}
    result = integrity.verify(Path(args.repo), env)
    print(json.dumps(result, ensure_ascii=False, indent=1))
    return EXIT[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
