#!/usr/bin/env python3
"""手动清理旧证据目录（R-RET-01）。pipeline 每轮结束也会按 rules.json 的 retention 自动清理。

只动形如 YYYYMMDDhhmmss-pid 且带 AUTO 标记（管线创建）的运行目录；含 PINNED 标记文件或被 git 跟踪的目录永不清理。
数据目录由 RETEST_DATA_DIR 指定（默认仓库根）。

用法：python3 tools/prune_evidence.py --keep 336 [--dry-run]
"""

import argparse
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

import evidence  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--keep", type=int, default=336)
    ap.add_argument("--dir", default=str((Path(os.environ["RETEST_DATA_DIR"]) if os.environ.get("RETEST_DATA_DIR") else REPO) / "evidence"))
    ap.add_argument("--include-unmarked", action="store_true", help="同时清理无 AUTO 标记的历史运行目录（PINNED / git 跟踪仍受保护）")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    d = Path(args.dir)
    if args.dry_run:
        runs = sorted(p.name for p in d.iterdir()
                      if p.is_dir() and evidence.RUN_DIR_RE.match(p.name)
                      and (args.include_unmarked or (p / evidence.AUTO_MARKER).exists())) if d.is_dir() else []
        print(f"将保留最近 {args.keep} 轮，候选清理 {max(0, len(runs) - args.keep)} 个（未排除 PINNED/git 跟踪目录）")
        return 0
    removed = evidence.prune(d, args.keep, include_unmarked=args.include_unmarked)
    print(f"已清理 {len(removed)} 个目录")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
