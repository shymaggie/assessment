"""证据落盘与留存清理（R-RET-01）。"""

import json
import re
import shutil
import subprocess
from pathlib import Path

from common import RunContext, safe_name

RUN_DIR_RE = re.compile(r"^\d{14}-\d+(\.\d+)?$")
PIN_MARKER = "PINNED"
AUTO_MARKER = "AUTO"  # 由管线创建的运行目录才有；自动清理只动带该标记的目录，人工收录/历史目录一律不碰


def mark_auto(ctx: RunContext) -> Path:
    """创建本轮证据目录并打上 AUTO 标记（管线每轮开始时调用）。"""
    d = ctx.evidence_dir / ctx.run_id
    d.mkdir(parents=True, exist_ok=True)
    (d / AUTO_MARKER).write_text("", encoding="utf-8")
    return d


def save_probe(ctx: RunContext, vuln_id: str, step: str, probe: dict, request_meta: dict) -> str:
    """保存探针原始响应；request_meta 只含 URL / 头名 / 检索串（不含任何凭据值）。

    返回相对 evidence_dir 的上级（仓库根）风格路径，形如 evidence/<run_id>/probe_*.json。
    """
    d = ctx.evidence_dir / ctx.run_id
    d.mkdir(parents=True, exist_ok=True)
    fp = d / f"probe_{safe_name(vuln_id)}_{safe_name(step)}.json"
    record = dict(probe)
    record["request_meta"] = request_meta
    fp.write_text(json.dumps(record, ensure_ascii=False, indent=1), encoding="utf-8")
    return f"evidence/{ctx.run_id}/{fp.name}"


def _git_tracked_dirs(evidence_dir: Path) -> set:
    """被 git 跟踪的证据目录（人工收录的快照）永不清理；无 git/非仓库时返回空集。"""
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z", "--", str(evidence_dir)],
            cwd=evidence_dir.parent, capture_output=True, timeout=5, check=False,
        ).stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return set()
    tracked = set()
    for rel in filter(None, out.split("\0")):
        parts = Path(rel).parts
        if len(parts) >= 2:
            tracked.add(parts[1])
    return tracked


def prune(evidence_dir: Path, keep_last: int, include_unmarked: bool = False) -> list:
    """保留最近 keep_last 个运行目录，返回被删除的目录名。

    只动 YYYYMMDDhhmmss-pid 形态且带 AUTO 标记的目录；PINNED 标记或被 git 跟踪的目录永不清理。
    include_unmarked=True（仅手动工具可用）时把无标记的历史目录也纳入候选。
    """
    if keep_last <= 0 or not evidence_dir.is_dir():
        return []
    runs = sorted(
        p.name for p in evidence_dir.iterdir()
        if p.is_dir() and RUN_DIR_RE.match(p.name)
        and (include_unmarked or (p / AUTO_MARKER).exists()))
    excess = runs[:-keep_last] if len(runs) > keep_last else []
    if not excess:
        return []
    tracked = _git_tracked_dirs(evidence_dir)
    removed = []
    for name in excess:
        target = evidence_dir / name
        if name in tracked or (target / PIN_MARKER).exists():
            continue
        shutil.rmtree(target, ignore_errors=True)
        removed.append(name)
    return removed
