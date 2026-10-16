"""R-INT-01 判定代码完整性校验。

背景：Agent 的工作区是可写挂载，LLM 理论上能改动 pipeline / rules。"判定逻辑不交给模型"
不能只靠 prompt 约束，所以：

  1. 管线启动时计算 src/*.py + knowledge/rules.json + data/vulns.json 的 sha256 清单；
  2. 与「固定值」比对：
       - 环境变量 RETEST_PINNED_MANIFEST_SHA256（由宿主机/部署侧注入，Agent 改仓库文件改不到它）
         不一致 → TAMPERED，管线拒绝运行；
       - 否则与仓库内 integrity/pins.json 比对，不一致 → DRIFT（运行但报告标红、要求人工关注）；
       - 都没有 → UNPINNED；
  3. 清单摘要写入 report.json，宿主机侧 tools/verify_integrity.py 可独立复核。

诚实边界：pins.json 本身在工作区内，Agent 同时改代码和 pins.json 能绕过 DRIFT 检测；
真正的防线是环境变量固定值或宿主机侧复核（见 docs/SECURITY.md）。
"""

import hashlib
import json
import os
from pathlib import Path

PIN_ENV = "RETEST_PINNED_MANIFEST_SHA256"
PINS_RELPATH = "integrity/pins.json"
TRACKED_GLOBS = ("src/*.py", "knowledge/rules.json", "data/vulns.json")


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compute_manifest(repo: Path) -> dict:
    files = {}
    for pattern in TRACKED_GLOBS:
        for p in sorted(repo.glob(pattern)):
            if p.is_file():
                files[p.relative_to(repo).as_posix()] = _sha256_file(p)
    return files


def manifest_digest(manifest: dict) -> str:
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def write_pins(repo: Path) -> dict:
    manifest = compute_manifest(repo)
    pins = {"manifest_sha256": manifest_digest(manifest), "files": manifest}
    path = repo / PINS_RELPATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(pins, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return pins


def verify(repo: Path, env=None) -> dict:
    """返回 {status, manifest_sha256, pinned_by, changed_files}；status ∈ OK/DRIFT/TAMPERED/UNPINNED。"""
    env = os.environ if env is None else env
    manifest = compute_manifest(repo)
    digest = manifest_digest(manifest)
    result = {"status": "UNPINNED", "manifest_sha256": digest, "pinned_by": None,
              "changed_files": []}

    env_pin = (env.get(PIN_ENV) or "").strip().lower()
    if env_pin:
        result["pinned_by"] = "env"
        result["status"] = "OK" if env_pin == digest else "TAMPERED"
        return result

    pins_path = repo / PINS_RELPATH
    if pins_path.exists():
        try:
            pins = json.loads(pins_path.read_text(encoding="utf-8"))
            pinned_files = pins.get("files") or {}
            result["pinned_by"] = "file"
            if pins.get("manifest_sha256") == digest:
                result["status"] = "OK"
            else:
                result["status"] = "DRIFT"
                names = set(manifest) | set(pinned_files)
                result["changed_files"] = sorted(n for n in names if manifest.get(n) != pinned_files.get(n))
        except (OSError, ValueError):
            result["status"] = "DRIFT"
            result["pinned_by"] = "file"
    return result
