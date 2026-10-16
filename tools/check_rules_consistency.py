#!/usr/bin/env python3
"""校验 knowledge/rules.json 与 knowledge/01_rules.md 的规则 ID 一一对应（CI 使用）。

规则：
  1. rules.json 中所有 `rule_id` / `*_rule_id` 的取值，必须在 01_rules.md 中出现；
  2. 01_rules.md 中所有「小节标题」或加粗声明的规则 ID（## R-… / **R-…**），必须在 rules.json 中出现；
  3. data/vulns.json 的 rule_ref 必须是 rules.json 中存在的规则 ID。

用法：python3 tools/check_rules_consistency.py   （不一致时退出码 1）
"""

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ID_RE = re.compile(r"R-[A-Z0-9]+(?:-[A-Z0-9]+)+")


def _rule_id_values(node, out: set) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            if (k == "rule_id" or k.endswith("_rule_id")) and isinstance(v, str):
                out.add(v)
            _rule_id_values(v, out)
    elif isinstance(node, list):
        for v in node:
            _rule_id_values(v, out)


def check(repo: Path = REPO) -> list:
    rules_text = (repo / "knowledge" / "rules.json").read_text(encoding="utf-8")
    md = (repo / "knowledge" / "01_rules.md").read_text(encoding="utf-8")
    vulns = json.loads((repo / "data" / "vulns.json").read_text(encoding="utf-8"))["vulns"]

    declared: set = set()
    _rule_id_values(json.loads(rules_text), declared)
    json_all = set(ID_RE.findall(rules_text))
    md_all = set(ID_RE.findall(md))
    md_declared = set()
    for line in md.splitlines():
        if line.startswith("## ") or re.match(r"^\*\*R-", line):
            md_declared.update(ID_RE.findall(line.split("：")[0].split("**", 2)[1] if line.startswith("**") else line))

    problems = []
    for rid in sorted(declared - md_all):
        problems.append(f"rules.json 声明了 {rid}，但 01_rules.md 中没有对应说明")
    for rid in sorted(md_declared - json_all):
        problems.append(f"01_rules.md 声明了 {rid}，但 rules.json 中没有对应条目")
    known = declared | json_all
    for v in vulns:
        ref = v.get("rule_ref")
        if ref and ref not in known:
            problems.append(f"{v.get('id')} 的 rule_ref={ref} 在 rules.json 中不存在")
    return problems


def main() -> int:
    problems = check()
    for p in problems:
        print("FAIL", p)
    if not problems:
        print("rules.json ↔ 01_rules.md 规则 ID 一致")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
