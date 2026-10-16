#!/usr/bin/env python3
"""宿主机侧告警外发：读取 outputs/alerts.jsonl 的新增行，POST 到 Webhook。

为什么放在宿主机而不是 pipeline：Agent 侧的一切对外访问必须经 OctoBus 网关（system_prompt 红线），
pipeline 因此只落盘告警、不外发。本脚本在 guest 之外运行（建议由 cron/systemd timer 触发）。

配置（环境变量）：
  RETEST_ALERT_WEBHOOK   Webhook URL（默认只允许 https；内网 http 需加 --allow-http）
  RETEST_DATA_DIR        运行数据目录（默认仓库根；其下 outputs/alerts.jsonl 为告警队列）

幂等：已发送的行数记录在 outputs/.alerts.offset，重复运行不会重复发送；发送失败不推进偏移，下次重试。

用法：
  python3 tools/notify.py            # 发送新增告警
  python3 tools/notify.py --dry-run  # 只打印，不发送、不推进偏移
"""

import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

REPO = Path(__file__).resolve().parent.parent


def pending_alerts(outputs: Path) -> tuple:
    """返回 (新增告警列表, 当前总行数)。"""
    path = outputs / "alerts.jsonl"
    if not path.exists():
        return [], 0
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    offset_file = outputs / ".alerts.offset"
    try:
        offset = int(offset_file.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        offset = 0
    offset = min(max(offset, 0), len(lines))
    alerts = []
    for line in lines[offset:]:
        try:
            alerts.append(json.loads(line))
        except ValueError:
            continue
    return alerts, len(lines)


def format_message(alerts: list) -> dict:
    rows = [f"- {a.get('vuln_id', '-')}: {a.get('from') or '-'} -> {a.get('to')} ({a.get('kind')})"
            for a in alerts]
    return {"text": "漏洞复测告警\n" + "\n".join(rows), "alerts": alerts}


def validate_webhook(url: str, allow_http: bool) -> None:
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ValueError("Webhook URL 非法")
    if parts.scheme == "http" and not allow_http:
        raise ValueError("拒绝明文 http Webhook（如确为内网地址，加 --allow-http）")


def send(url: str, payload: dict, timeout: float = 10.0) -> None:
    req = urllib.request.Request(url, data=json.dumps(payload, ensure_ascii=False).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status >= 300:
            raise RuntimeError(f"Webhook 返回 {resp.status}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    default_outputs = (Path(os.environ["RETEST_DATA_DIR"]) if os.environ.get("RETEST_DATA_DIR") else REPO) / "outputs"
    ap.add_argument("--outputs", default=str(default_outputs))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--allow-http", action="store_true")
    args = ap.parse_args(argv)
    outputs = Path(args.outputs)

    alerts, total = pending_alerts(outputs)
    if not alerts:
        print("无新增告警")
        return 0
    message = format_message(alerts)
    if args.dry_run:
        print(json.dumps(message, ensure_ascii=False, indent=1))
        return 0
    url = os.environ.get("RETEST_ALERT_WEBHOOK", "").strip()
    if not url:
        print("未配置 RETEST_ALERT_WEBHOOK，跳过发送（偏移不推进）", file=sys.stderr)
        return 1
    try:
        validate_webhook(url, args.allow_http)
        send(url, message)
    except Exception as exc:
        print(f"告警发送失败（下次重试）: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    (outputs / ".alerts.offset").write_text(str(total), encoding="utf-8")
    print(f"已发送 {len(alerts)} 条告警")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
