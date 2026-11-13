"""Best-effort JSON Lines audit log."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path


def audit_path() -> Path:
    override = os.environ.get("HASHSEAL_AUDIT_LOG")
    if override:
        return Path(override).expanduser()
    base = os.environ.get("XDG_STATE_HOME")
    root = Path(base).expanduser() if base else Path.home() / ".local" / "state"
    return root / "hashseal" / "audit.jsonl"


def write_event(event: str, **fields: object) -> None:
    """追加一条审计事件；失败时静默（审计不能影响主流程）。"""
    if os.environ.get("HASHSEAL_NO_AUDIT"):
        return
    record = {
        "ts": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "event": event,
        **fields,
    }
    try:
        path = audit_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass
