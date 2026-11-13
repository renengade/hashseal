"""Audit logging: local JSONL with rotation + optional syslog sink."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_BACKUPS = 5
SINKS = {"file", "syslog", "both"}


def audit_path() -> Path:
    override = os.environ.get("HASHSEAL_AUDIT_LOG")
    if override:
        return Path(override).expanduser()
    base = os.environ.get("XDG_STATE_HOME")
    root = Path(base).expanduser() if base else Path.home() / ".local" / "state"
    return root / "hashseal" / "audit.jsonl"


def _settings(config: dict | None) -> tuple[str, Path, int, int, str]:
    cfg = config or {}
    sink = os.environ.get("HASHSEAL_AUDIT_SINK") or cfg.get("audit_sink") or "file"
    if sink not in SINKS:
        sink = "file"
    path = Path(
        os.environ.get("HASHSEAL_AUDIT_LOG") or cfg.get("audit_file") or audit_path()
    ).expanduser()
    max_bytes = int(
        os.environ.get("HASHSEAL_AUDIT_MAX_BYTES")
        or cfg.get("audit_max_bytes")
        or DEFAULT_MAX_BYTES
    )
    backups = int(
        os.environ.get("HASHSEAL_AUDIT_BACKUPS") or cfg.get("audit_backups") or DEFAULT_BACKUPS
    )
    facility = str(cfg.get("audit_facility") or "user")
    return sink, path, max_bytes, backups, facility


def _rotate(path: Path, backups: int) -> None:
    if backups <= 0:
        path.unlink(missing_ok=True)
        return
    oldest = path.with_name(f"{path.name}.{backups}")
    oldest.unlink(missing_ok=True)
    for index in range(backups - 1, 0, -1):
        src = path.with_name(f"{path.name}.{index}")
        if src.exists():
            os.replace(src, path.with_name(f"{path.name}.{index + 1}"))
    if path.exists():
        os.replace(path, path.with_name(f"{path.name}.1"))


def _write_file(path: Path, line: str, max_bytes: int, backups: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if max_bytes > 0 and path.exists() and path.stat().st_size + len(line) > max_bytes:
        _rotate(path, backups)
    fd = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(line)


def _write_syslog(line: str, facility_name: str) -> None:
    try:
        import syslog  # Unix only
    except ImportError:
        return
    facility = getattr(syslog, f"LOG_{facility_name.upper()}", syslog.LOG_USER)
    try:
        syslog.openlog("hashseal", syslog.LOG_PID, facility)
        syslog.syslog(syslog.LOG_INFO, line.rstrip("\n"))
    except OSError:
        pass


def write_event(event: str, config: dict | None = None, **fields: object) -> None:
    """追加审计事件；任何失败都不能影响主流程。"""
    if os.environ.get("HASHSEAL_NO_AUDIT"):
        return
    record = {
        "ts": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "event": event,
        **fields,
    }
    line = json.dumps(record, ensure_ascii=False) + "\n"
    sink, path, max_bytes, backups, facility = _settings(config)
    try:
        if sink in ("file", "both"):
            _write_file(path, line, max_bytes, backups)
        if sink in ("syslog", "both"):
            _write_syslog(line, facility)
    except OSError:
        pass
