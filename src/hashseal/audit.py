"""Audit logging: local JSONL with daily/size rotation and 90-day retention."""

from __future__ import annotations

import getpass
import json
import os
import socket
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from .core import fmt_time, warn

DEFAULT_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_RETENTION_DAYS = 90
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
    retention = int(
        os.environ.get("HASHSEAL_AUDIT_RETENTION_DAYS")
        or cfg.get("audit_retention_days")
        or DEFAULT_RETENTION_DAYS
    )
    facility = str(cfg.get("audit_facility") or "user")
    return sink, path, max_bytes, retention, facility


def _archive(path: Path, stamp: str) -> Path:
    return path.with_name(f"{path.stem}-{stamp}{path.suffix}")


def _first_entry_date(path: Path) -> date | None:
    try:
        with path.open("rb") as f:
            head = f.read(4096)
    except OSError:
        return None
    for raw in head.splitlines():
        try:
            record = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        ts = record.get("ts")
        if not ts:
            break
        try:
            return datetime.fromisoformat(ts).date()
        except (TypeError, ValueError):
            break
    return None


def _rotate_by_day(path: Path, now: datetime) -> None:
    if not path.exists() or path.stat().st_size == 0:
        return
    entry_date = _first_entry_date(path)
    if entry_date is None:
        entry_date = datetime.fromtimestamp(path.stat().st_mtime).date()
    if entry_date < now.date():
        target = _archive(path, entry_date.isoformat())
        if target.exists():
            target = _archive(path, now.strftime("%Y-%m-%d-%H%M%S-%f"))
        os.replace(path, target)


def _rotate_by_size(path: Path, max_bytes: int, incoming: int, now: datetime) -> None:
    if max_bytes <= 0 or not path.exists():
        return
    if path.stat().st_size + incoming <= max_bytes:
        return
    target = _archive(path, now.strftime("%Y-%m-%d-%H%M%S"))
    index = 1
    while target.exists():
        target = _archive(path, f"{now.strftime('%Y-%m-%d-%H%M%S')}-{index}")
        index += 1
    os.replace(path, target)


def _cleanup(path: Path, retention_days: int, now: datetime) -> None:
    if retention_days <= 0:
        return
    cutoff = now.date() - timedelta(days=retention_days)
    for archive in path.parent.glob(f"{path.stem}-*{path.suffix}"):
        name = archive.name
        prefix = f"{path.stem}-"
        if not (name.startswith(prefix) and name.endswith(path.suffix)):
            continue
        middle = name[len(prefix) : -len(path.suffix)]
        try:
            archive_date = date.fromisoformat(middle[:10])
        except ValueError:
            archive_date = datetime.fromtimestamp(archive.stat().st_mtime).date()
        if archive_date < cutoff:
            archive.unlink(missing_ok=True)


def audit_files(path: Path) -> list[Path]:
    """活跃文件 + 归档文件，按时间从旧到新。"""
    archives = sorted(
        p
        for p in path.parent.glob(f"{path.stem}-*{path.suffix}")
        if p.name[len(path.stem) + 1 : -len(path.suffix)][:10].count("-") == 2
    )
    files = list(archives)
    if path.is_file():
        files.append(path)
    return files


def read_events(path: Path, limit: int) -> list[str]:
    lines: list[str] = []
    for file in audit_files(path):
        try:
            lines.extend(file.read_text(encoding="utf-8").splitlines())
        except OSError:
            continue
    return lines[-limit:]


def _primary_ip() -> str | None:
    """获取本机主 IPv4；UDP connect 不会真正发包。"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return None


def audit_context() -> dict:
    """记录操作者与来源主机信息（本地 CLI 没有“客户端 IP”）。"""
    try:
        user = getpass.getuser()
    except (KeyError, OSError):
        user = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
    context: dict[str, object] = {
        "user": user,
        "hostname": socket.gethostname(),
    }
    if hasattr(os, "getuid"):
        context["uid"] = os.getuid()
    ip = _primary_ip()
    if ip:
        context["ip"] = ip
    ssh_connection = os.environ.get("SSH_CONNECTION")
    ssh_client = os.environ.get("SSH_CLIENT")
    if ssh_connection:
        context["ssh_client"] = ssh_connection.split()[0]
    elif ssh_client:
        context["ssh_client"] = ssh_client.split()[0]
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        context["sudo_user"] = sudo_user
    return context


def _write_file(path: Path, line: str, max_bytes: int, retention_days: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now()
    _rotate_by_day(path, now)
    _rotate_by_size(path, max_bytes, len(line.encode("utf-8")), now)
    fd = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(line)
    _cleanup(path, retention_days, now)


def _write_syslog(line: str, facility_name: str) -> bool:
    try:
        import syslog  # Unix only
    except ImportError:
        return False
    facility = getattr(syslog, f"LOG_{facility_name.upper()}", syslog.LOG_USER)
    try:
        syslog.openlog("hashseal", syslog.LOG_PID, facility)
        syslog.syslog(syslog.LOG_INFO, line.rstrip("\n"))
        return True
    except OSError:
        return False


def write_event(event: str, config: dict | None = None, **fields: object) -> None:
    """追加审计事件；任何失败都不能影响主流程。"""
    ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    record = {
        "ts": ts,
        "ts_local": fmt_time(ts),
        "event": event,
        **audit_context(),
        **fields,
    }
    line = json.dumps(record, ensure_ascii=False) + "\n"
    sink, path, max_bytes, retention, facility = _settings(config)
    try:
        if sink in ("file", "both"):
            _write_file(path, line, max_bytes, retention)
        if sink in ("syslog", "both"):
            ok = _write_syslog(line, facility)
            if not ok:
                warn("syslog 不可用，回退写入本地审计文件")
                if sink == "syslog":
                    _write_file(path, line, max_bytes, retention)
    except OSError as exc:
        warn(f"审计日志写入失败: {exc}")
