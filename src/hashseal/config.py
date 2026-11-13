"""User configuration (~/.config/hashseal/config.toml)."""

from __future__ import annotations

import os
from pathlib import Path

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from .core import warn

CONFIG_ENV = "HASHSEAL_CONFIG"


def config_path() -> Path:
    override = os.environ.get(CONFIG_ENV)
    if override:
        return Path(override).expanduser()
    base = os.environ.get("XDG_CONFIG_HOME")
    root = Path(base).expanduser() if base else Path.home() / ".config"
    return root / "hashseal" / "config.toml"


def load_config() -> dict:
    path = config_path()
    if not path.is_file():
        return {}
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        warn(f"无法读取配置文件 {path}: {exc}")
        return {}
    section = data.get("hashseal", data)
    return section if isinstance(section, dict) else {}
