"""CycloneDX SBOM generation from a signed manifest."""

from __future__ import annotations

import re
from pathlib import Path

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from . import __version__
from .core import MANIFEST_NAME, now_iso, warn
from .manifest import parse_manifest

_REQ_RE = re.compile(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*==\s*([^\s;#]+)")


def _purl(name: str, version: str) -> str:
    normalized = name.lower().replace("_", "-")
    return f"pkg:pypi/{normalized}@{version}"


def _from_uv_lock(path: Path, root_name: str) -> list[dict]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    components: list[dict] = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        if not name or not version or name == root_name:
            continue
        components.append({
            "type": "library",
            "name": name,
            "version": version,
            "purl": _purl(name, version),
        })
    return components


def _from_requirements(path: Path) -> list[dict]:
    components: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "--")):
            continue
        match = _REQ_RE.match(line)
        if not match:
            continue
        name, version = match.group(1), match.group(2)
        components.append({
            "type": "library",
            "name": name,
            "version": version,
            "purl": _purl(name, version),
        })
    return components


def dependency_components(
    root: Path, lock_path: Path | None = None
) -> list[dict]:
    """解析 uv.lock 或 requirements.txt，返回去重后的组件列表。"""
    if lock_path is not None:
        if not lock_path.is_file():
            raise FileNotFoundError(f"找不到依赖清单: {lock_path}")
        candidates = [lock_path]
    else:
        candidates = [root / "uv.lock", root / "requirements.txt"]

    for path in candidates:
        if not path.is_file():
            continue
        try:
            items = (
                _from_uv_lock(path, root.name)
                if path.name == "uv.lock"
                else _from_requirements(path)
            )
        except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
            warn(f"无法解析依赖清单 {path}: {exc}")
            return []
        seen: set[tuple[str, str]] = set()
        unique: list[dict] = []
        for item in items:
            key = (item["name"], item["version"])
            if key not in seen:
                seen.add(key)
                unique.append(item)
        return unique
    return []


def build_sbom(
    root: Path,
    *,
    include_deps: bool = False,
    lock_path: Path | None = None,
) -> dict:
    manifest = root / MANIFEST_NAME
    entries = parse_manifest(manifest)
    file_components = [
        {
            "type": "file",
            "name": rel,
            "hashes": [{"alg": "SHA-256", "content": digest}],
        }
        for digest, rel in entries
    ]
    components = list(file_components)
    if include_deps:
        components.extend(dependency_components(root, lock_path))

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": now_iso(),
            "tools": [{"vendor": "hashseal", "name": "hashseal", "version": __version__}],
            "component": {"type": "application", "name": root.name},
        },
        "components": components,
    }
