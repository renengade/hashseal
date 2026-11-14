"""Manifest generation, parsing and directory verification."""

from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path, PurePosixPath

from .core import (
    DEFAULT_EXCLUDES,
    MANIFEST_NAME,
    META_DIR,
    SKIP_DIRS,
    SKIP_SUFFIXES,
    atomic_write_text,
    sha256_file,
)

_LINE_RE = re.compile(r"^([0-9a-fA-F]{64}) [ *](.+)$")


class ManifestError(Exception):
    """清单内容非法（路径逃逸、格式错误等）。"""


def find_manifest(root: Path) -> tuple[Path, Path] | None:
    """优先 .hashseal/，兼容旧版根目录布局；返回 (清单路径, 元数据目录)。"""
    preferred = root / META_DIR / MANIFEST_NAME
    if preferred.is_file():
        return preferred, preferred.parent
    legacy = root / MANIFEST_NAME
    if legacy.is_file():
        return legacy, root
    return None


def _excluded(rel: PurePosixPath, patterns: tuple[str, ...]) -> bool:
    text = rel.as_posix()
    name = rel.name
    return any(fnmatch.fnmatch(text, p) or fnmatch.fnmatch(name, p) for p in patterns)


def iter_files(
    paths: list[str],
    *,
    excludes: tuple[str, ...] = (),
    follow_symlinks: bool = False,
) -> list[Path]:
    """展开文件/目录；目录遍历跳过缓存、签名产物和敏感文件。"""
    patterns = tuple(DEFAULT_EXCLUDES) + tuple(excludes)
    out: list[Path] = []
    for name in paths:
        p = Path(name)
        if p.is_dir():
            root = p.resolve()
            for dirpath, dirnames, filenames in os.walk(p, followlinks=follow_symlinks):
                dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
                for f in sorted(filenames):
                    fp = Path(dirpath) / f
                    if fp.is_symlink() and not follow_symlinks:
                        continue
                    if fp.suffix in SKIP_SUFFIXES or fp.name == MANIFEST_NAME:
                        continue
                    try:
                        rel = PurePosixPath(fp.resolve().relative_to(root).as_posix())
                    except ValueError:
                        continue
                    if _excluded(rel, patterns):
                        continue
                    out.append(fp)
        elif p.is_file():
            out.append(p)
    return out


def _default_base(paths: list[str]) -> Path:
    """未指定 --base 时，自动选择能让所有路径都相对化的基准目录。"""
    resolved = [Path(p).resolve() for p in paths]
    if len(resolved) == 1:
        p = resolved[0]
        return p if p.is_dir() else p.parent
    try:
        return Path(os.path.commonpath([str(p) for p in resolved]))
    except ValueError:
        return Path.cwd()


def build_manifest(
    paths: list[str],
    out_path: Path,
    base: Path | None = None,
    *,
    excludes: tuple[str, ...] = (),
    follow_symlinks: bool = False,
) -> int:
    """生成 sha256sum 兼容清单，返回条目数。"""
    files = iter_files(paths, excludes=excludes, follow_symlinks=follow_symlinks)
    if not files:
        raise ManifestError("没有找到任何文件")

    if base is None:
        base = _default_base(paths)
    base_resolved = base.resolve()
    lines: list[str] = []
    seen: set[str] = set()
    for p in files:
        if p.resolve() == out_path.resolve():
            continue
        try:
            shown = p.resolve().relative_to(base_resolved)
        except ValueError as exc:
            raise ManifestError(f"{p} 不在基准目录 {base} 下；请用 --base 指定") from exc
        rel = PurePosixPath(shown.as_posix())
        if rel.as_posix() in seen:
            continue
        seen.add(rel.as_posix())
        digest, _ = sha256_file(p)
        lines.append(f"{digest}  {rel.as_posix()}")

    if not lines:
        raise ManifestError("没有找到任何文件")
    atomic_write_text(out_path, "\n".join(lines) + "\n")
    return len(lines)


def parse_manifest(path: Path) -> list[tuple[str, str]]:
    """解析清单并做路径安全校验，返回 [(digest, rel)]。"""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ManifestError(f"无法读取清单 {path}: {exc}") from exc

    entries: list[tuple[str, str]] = []
    seen: set[str] = set()
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        match = _LINE_RE.match(line)
        if not match:
            raise ManifestError(f"清单第 {lineno} 行格式错误: {line!r}")
        digest, rel = match.group(1).lower(), match.group(2)
        pure = PurePosixPath(rel)
        if pure.is_absolute() or rel.startswith("\\"):
            raise ManifestError(f"清单第 {lineno} 行使用了绝对路径: {rel!r}")
        if any(part == ".." for part in pure.parts):
            raise ManifestError(f"清单第 {lineno} 行包含 '..'，拒绝路径逃逸: {rel!r}")
        if any(part in ("", ".") for part in pure.parts):
            raise ManifestError(f"清单第 {lineno} 行路径非法: {rel!r}")
        if "\x00" in rel:
            raise ManifestError(f"清单第 {lineno} 行包含 NUL 字符")
        key = pure.as_posix()
        if key in seen:
            raise ManifestError(f"清单存在重复条目: {key}")
        seen.add(key)
        entries.append((digest, key))
    if not entries:
        raise ManifestError("清单为空")
    return entries


def resolve_member(root: Path, rel: str) -> Path:
    """把清单条目解析到根目录内，拒绝逃逸。"""
    root_resolved = root.resolve()
    candidate = (root / rel).resolve()
    try:
        candidate.relative_to(root_resolved)
    except ValueError as exc:
        raise ManifestError(f"清单条目逃出根目录: {rel!r}") from exc
    return candidate


def verify_entries(
    root: Path, entries: list[tuple[str, str]]
) -> tuple[list[dict], list[dict]]:
    """校验清单条目，返回 (通过项, 失败项)。"""
    good: list[dict] = []
    bad: list[dict] = []
    for digest, rel in entries:
        try:
            target = resolve_member(root, rel)
        except ManifestError as exc:
            bad.append({"path": rel, "reason": str(exc)})
            continue
        if not target.is_file():
            bad.append({"path": rel, "reason": "文件缺失"})
            continue
        actual, _ = sha256_file(target)
        if actual != digest:
            bad.append({"path": rel, "reason": "内容不一致"})
        else:
            good.append({"path": rel, "digest": actual})
    return good, bad


def find_unlisted(
    root: Path,
    listed: set[str],
    *,
    excludes: tuple[str, ...] = (),
    follow_symlinks: bool = False,
) -> list[str]:
    """找出目录中存在、但清单未收录的文件（检测“新增文件”）。"""
    patterns = tuple(DEFAULT_EXCLUDES) + tuple(excludes)
    root_resolved = root.resolve()
    extras: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for f in sorted(filenames):
            fp = Path(dirpath) / f
            if fp.is_symlink() and not follow_symlinks:
                continue
            if fp.suffix in SKIP_SUFFIXES or fp.name == MANIFEST_NAME:
                continue
            try:
                rel = fp.resolve().relative_to(root_resolved)
            except ValueError:
                continue
            rel_posix = PurePosixPath(rel.as_posix())
            if _excluded(rel_posix, patterns):
                continue
            if rel_posix.as_posix() not in listed:
                extras.append(rel_posix.as_posix())
    return extras


def diff_manifests(left: list[tuple[str, str]], right: list[tuple[str, str]]) -> dict:
    """对比两份清单：新增 / 删除 / 内容变化。"""
    a = {rel: digest for digest, rel in left}
    b = {rel: digest for digest, rel in right}
    return {
        "added": sorted(set(b) - set(a)),
        "removed": sorted(set(a) - set(b)),
        "changed": sorted(rel for rel in set(a) & set(b) if a[rel] != b[rel]),
    }
