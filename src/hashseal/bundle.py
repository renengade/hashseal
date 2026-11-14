"""Portable bundles: signed directory + manifest + optional timestamp."""

from __future__ import annotations

import json
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from .core import (
    load_public,
    parse_record,
    public_fingerprint,
    sha256_file,
    verify_record,
)
from .manifest import (
    ManifestError,
    find_manifest,
    find_unlisted,
    parse_manifest,
    verify_entries,
)

BUNDLE_META = "hashseal-bundle.json"
BUNDLE_FORMAT = "hashseal-bundle/1"


class BundleError(Exception):
    """Bundle creation or extraction failed."""


def _safe_name(name: str) -> PurePosixPath:
    pure = PurePosixPath(name)
    if pure.is_absolute() or any(part in ("..", "") for part in pure.parts):
        raise BundleError(f"bundle 中包含非法路径: {name!r}")
    return pure


def create_bundle(
    root: Path,
    out_path: Path,
    *,
    public_key_path: Path,
    include_pubkey: bool = False,
    allow_unlisted: bool = False,
) -> dict:
    if not root.is_dir():
        raise BundleError(f"不是目录: {root}")
    found = find_manifest(root)
    if found is None:
        raise BundleError(f"{root} 还没有签名（先执行 hashseal sign {root}）")
    manifest, _meta_dir = found
    sig = Path(str(manifest) + ".sig")
    if not sig.is_file():
        raise BundleError(f"{root} 还没有签名（先执行 hashseal sign {root}）")

    try:
        entries = parse_manifest(manifest)
        _good, bad = verify_entries(root, entries)
    except ManifestError as exc:
        raise BundleError(str(exc)) from exc
    if bad:
        raise BundleError(f"清单校验失败：{len(bad)} 个文件不一致，拒绝打包")

    extras = find_unlisted(root, {rel for _, rel in entries})
    if extras and not allow_unlisted:
        raise BundleError(
            f"目录中有未列入清单的文件（{len(extras)} 个），先用 --allow-unlisted 或重新签名"
        )

    public_key = load_public(public_key_path)
    record = parse_record(sig)
    result = verify_record(record, manifest, public_key)
    if not result["ok"]:
        raise BundleError("清单签名无效，拒绝打包")

    tsr = Path(str(sig) + ".tsr")
    manifest_rel = manifest.relative_to(root).as_posix()
    sig_rel = sig.relative_to(root).as_posix()
    tsr_rel = tsr.relative_to(root).as_posix()
    meta = {
        "format": BUNDLE_FORMAT,
        "created": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "root": root.name,
        "manifest": manifest_rel,
        "files": len(entries),
        "fingerprint": public_fingerprint(public_key),
        "signer": record.get("signer", ""),
        "has_timestamp": tsr.is_file(),
    }

    tmp_path = out_path.with_name(out_path.name + ".tmp")
    try:
        with zipfile.ZipFile(tmp_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(BUNDLE_META, json.dumps(meta, ensure_ascii=False, indent=2))
            zf.write(manifest, manifest_rel)
            zf.write(sig, sig_rel)
            if tsr.is_file():
                zf.write(tsr, tsr_rel)
            if include_pubkey:
                zf.write(public_key_path, "public.pem")
            for _digest, rel in entries:
                zf.write(root / rel, rel)
        os.replace(tmp_path, out_path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise
    return meta


def unpack_bundle(bundle_path: Path, dest: Path, *, force: bool = False) -> dict:
    if not bundle_path.is_file():
        raise BundleError(f"找不到 bundle: {bundle_path}")
    if dest.exists() and any(dest.iterdir()) and not force:
        raise BundleError(f"目标目录非空: {dest}（覆盖加 --force）")

    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    try:
        with zipfile.ZipFile(bundle_path) as zf:
            meta_raw = zf.read(BUNDLE_META)
            meta = json.loads(meta_raw.decode("utf-8"))
            for info in zf.infolist():
                pure = _safe_name(info.filename)
                mode = (info.external_attr >> 16) & 0o170000
                if mode == 0o120000:
                    raise BundleError(f"bundle 中包含符号链接: {info.filename!r}")
                target = (root / pure).resolve()
                try:
                    target.relative_to(root)
                except ValueError as exc:
                    raise BundleError(f"bundle 条目逃出目标目录: {info.filename!r}") from exc
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, target.open("wb") as dst:
                    dst.write(src.read())
    except (zipfile.BadZipFile, OSError, json.JSONDecodeError) as exc:
        raise BundleError(f"解包失败: {exc}") from exc
    return meta


def bundle_size(path: Path) -> int:
    return sha256_file(path)[1]
