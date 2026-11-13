"""Command-line interface for hashseal."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from . import __version__
from .audit import audit_path, write_event
from .bundle import BundleError, create_bundle, unpack_bundle
from .config import config_path, load_config
from .core import (
    DEFAULT_PRIVATE,
    DEFAULT_PUBLIC,
    DEFAULT_TSA,
    FORMAT,
    MANIFEST_NAME,
    atomic_write_text,
    build_record,
    die,
    fingerprint_matches,
    generate_keypair,
    load_private,
    load_public,
    parse_record,
    public_fingerprint,
    sha256_file,
    sig_path_for,
    verify_record,
    warn,
)
from .manifest import (
    ManifestError,
    build_manifest,
    diff_manifests,
    find_unlisted,
    iter_files,
    parse_manifest,
    verify_entries,
)
from .sbom import build_sbom
from .tsa import (
    TimestampError,
    _dir_timestamp_target,
    _fmt_gen_time,
    _print_token_info,
    _stamp_file,
    check_token,
    resolve_ca,
    token_metadata,
)


def _password(args: argparse.Namespace, *, required: bool = False) -> str | None:
    if getattr(args, "password_file", None):
        path = Path(args.password_file)
        if not path.is_file():
            die(f"找不到口令文件: {path}")
        return path.read_text(encoding="utf-8").rstrip("\n")
    env = os.environ.get("HASHSEAL_KEY_PASSWORD")
    if env:
        return env
    if required:
        die(
            "私钥已加密：请用 --password-file 或环境变量 HASHSEAL_KEY_PASSWORD 提供口令"
        )
    return None


def _cfg(args: argparse.Namespace, key: str, default=None):
    cfg = getattr(args, "_config", None) or {}
    return cfg.get(key, default)


def _tsa(args: argparse.Namespace) -> str:
    return (
        getattr(args, "tsa", None)
        or os.environ.get("HASHSEAL_TSA")
        or _cfg(args, "tsa")
        or DEFAULT_TSA
    )


def _tsa_ca(args: argparse.Namespace) -> str | None:
    return getattr(args, "tsa_ca", None) or _cfg(args, "tsa_ca")


def _key_path(args: argparse.Namespace) -> Path:
    return Path(getattr(args, "key", None) or _cfg(args, "key") or DEFAULT_PRIVATE)


def _pub_path(args: argparse.Namespace) -> Path:
    return Path(getattr(args, "pubkey", None) or _cfg(args, "pubkey") or DEFAULT_PUBLIC)


def _follow(args: argparse.Namespace) -> bool:
    value = getattr(args, "follow_symlinks", None)
    if value is not None:
        return bool(value)
    return bool(_cfg(args, "follow_symlinks", False))


def _excludes(args: argparse.Namespace) -> tuple[str, ...]:
    configured = tuple(_cfg(args, "exclude", []) or ())
    return tuple(getattr(args, "exclude", None) or ()) + configured


def _audit(args: argparse.Namespace, event: str, **fields: object) -> None:
    if getattr(args, "no_audit", False):
        return
    if not _cfg(args, "audit", True):
        return
    write_event(event, **fields)


def _collect_targets(args: argparse.Namespace) -> tuple[list[Path], dict[Path, Path]]:
    """只计算目标，不写任何文件（预检之前不能有副作用）。"""
    targets: list[Path] = []
    dir_roots: dict[Path, Path] = {}
    for name in args.files:
        src = Path(name)
        if src.is_dir():
            manifest = src / MANIFEST_NAME
            targets.append(manifest)
            dir_roots[manifest] = src
        elif src.is_file():
            targets.append(src)
        else:
            warn(f"跳过（不存在）: {src}")
    if not targets:
        die("没有找到可签名的文件")
    return targets, dir_roots


def _materialize_manifests(args: argparse.Namespace, dir_roots: dict[Path, Path]) -> None:
    for manifest, src in dir_roots.items():
        try:
            count = build_manifest(
                [str(src)],
                manifest,
                src,
                excludes=_excludes(args),
                follow_symlinks=_follow(args),
            )
        except ManifestError as exc:
            die(str(exc))
        print(f"已生成清单 {manifest}（{count} 个文件）")
        sys.stdout.flush()


def cmd_keygen(args: argparse.Namespace) -> int:
    priv_path = Path(args.private)
    pub_path = Path(args.public)
    for label, target in (("私钥", priv_path), ("公钥", pub_path)):
        if target.is_dir():
            die(f"{label}输出路径是目录，需要文件路径: {target}")
        if target.exists() and not args.force:
            die(f"{target} 已存在（确需覆盖加 --force）")

    password = _password(args)
    if password is not None and len(password) < 8:
        warn("口令过短（< 8 字符），建议使用更强的口令")
    key = generate_keypair(priv_path, pub_path, password)
    print(
        f"私钥: {priv_path}{'（已加密）' if password else '（未加密，建议使用 --password-file）'}"
    )
    print(f"公钥: {pub_path}  (可公开分发)")
    print(f"指纹: {public_fingerprint(key.public_key())}")
    print()
    print("下一步：把公钥和上面这行指纹，通过“与文件不同的可信渠道”交给对方核对。")
    return 0


def cmd_fingerprint(args: argparse.Namespace) -> int:
    target = Path(args.public) if getattr(args, "public", None) else _pub_path(args)
    print(public_fingerprint(load_public(target)))
    return 0


def cmd_hash(args: argparse.Namespace) -> int:
    rc = 0
    for name in args.files:
        p = Path(name)
        if p.is_dir():
            targets = iter_files(
                [name], excludes=_excludes(args), follow_symlinks=_follow(args)
            )
            if not targets:
                warn(f"跳过（目录里没有可哈希的文件）: {p}")
                rc = 2
                continue
        elif p.is_file():
            targets = [p]
        else:
            warn(f"跳过（不存在）: {p}")
            rc = 2
            continue
        for target in targets:
            digest, size = sha256_file(target)
            print(f"{digest}  {target}")
            if args.verbose:
                warn(f"{target}: {size} 字节")
    return rc


def cmd_manifest(args: argparse.Namespace) -> int:
    out_path = Path(args.output)
    if out_path.is_dir():
        die(f"清单输出路径是目录，请给文件路径: {out_path}")
    base = Path(args.base) if args.base else None
    try:
        count = build_manifest(
            args.paths,
            out_path,
            base,
            excludes=_excludes(args),
            follow_symlinks=_follow(args),
        )
    except ManifestError as exc:
        die(str(exc))
    print(f"已写入 {out_path}（{count} 个文件）")
    print(f"下一步：hashseal sign {out_path}   然后 hashseal verify {out_path}")
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    key = load_private(_key_path(args), _password(args))

    if any(Path(n).is_dir() for n in args.files):
        if args.sig:
            die("--sig 不支持目录输入（目录固定签 MANIFEST.sha256）")
        if args.name:
            die("--name 不支持目录输入")

    targets, dir_roots = _collect_targets(args)
    if (args.sig or args.tsr) and len(targets) > 1:
        die("--sig / --tsr 只能用于单文件或单个目录")
    if args.tsr and not args.timestamp:
        die("--tsr 需要配合 --timestamp 使用")
    if _tsa_ca(args) and not args.timestamp:
        warn("--tsa-ca 只有配合 --timestamp 才有意义，已忽略")
    if args.sig and Path(args.sig).is_dir():
        die(f"--sig 指向的是目录，需要文件路径: {args.sig}")

    if not args.force:
        for target in targets:
            sig_path = Path(args.sig) if args.sig else sig_path_for(target)
            if sig_path.exists():
                die(f"{sig_path} 已存在（覆盖加 --force）")
            if args.timestamp:
                tsr_path = Path(args.tsr) if args.tsr else Path(str(sig_path) + ".tsr")
                if tsr_path.exists():
                    die(f"{tsr_path} 已存在（覆盖加 --force）")

    _materialize_manifests(args, dir_roots)

    rc = 0
    for p in targets:
        record = build_record(key, p, signer=args.signer, signed_name=args.name)
        sig_path = Path(args.sig) if args.sig else sig_path_for(p)
        atomic_write_text(
            sig_path,
            json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        )
        print(f"已签名 {p}")
        print(f"  签名文件: {sig_path}")
        print(f"  SHA-256 : {record['digest']}")
        print(f"  大小    : {record['size']} 字节")
        print(f"  格式    : {record['format']}")
        sys.stdout.flush()
        _audit(
            args,
            "sign",
            path=str(p),
            ok=True,
            fingerprint=public_fingerprint(key.public_key()),
            timestamp=bool(args.timestamp),
        )

        if args.timestamp:
            try:
                tsr_path, info, _ = _stamp_file(
                    sig_path,
                    tsa=_tsa(args),
                    tsa_ca=_tsa_ca(args),
                    timeout=args.timeout,
                    out_path=Path(args.tsr) if args.tsr else None,
                    force=args.force,
                    retries=args.retry,
                )
            except TimestampError as exc:
                warn(f"{p}: 签名已生成，但时间戳失败: {exc}")
                warn(f"可稍后单独重试: hashseal timestamp {sig_path}")
                _audit(args, "timestamp", path=str(sig_path), ok=False, error=str(exc))
                rc = 1
                continue
            print(f"  时间戳  : {tsr_path}")
            print(
                f"            {_fmt_gen_time(info['gen_time'])} 由 TSA「{info['tsa']}」见证"
                f"（证书链: {info['chain']}）"
            )
    return rc


def _print_file_result(result: dict, pubkey_fp: str) -> None:
    expected = result["expected"]
    print(f"大小      : {result['size']} 字节")
    print(f"SHA-256   : {result['digest']}")
    signer_label = "" if result["signer_signed"] else "（未签名备注）"
    print(
        f"签名记录  : 名称={expected['name']} 大小={expected['size']} "
        f"签名者={expected['signer'] or '(未填写)'}{signer_label} "
        f"本地时间={expected['created']}"
    )
    print(f"公钥指纹  : {pubkey_fp}")


def _verify_file(
    file_path: Path,
    sig_path: Path,
    pubkey,
    args: argparse.Namespace,
) -> dict:
    record = parse_record(sig_path)
    result = verify_record(record, file_path, pubkey, name=args.name)
    if result["ok"] and not result["signer_signed"]:
        pass  # v1 签名没有签名者字段，展示时已标注
    ts_info = None
    ts_error = None
    if result["ok"] and args.tsr:
        try:
            tsr_path = Path(args.tsr)
            if not tsr_path.is_file():
                raise TimestampError(f"找不到时间戳令牌: {tsr_path}")
            ca_pem, ca_label, strict = resolve_ca(_tsa_ca(args))
            ts_info = check_token(
                tsr_path.read_bytes(),
                hashlib.sha256(sig_path.read_bytes()).digest(),
                data_path=sig_path,
                ca_pem=ca_pem,
                ca_label=ca_label,
                chain_required=strict,
            )
        except TimestampError as exc:
            ts_error = str(exc)
    return {
        "result": result,
        "ts_info": ts_info,
        "ts_error": ts_error,
        "record": record,
    }


def _verify_dir(args: argparse.Namespace, root: Path) -> int:
    manifest = root / MANIFEST_NAME
    if not manifest.is_file():
        die(f"{root} 下没有 {MANIFEST_NAME}，请先执行: hashseal sign {root}")
    sig_path = Path(str(manifest) + ".sig")
    if not sig_path.is_file():
        die(f"找不到清单签名 {sig_path}")

    tsr = args.tsr
    if args.ts_only:
        target, _kind = _dir_timestamp_target(root)
        if tsr is None:
            auto = Path(str(target) + ".tsr")
            if not auto.is_file():
                die(f"找不到时间戳令牌 {auto}")
            tsr = str(auto)
        return _check_timestamp_only(target, tsr, _tsa_ca(args), args.json)

    pub = load_public(_pub_path(args))
    fp = public_fingerprint(pub)
    if args.expect_fingerprint and not fingerprint_matches(
        args.expect_fingerprint, pub
    ):
        print(f"公钥指纹  : {fp}")
        print("结果      : ❌ 公钥指纹与 --expect-fingerprint 不一致")
        return 1

    if tsr is None:
        auto = Path(str(sig_path) + ".tsr")
        if auto.is_file():
            tsr = str(auto)
    sub = argparse.Namespace(**vars(args))
    sub.file = str(manifest)
    sub.sig = None
    sub.name = None
    sub.tsr = tsr

    info = _verify_file(manifest, sig_path, pub, sub)
    result = info["result"]
    try:
        entries = parse_manifest(manifest)
        good, bad = verify_entries(root, entries)
    except ManifestError as exc:
        die(str(exc))
    extras: list[str] = []
    if not args.allow_unlisted:
        extras = find_unlisted(
            root,
            {rel for _, rel in entries},
            excludes=_excludes(args),
            follow_symlinks=_follow(args),
        )
    ok = result["ok"] and not bad and not extras and info["ts_error"] is None
    _audit(args, "verify", path=str(root), ok=ok, signature_ok=result["ok"], timestamp_ok=bool(info["ts_info"]))

    if args.json:
        print(
            json.dumps(
                {
                    "file": str(root),
                    "ok": ok,
                    "manifest": {
                        "file": str(manifest),
                        "ok": result["ok"],
                        "digest": result["digest"],
                        "expected": result["expected"],
                    },
                    "signer_fingerprint": fp,
                    "timestamp": info["ts_info"]
                    or ({"ok": False, "error": info["ts_error"]} if args.tsr else None),
                    "files": {
                        "checked": len(entries),
                        "ok": len(good),
                        "failed": bad,
                        "unlisted": extras,
                    },
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0 if ok else 1

    print(f"目录      : {root}")
    print(f"清单      : {manifest}")
    _print_file_result(result, fp)
    if not result["ok"]:
        print("结果      : ❌ 清单签名不成立")
        return 1
    print("结果      : ✅ 清单签名通过")
    if info["ts_info"]:
        print(
            f"时间戳    : ✅ {_fmt_gen_time(info['ts_info']['gen_time'])} 由 TSA"
            f"「{info['ts_info']['tsa']}」见证（证书链: {info['ts_info']['chain']}）"
        )
    elif info["ts_error"]:
        print(f"时间戳    : ❌ {info['ts_error']}")
    if bad:
        print(f"逐文件校验  : ❌ {len(bad)}/{len(entries)} 项失败")
        for item in bad:
            print(f"  - {item['path']}: {item['reason']}")
    else:
        print(f"逐文件校验  : ✅ {len(entries)} 个文件全部一致")
    if extras:
        print(f"未列入清单  : ❌ {len(extras)} 个文件")
        for rel in extras:
            print(f"  - {rel}")
    return 0 if ok else 1


def _check_timestamp_only(
    target: Path, tsr: str | None, tsa_ca: str | None, as_json: bool
) -> int:
    if tsr is None:
        die("请用 --tsr 指定时间戳令牌")
    token_path = Path(tsr)
    if not token_path.is_file():
        die(f"找不到时间戳令牌: {token_path}")
    digest_hex, size = sha256_file(target)
    ca_pem, ca_label, strict = resolve_ca(tsa_ca)
    try:
        info = check_token(
            token_path.read_bytes(),
            bytes.fromhex(digest_hex),
            data_path=target,
            ca_pem=ca_pem,
            ca_label=ca_label,
            chain_required=strict,
        )
    except TimestampError as exc:
        if as_json:
            print(
                json.dumps(
                    {
                        "file": str(target),
                        "token": str(token_path),
                        "ok": False,
                        "error": str(exc),
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
        else:
            print(f"文件    : {target}")
            print(f"SHA-256 : {digest_hex}")
            print(f"结果    : ❌ {exc}")
        return 1

    if as_json:
        print(
            json.dumps(
                {
                    "file": str(target),
                    "size": size,
                    "token": str(token_path),
                    "ts_only": True,
                    **info,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        print(f"文件    : {target}")
        print(f"大小    : {size} 字节")
        print(f"SHA-256 : {digest_hex}")
        print("结果    : ✅ 令牌有效，且确实对应这份内容")
        _print_token_info(info)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    p = Path(args.file)
    if p.is_dir():
        return _verify_dir(args, p)

    if args.ts_only:
        if not p.is_file():
            die(f"路径不存在: {p}")
        return _check_timestamp_only(p, args.tsr, _tsa_ca(args), args.json)
    if not p.is_file():
        die(f"文件不存在或不是普通文件: {p}")

    sig_path = Path(args.sig) if args.sig else sig_path_for(p)
    if not sig_path.is_file():
        die(f"找不到签名文件 {sig_path}")
    pub = load_public(_pub_path(args))
    fp = public_fingerprint(pub)
    if args.expect_fingerprint and not fingerprint_matches(
        args.expect_fingerprint, pub
    ):
        print(f"公钥指纹  : {fp}")
        print("结果      : ❌ 公钥指纹与 --expect-fingerprint 不一致")
        return 1

    info = _verify_file(p, sig_path, pub, args)
    result, ts_info, ts_error = info["result"], info["ts_info"], info["ts_error"]
    record = info["record"]
    ok = result["ok"] and ts_error is None

    if args.json:
        _audit(
            args,
            "verify",
            path=str(p),
            ok=ok,
            signature_ok=result["ok"],
            timestamp_ok=(ts_info is not None if args.tsr else None),
        )
        payload = {
            "file": str(p),
            "ok": ok,
            "signature_valid": result["ok"],
            "signer_signed": result["signer_signed"],
            "digest": result["digest"],
            "size": result["size"],
            "name": result["name"],
            "expected": result["expected"],
            "signer_fingerprint": fp,
            "timestamp": (ts_info or {"ok": False, "error": ts_error})
            if args.tsr
            else None,
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0 if ok else 1

    print(f"文件      : {p}")
    _print_file_result(result, fp)
    if result["ok"]:
        if (
            record.get("digest") != result["digest"]
            or record.get("size") != result["size"]
        ):
            warn("签名有效，但签名文件中的摘要/大小字段与实物不符（元数据被改过？）")
        print("结果      : ✅ 通过 —— 内容与签名完全一致，且签名来自该公钥对应的私钥")
        if args.tsr:
            if ts_info is not None:
                ca_note = f"信任根: {ts_info['ca']}，" if ts_info.get("ca") else ""
                print(
                    f"时间戳    : ✅ {_fmt_gen_time(ts_info['gen_time'])} 由 TSA"
                    f"「{ts_info['tsa']}」见证（{ca_note}证书链: {ts_info['chain']}）"
                )
                print("            → 该签名在该时刻之前已经存在，事后无法抵赖")
            else:
                print(f"时间戳    : ❌ {ts_error}")
                return 1
        return 0

    expected = result["expected"]
    print("结果      : ❌ 失败 —— 文件与签名不匹配")
    if expected["size"] != result["size"]:
        print(f"  - 大小不同：签名记录 {expected['size']}，实际 {result['size']}")
    if expected["digest"] != result["digest"]:
        print(
            f"  - SHA-256 不同：签名记录 {expected['digest']}，实际 {result['digest']}"
        )
    if expected["name"] != result["name"]:
        print(
            f"  - 名称不同：签名记录 {expected['name']}，实际按 {result['name']} 校验"
        )
    if (
        expected["digest"] == result["digest"]
        and expected["size"] == result["size"]
        and expected["name"] != result["name"]
    ):
        print("  → 内容一致，只是文件名不同。若确属改名，加 --name", expected["name"])
    elif expected["digest"] == result["digest"] and expected["size"] == result["size"]:
        print(
            "  → 内容一致但签名不成立：可能是签名文件被替换，或公钥不是签名者本人的。"
        )
    else:
        print("  → 文件内容已被修改，或拿到的不是签名时的那一份。")
    print("  → 也可能只是公钥不对：请用可信渠道核对上面的公钥指纹。")
    if args.tsr:
        print("时间戳    : 未校验（签名已失败，时间戳无法挽救内容）")
    return 1


def cmd_timestamp(args: argparse.Namespace) -> int:
    p = Path(args.file)
    if p.is_dir():
        p, kind = _dir_timestamp_target(p)
        print(f"目录模式：对{kind} {p} 申请时间戳")
    elif not p.is_file():
        die(f"路径不存在: {p}")
    digest_hex, size = sha256_file(p)
    try:
        out, info, _ = _stamp_file(
            p,
            tsa=_tsa(args),
            tsa_ca=_tsa_ca(args),
            timeout=args.timeout,
            out_path=Path(args.out) if args.out else None,
            force=args.force,
            digest_hex=digest_hex,
            retries=args.retry,
        )
    except TimestampError as exc:
        die(f"获取时间戳失败: {exc}")

    if args.json:
        print(
            json.dumps(
                {"file": str(p), "size": size, "token": str(out), **info},
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        print(f"已取得时间戳 {p}")
        print(f"  令牌文件: {out}")
        print(f"  SHA-256 : {digest_hex}")
        _print_token_info(info)
    print()
    print(
        "提示：把 .tsr 与文件/签名一起分发；验证用 verify --tsr（仅验时间戳加 --ts-only）。"
    )
    return 0


def cmd_ots(args: argparse.Namespace) -> int:
    exe = shutil.which("ots")
    if not exe:
        die("未安装 ots。执行：uv tool install opentimestamps-client")
    if not args.ots_args:
        die("用法：hashseal ots stamp|verify|upgrade FILE ...")
    return subprocess.run([exe, *args.ots_args], check=False).returncode


def cmd_diff(args: argparse.Namespace) -> int:
    try:
        left = parse_manifest(Path(args.left))
        right = parse_manifest(Path(args.right))
    except ManifestError as exc:
        die(str(exc))
    result = diff_manifests(left, right)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"新增: {len(result['added'])}")
        for rel in result["added"]:
            print(f"  + {rel}")
        print(f"删除: {len(result['removed'])}")
        for rel in result["removed"]:
            print(f"  - {rel}")
        print(f"变化: {len(result['changed'])}")
        for rel in result["changed"]:
            print(f"  ~ {rel}")
    return 0 if not (result["added"] or result["removed"] or result["changed"]) else 1


def cmd_inspect(args: argparse.Namespace) -> int:
    p = Path(args.file)
    if not p.is_file():
        die(f"文件不存在: {p}")
    if p.suffix == ".tsr":
        try:
            meta = token_metadata(p.read_bytes())
        except TimestampError as exc:
            die(str(exc))
        if args.json:
            print(json.dumps(meta, ensure_ascii=False, indent=2))
        else:
            print(f"令牌      : {p}")
            for key in (
                "gen_time",
                "tsa",
                "serial",
                "policy",
                "digest_alg",
                "sig_alg",
                "chain",
            ):
                if key in meta:
                    print(f"{key:10}: {meta[key]}")
        return 0

    record = parse_record(p)
    if args.json:
        print(json.dumps(record, ensure_ascii=False, indent=2))
    else:
        print(f"签名文件  : {p}")
        print(
            f"格式      : {record.get('format')}（签名者字段{'已签名' if record.get('format') == FORMAT else '未签名'}）"
        )
        print(f"名称      : {record.get('name')}")
        print(f"大小      : {record.get('size')}")
        print(f"SHA-256   : {record.get('digest')}")
        print(f"签名者    : {record.get('signer') or '(未填写)'}")
        print(f"本地时间  : {record.get('created')}（未签名）")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    p = Path(args.file)
    if p.is_dir():
        manifest = p / MANIFEST_NAME
        sig = Path(str(manifest) + ".sig")
        if not manifest.is_file() or not sig.is_file():
            die(f"{p} 尚未签名")
        pub = load_public(_pub_path(args))
        record = parse_record(sig)
        result = verify_record(record, manifest, pub)
        try:
            entries = parse_manifest(manifest)
            good, bad = verify_entries(p, entries)
        except ManifestError as exc:
            die(str(exc))
        extras = [] if args.allow_unlisted else find_unlisted(
            p, {rel for _, rel in entries}, excludes=_excludes(args), follow_symlinks=_follow(args)
        )
        ok = result["ok"] and not bad and not extras
        if args.json:
            print(json.dumps({
                "path": str(p), "ok": ok, "signature_ok": result["ok"],
                "checked": len(entries), "failed": bad, "unlisted": extras,
            }, ensure_ascii=False, indent=2))
        else:
            mark = "✅" if ok else "❌"
            print(f"{mark} {p}: 清单签名{'有效' if result['ok'] else '无效'}，"
                  f"{len(good)}/{len(entries)} 个文件一致"
                  + (f"，{len(extras)} 个未列入清单" if extras else ""))
        _audit(args, "status", path=str(p), ok=ok)
        return 0 if ok else 1

    if not p.is_file():
        die(f"文件不存在: {p}")
    sig = Path(args.sig) if args.sig else sig_path_for(p)
    if not sig.is_file():
        die(f"找不到签名文件 {sig}")
    pub = load_public(_pub_path(args))
    result = verify_record(parse_record(sig), p, pub)
    if args.json:
        print(json.dumps({"path": str(p), "ok": result["ok"], **result}, ensure_ascii=False, indent=2))
    else:
        print(f"{'✅' if result['ok'] else '❌'} {p}: 签名{'有效' if result['ok'] else '无效'}")
    _audit(args, "status", path=str(p), ok=result["ok"])
    return 0 if result["ok"] else 1


def cmd_renew(args: argparse.Namespace) -> int:
    p = Path(args.file)
    if p.is_dir():
        target, _kind = _dir_timestamp_target(p)
    elif p.suffix == ".sig":
        target = p
    else:
        target = Path(str(p) + ".sig")
    if not target.is_file():
        die(f"找不到签名文件: {target}")
    digest_hex, _size = sha256_file(target)
    try:
        out, info, _ = _stamp_file(
            target,
            tsa=_tsa(args),
            tsa_ca=_tsa_ca(args),
            timeout=args.timeout,
            force=args.force,
            digest_hex=digest_hex,
            retries=args.retry,
        )
    except TimestampError as exc:
        _audit(args, "renew", path=str(target), ok=False, error=str(exc))
        die(f"续期失败: {exc}")
    print(f"已续期 {target}")
    print(f"  令牌文件: {out}")
    print(f"  {_fmt_gen_time(info['gen_time'])} 由 TSA「{info['tsa']}」见证")
    _audit(args, "renew", path=str(target), ok=True, tsa=info["tsa"])
    return 0


def cmd_bundle(args: argparse.Namespace) -> int:
    root = Path(args.dir)
    out = Path(args.output)
    try:
        meta = create_bundle(
            root,
            out,
            public_key_path=_pub_path(args),
            include_pubkey=args.include_pubkey,
            allow_unlisted=args.allow_unlisted,
        )
    except BundleError as exc:
        die(str(exc))
    print(f"已打包 {root} -> {out}")
    print(f"  文件数: {meta['files']}")
    print(f"  指纹  : {meta['fingerprint']}")
    print(f"  时间戳: {'包含' if meta['has_timestamp'] else '未包含'}")
    _audit(args, "bundle", path=str(out), ok=True, files=meta["files"])
    return 0


def cmd_unpack(args: argparse.Namespace) -> int:
    bundle = Path(args.bundle)
    dest = Path(args.dest)
    try:
        meta = unpack_bundle(bundle, dest, force=args.force)
    except BundleError as exc:
        die(str(exc))
    print(f"已解包 {bundle} -> {dest}")
    print(f"  文件数: {meta.get('files')}")
    print(f"  指纹  : {meta.get('fingerprint')}")

    if args.no_verify:
        _audit(args, "unpack", path=str(dest), ok=True, verified=False)
        return 0
    included_pub = dest / "public.pem"
    pub = Path(args.pubkey) if args.pubkey else (
        included_pub if included_pub.is_file() else _pub_path(args)
    )
    if included_pub.is_file() and not args.pubkey:
        warn("使用的是 bundle 内置公钥，请通过可信渠道核对指纹")
    verify_args = build_parser().parse_args([
        "verify", str(dest), "-p", str(pub),
        "--exclude", "hashseal-bundle.json",
        "--exclude", "public.pem",
    ])
    verify_args._config = getattr(args, "_config", {})
    verify_args.no_audit = getattr(args, "no_audit", False)
    rc = cmd_verify(verify_args)
    _audit(args, "unpack", path=str(dest), ok=(rc == 0), verified=True)
    return rc


def cmd_config(args: argparse.Namespace) -> int:
    path = config_path()
    cfg = load_config()
    if args.json:
        print(json.dumps(
            {"path": str(path), "exists": path.is_file(), "config": cfg},
            ensure_ascii=False, indent=2,
        ))
    else:
        print(f"配置路径: {path}" + ("" if path.is_file() else "（不存在，使用默认值）"))
        for key in ("tsa", "tsa_ca", "key", "pubkey", "exclude", "follow_symlinks", "audit"):
            if key in cfg:
                print(f"  {key} = {cfg[key]}")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    path = audit_path()
    if not path.is_file():
        print("(暂无审计日志)")
        return 0
    lines = path.read_text(encoding="utf-8").splitlines()[-args.lines:]
    print("\n".join(lines))
    return 0


def cmd_sbom(args: argparse.Namespace) -> int:
    root = Path(args.dir)
    manifest = root / MANIFEST_NAME
    if not manifest.is_file():
        die(f"{root} 下没有 {MANIFEST_NAME}，请先执行: hashseal sign {root}")
    try:
        data = build_sbom(root)
    except ManifestError as exc:
        die(str(exc))
    out = Path(args.output)
    atomic_write_text(out, json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    print(f"已生成 SBOM {out}（{len(data['components'])} 个组件）")
    print(f"下一步：hashseal sign {out}")
    _audit(args, "sbom", path=str(out), ok=True, components=len(data["components"]))
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="hashseal",
        description="SHA-256 + Ed25519 文件一致性 / 来源校验工具",
    )
    ap.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {__version__}"
    )
    ap.add_argument("--no-audit", action="store_true", help="本次不写审计日志")
    sub = ap.add_subparsers(dest="cmd", required=True)

    kg = sub.add_parser("keygen", help="生成密钥对（只做一次）")
    kg.add_argument("--private", default=DEFAULT_PRIVATE, help="私钥输出路径")
    kg.add_argument("--public", default=DEFAULT_PUBLIC, help="公钥输出路径")
    kg.add_argument("--password-file", help="私钥口令文件（写入后私钥加密）")
    kg.add_argument("--force", action="store_true")
    kg.set_defaults(func=cmd_keygen)

    fp = sub.add_parser("fingerprint", help="打印公钥指纹，供电话/当面核对")
    fp.add_argument("public", nargs="?", default=None, help="公钥 PEM 文件")
    fp.set_defaults(func=cmd_fingerprint)

    h = sub.add_parser("hash", help="输出 sha256sum 兼容的校验和")
    h.add_argument("files", nargs="+", help="文件或目录")
    h.add_argument("-v", "--verbose", action="store_true")
    h.add_argument(
        "--exclude",
        action="append",
        metavar="GLOB",
        help="目录模式下排除的文件（可重复）",
    )
    h.add_argument("--follow-symlinks", action="store_true", default=None)
    h.set_defaults(func=cmd_hash)

    mf = sub.add_parser("manifest", help="为一组文件生成 MANIFEST.sha256")
    mf.add_argument("paths", nargs="+", help="文件或目录")
    mf.add_argument("-o", "--output", default=MANIFEST_NAME)
    mf.add_argument("--base", help="记录相对路径的基准目录")
    mf.add_argument("--exclude", action="append", metavar="GLOB")
    mf.add_argument("--follow-symlinks", action="store_true", default=None)
    mf.set_defaults(func=cmd_manifest)

    sg = sub.add_parser("sign", help="为文件/目录生成 .sig 分离签名")
    sg.add_argument("files", nargs="+", help="文件或目录")
    sg.add_argument("-k", "--key", default=None)
    sg.add_argument("--password-file", help="私钥口令文件")
    sg.add_argument("--sig", help="签名输出路径（单文件或单个目录）")
    sg.add_argument("--signer", default="", help="署名信息（v2 起纳入签名）")
    sg.add_argument("--name", help="签名时记录的文件名")
    sg.add_argument("--timestamp", action="store_true")
    sg.add_argument("--tsa", default=None)
    sg.add_argument("--tsa-ca")
    sg.add_argument("--timeout", type=float, default=30.0)
    sg.add_argument("--retry", type=int, default=2, help="TSA 失败重试次数")
    sg.add_argument("--tsr")
    sg.add_argument("--exclude", action="append", metavar="GLOB")
    sg.add_argument("--follow-symlinks", action="store_true", default=None)
    sg.add_argument("--force", action="store_true")
    sg.set_defaults(func=cmd_sign)

    vf = sub.add_parser("verify", help="验证文件/目录与签名")
    vf.add_argument("file", help="文件或目录")
    vf.add_argument("--sig")
    vf.add_argument("-p", "--pubkey", default=None, help="公钥 PEM")
    vf.add_argument("--name", help="文件被改名时指定原文件名")
    vf.add_argument("--tsr")
    vf.add_argument("--ts-only", action="store_true", help="只校验时间戳，不要求 .sig")
    vf.add_argument("--tsa-ca")
    vf.add_argument("--expect-fingerprint", help="要求公钥指纹匹配（如 SHA256:...）")
    vf.add_argument(
        "--allow-unlisted", action="store_true", help="允许目录中存在未列入清单的文件"
    )
    vf.add_argument("--exclude", action="append", metavar="GLOB")
    vf.add_argument("--follow-symlinks", action="store_true", default=None)
    vf.add_argument("--json", action="store_true")
    vf.set_defaults(func=cmd_verify)

    ts = sub.add_parser("timestamp", help="向 TSA 申请 RFC 3161 可信时间戳")
    ts.add_argument("file", help="文件或目录（目录会自动定位 MANIFEST）")
    ts.add_argument("-o", "--out")
    ts.add_argument("--tsa", default=None)
    ts.add_argument("--tsa-ca")
    ts.add_argument("--timeout", type=float, default=30.0)
    ts.add_argument("--retry", type=int, default=2)
    ts.add_argument("--force", action="store_true")
    ts.add_argument("--json", action="store_true")
    ts.set_defaults(func=cmd_timestamp)

    d = sub.add_parser("diff", help="对比两份清单")
    d.add_argument("left")
    d.add_argument("right")
    d.add_argument("--json", action="store_true")
    d.set_defaults(func=cmd_diff)

    ins = sub.add_parser("inspect", help="查看 .sig / .tsr 的元数据")
    ins.add_argument("file")
    ins.add_argument("--json", action="store_true")
    ins.set_defaults(func=cmd_inspect)

    st = sub.add_parser("status", help="快速检查签名（不请求 TSA）")
    st.add_argument("file", help="文件或目录")
    st.add_argument("--sig")
    st.add_argument("-p", "--pubkey", default=None)
    st.add_argument("--allow-unlisted", action="store_true")
    st.add_argument("--exclude", action="append", metavar="GLOB")
    st.add_argument("--follow-symlinks", action="store_true", default=None)
    st.add_argument("--json", action="store_true")
    st.set_defaults(func=cmd_status)

    rn = sub.add_parser("renew", help="只续期时间戳，不重签")
    rn.add_argument("file", help=".sig、文件或目录")
    rn.add_argument("--tsa", default=None)
    rn.add_argument("--tsa-ca")
    rn.add_argument("--timeout", type=float, default=30.0)
    rn.add_argument("--retry", type=int, default=2)
    rn.add_argument("--force", action="store_true")
    rn.set_defaults(func=cmd_renew)

    bd = sub.add_parser("bundle", help="把已签名目录打包为可分发 zip")
    bd.add_argument("dir")
    bd.add_argument("-o", "--output", required=True)
    bd.add_argument("-p", "--pubkey", default=None)
    bd.add_argument("--include-pubkey", action="store_true")
    bd.add_argument("--allow-unlisted", action="store_true")
    bd.set_defaults(func=cmd_bundle)

    up = sub.add_parser("unpack", help="解包 bundle 并校验")
    up.add_argument("bundle")
    up.add_argument("-d", "--dest", required=True)
    up.add_argument("-p", "--pubkey", default=None)
    up.add_argument("--force", action="store_true")
    up.add_argument("--no-verify", action="store_true")
    up.set_defaults(func=cmd_unpack)

    cf = sub.add_parser("config", help="显示配置路径与生效配置")
    cf.add_argument("--json", action="store_true")
    cf.set_defaults(func=cmd_config)

    sb = sub.add_parser("sbom", help="从已签名清单生成 CycloneDX SBOM")
    sb.add_argument("dir")
    sb.add_argument("-o", "--output", default="sbom.cdx.json")
    sb.set_defaults(func=cmd_sbom)

    au = sub.add_parser("audit", help="查看审计日志")
    au.add_argument("-n", "--lines", type=int, default=20)
    au.set_defaults(func=cmd_audit)

    ot = sub.add_parser("ots", help="透传 OpenTimestamps 客户端")
    ot.add_argument("ots_args", nargs=argparse.REMAINDER)
    ot.set_defaults(func=cmd_ots)

    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args._config = load_config()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
