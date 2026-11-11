#!/usr/bin/env python3
"""hashseal — 用 SHA-256 + Ed25519 证明“文件没被改过，且确实来自某人”。

子命令
------
  keygen       生成 Ed25519 密钥对（私钥保密，公钥分发）
  fingerprint  打印公钥指纹（用于电话 / 当面核对）
  hash         输出 sha256sum 兼容的校验和
  manifest     为一组文件生成 MANIFEST.sha256（可交给 sha256sum -c 校验）
  sign         为文件生成分离式签名 <file>.sig
  verify       验证文件与签名是否一致

退出码：0 = 通过，1 = 不一致 / 签名无效，2 = 用法或 IO 错误。
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unicodedata
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn

try:
    from cryptography import x509 as cx509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "缺少依赖 cryptography。安装：uv sync  或  pip install cryptography\n"
        "或改用 README.md 里“无 Python 依赖”的 openssl / gpg 做法。\n"
    )
    raise SystemExit(2)

# asn1crypto 只在时间戳相关命令里懒加载，核心校验功能不强依赖它
cms = tsp = asn1x509 = None  # type: ignore[assignment]

__version__ = "0.2.0"

FORMAT = "hashseal/1"
# 兼容改名前的签名格式，便于平滑迁移（只读，不再新签）
LEGACY_FORMATS = {"fileproof/1"}
ALLOWED_FORMATS = {FORMAT} | LEGACY_FORMATS
ALG = "ed25519"
HASH = "sha256"
CHUNK = 8 << 20  # 8 MiB
DEFAULT_PRIVATE = "hashseal_private.pem"
DEFAULT_PUBLIC = "hashseal_public.pem"


# --------------------------------------------------------------------------- #
# 基础工具
# --------------------------------------------------------------------------- #
def die(msg: str, code: int = 2) -> NoReturn:
    print(f"错误: {msg}", file=sys.stderr)
    raise SystemExit(code)


def warn(msg: str) -> None:
    print(f"警告: {msg}", file=sys.stderr)


def sha256_file(path: Path) -> tuple[str, int]:
    """返回 (sha256 十六进制, 字节数)。分块读取，大文件也不吃内存。"""
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def norm_name(name: str) -> str:
    """签名里记录的文件名：只取 basename，NFC 归一化，禁止换行（避免拼接歧义）。"""
    name = unicodedata.normalize("NFC", os.path.basename(name))
    if not name or "\n" in name or "\r" in name:
        die(f"非法的文件名: {name!r}")
    return name


def canonical_payload(
    fmt: str, alg: str, hash_name: str, size: int, name: str, digest: str
) -> bytes:
    """被签名的字节串。字段固定顺序、行分隔，避免 JSON 序列化差异带来的坑。"""
    return (
        b"\n".join(
            [
                fmt.encode(),
                f"alg: {alg}".encode(),
                f"hash: {hash_name}".encode(),
                f"size: {size}".encode(),
                f"name: {name}".encode(),
                f"digest: {digest}".encode(),
            ]
        )
        + b"\n"
    )


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# --------------------------------------------------------------------------- #
# 密钥
# --------------------------------------------------------------------------- #
def load_private(path: Path) -> ed25519.Ed25519PrivateKey:
    if not path.exists():
        die(f"找不到私钥 {path}（先运行 hashseal keygen）")
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        die(f"{path} 不是 Ed25519 私钥")
    return key


def load_public(path: Path) -> ed25519.Ed25519PublicKey:
    if not path.exists():
        die(f"找不到公钥 {path}（向发送方索取，并经可信渠道核对指纹）")
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, ed25519.Ed25519PublicKey):
        die(f"{path} 不是 Ed25519 公钥")
    return key


def public_fingerprint(key: ed25519.Ed25519PublicKey) -> str:
    """公钥指纹：SHA-256(SPKI DER) 的 base64。和 SSH 指纹习惯一致，便于口头核对。"""
    der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(der).digest()
    return "SHA256:" + b64e(digest).rstrip("=")


def cmd_keygen(args: argparse.Namespace) -> int:
    priv_path = Path(args.private)
    pub_path = Path(args.public)
    if priv_path.exists() and not args.force:
        die(f"{priv_path} 已存在；不要覆盖正在使用的私钥（确需覆盖加 --force）")
    if pub_path.exists() and not args.force:
        die(f"{pub_path} 已存在（确需覆盖加 --force）")

    key = ed25519.Ed25519PrivateKey.generate()

    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path.write_bytes(priv_pem)
    try:
        os.chmod(priv_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    except OSError:
        warn("无法修改私钥权限（Windows 上正常），请自行确认文件访问控制")
    pub_path.write_bytes(pub_pem)

    print(f"私钥: {priv_path}  (600, 严禁外传、严禁入 git)")
    print(f"公钥: {pub_path}  (可公开分发)")
    print(f"指纹: {public_fingerprint(key.public_key())}")
    print()
    print("下一步：把公钥和上面这行指纹，通过“与文件不同的可信渠道”交给对方核对。")
    return 0


def cmd_fingerprint(args: argparse.Namespace) -> int:
    print(public_fingerprint(load_public(Path(args.public))))
    return 0


# --------------------------------------------------------------------------- #
# 纯哈希（sha256sum / certutil 兼容）
# --------------------------------------------------------------------------- #
def cmd_hash(args: argparse.Namespace) -> int:
    rc = 0
    for name in args.files:
        p = Path(name)
        if not p.is_file():
            warn(f"跳过（不是普通文件）: {p}")
            rc = 2
            continue
        digest, size = sha256_file(p)
        print(f"{digest}  {p}")
        if args.verbose:
            warn(f"{p}: {size} 字节")
    return rc


def iter_files(paths: list[str]) -> list[Path]:
    out: list[Path] = []
    for name in paths:
        p = Path(name)
        if p.is_dir():
            for root, dirs, files in os.walk(p, followlinks=False):
                dirs.sort()
                for f in sorted(files):
                    out.append(Path(root) / f)
        elif p.is_file():
            out.append(p)
        else:
            warn(f"跳过（不存在）: {p}")
    return out


def cmd_manifest(args: argparse.Namespace) -> int:
    out_path = Path(args.output)
    files = iter_files(args.paths)
    if not files:
        die("没有找到任何文件")

    base = Path(args.base).resolve() if args.base else None
    lines: list[str] = []
    for p in files:
        if p.resolve() == out_path.resolve():
            continue
        shown = p
        if base is not None:
            try:
                shown = p.resolve().relative_to(base)
            except ValueError:
                warn(f"{p} 不在 {base} 下，按原路径记录")
        digest, _ = sha256_file(p)
        lines.append(f"{digest}  {shown.as_posix()}")

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"已写入 {out_path}（{len(lines)} 个文件）")
    print(f"下一步：hashseal sign {out_path}   然后 hashseal verify {out_path}")
    return 0


# --------------------------------------------------------------------------- #
# 签名 / 验证
# --------------------------------------------------------------------------- #
def sig_path_for(file_path: Path) -> Path:
    return Path(str(file_path) + ".sig")


def cmd_sign(args: argparse.Namespace) -> int:
    key = load_private(Path(args.key))
    if (args.sig or args.tsr) and len(args.files) > 1:
        die("--sig / --tsr 只能用于单文件")
    if args.tsr and not args.timestamp:
        die("--tsr 需要配合 --timestamp 使用")
    if args.tsa_ca and not args.timestamp:
        warn("--tsa-ca 只有配合 --timestamp 才有意义，已忽略")

    rc = 0
    for name in args.files:
        p = Path(name)
        if not p.is_file():
            warn(f"跳过（不是普通文件）: {p}")
            rc = 2
            continue

        digest, size = sha256_file(p)
        signed_name = norm_name(args.name) if args.name else norm_name(p.name)
        payload = canonical_payload(FORMAT, ALG, HASH, size, signed_name, digest)
        signature = key.sign(payload)

        record = {
            "format": FORMAT,
            "alg": ALG,
            "hash": HASH,
            "size": size,
            "name": signed_name,
            "digest": digest,
            "signer": args.signer or "",
            "created": now_iso(),
            "sig": b64e(signature),
        }

        sig_path = Path(args.sig) if args.sig else sig_path_for(p)
        if sig_path.exists() and not args.force:
            die(f"{sig_path} 已存在（覆盖加 --force）")
        sig_path.write_text(
            json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"已签名 {p}")
        print(f"  签名文件: {sig_path}")
        print(f"  SHA-256 : {digest}")
        print(f"  大小    : {size} 字节")
        sys.stdout.flush()

        if args.timestamp:
            try:
                tsr_path, info, _ = _stamp_file(
                    sig_path,
                    tsa=args.tsa,
                    tsa_ca=args.tsa_ca,
                    timeout=args.timeout,
                    out_path=Path(args.tsr) if args.tsr else None,
                    force=args.force,
                )
            except TimestampError as exc:
                warn(f"{p}: 签名已生成，但时间戳失败: {exc}")
                warn(f"可稍后单独重试: hashseal timestamp {sig_path}")
                rc = 1
                continue
            print(f"  时间戳  : {tsr_path}")
            print(
                f"            {info['gen_time']} 由 TSA「{info['tsa']}」见证"
                f"（证书链: {info['chain']}）"
            )
    return rc


def cmd_verify(args: argparse.Namespace) -> int:
    p = Path(args.file)
    if not p.is_file():
        die(f"文件不存在或不是普通文件: {p}")

    sig_path = Path(args.sig) if args.sig else sig_path_for(p)
    if not sig_path.is_file():
        die(f"找不到签名文件 {sig_path}")

    try:
        record = json.loads(sig_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        die(f"签名文件无法解析: {exc}")

    record_format = record.get("format")
    if record_format not in ALLOWED_FORMATS:
        die(f"不认识的签名格式: {record_format!r}（支持 {sorted(ALLOWED_FORMATS)}）")
    if record.get("alg") != ALG or record.get("hash") != HASH:
        die(f"不支持的算法组合: alg={record.get('alg')!r} hash={record.get('hash')!r}")

    pub = load_public(Path(args.pubkey))
    fp = public_fingerprint(pub)

    digest, size = sha256_file(p)
    check_name = norm_name(args.name) if args.name else norm_name(p.name)
    payload = canonical_payload(record_format, ALG, HASH, size, check_name, digest)

    try:
        pub.verify(b64d(record.get("sig", "")), payload)
        ok = True
    except (InvalidSignature, ValueError):
        ok = False

    # 签名文件里的字段只用于“差异诊断”，不参与判定：判定只依赖真实文件 + 公钥。
    rec_size = record.get("size")
    rec_name = record.get("name")
    rec_digest = record.get("digest")
    rec_signer = record.get("signer") or "(未填写)"
    rec_created = record.get("created") or "(未记录)"

    # 时间戳只对“签名文件”本身取证：签的是 .sig 的字节，证明这份签名在某时刻已存在。
    ts_info: dict | None = None
    ts_error: str | None = None
    if ok and args.tsr:
        try:
            tsr_path = Path(args.tsr)
            if not tsr_path.is_file():
                raise TimestampError(f"找不到时间戳令牌: {tsr_path}")
            ca_pem, ca_label, strict = resolve_ca(args.tsa_ca)
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

    if args.json:
        print(
            json.dumps(
                {
                    "file": str(p),
                    "ok": ok,
                    "signature_valid": ok,
                    "digest": digest,
                    "size": size,
                    "name": check_name,
                    "expected": {
                        "name": rec_name,
                        "size": rec_size,
                        "digest": rec_digest,
                        "signer": rec_signer,
                        "created": rec_created,
                    },
                    "signer_fingerprint": fp,
                    "timestamp": (
                        (ts_info or {"ok": False, "error": ts_error})
                        if args.tsr
                        else None
                    ),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0 if (ok and ts_error is None) else 1

    print(f"文件      : {p}")
    print(f"大小      : {size} 字节")
    print(f"SHA-256   : {digest}")
    print(
        f"签名记录  : 名称={rec_name} 大小={rec_size} 签名者={rec_signer} 时间={rec_created}"
    )
    print(f"公钥指纹  : {fp}")

    if ok:
        if rec_digest != digest or rec_size != size:
            warn("签名有效，但签名文件中的摘要/大小字段与实物不符（元数据被改过？）")
        print("结果      : ✅ 通过 —— 内容与签名完全一致，且签名来自该公钥对应的私钥")
        if args.tsr:
            if ts_info is not None:
                ca_note = f"信任根: {ts_info['ca']}，" if ts_info.get("ca") else ""
                print(
                    f"时间戳    : ✅ {ts_info['gen_time']} 由 TSA「{ts_info['tsa']}」见证"
                    f"（{ca_note}证书链: {ts_info['chain']}）"
                )
                print("            → 该签名在该时刻之前已经存在，事后无法抵赖")
            else:
                print(f"时间戳    : ❌ {ts_error}")
                print("            → 签名本身有效，但“某时刻已存在”的主张不成立")
                return 1
        return 0

    print("结果      : ❌ 失败 —— 文件与签名不匹配")
    diffs: list[str] = []
    if rec_size != size:
        diffs.append(f"大小不同：签名记录 {rec_size}，实际 {size}")
    if rec_digest != digest:
        diffs.append(f"SHA-256 不同：签名记录 {rec_digest}，实际 {digest}")
    if rec_name != check_name:
        diffs.append(f"名称不同：签名记录 {rec_name}，实际按 {check_name} 校验")
    for d in diffs:
        print(f"  - {d}")

    if rec_digest == digest and rec_size == size and rec_name != check_name:
        print("  → 内容一致，只是文件名不同。若确属改名，加 --name", rec_name)
    elif rec_digest == digest and rec_size == size:
        print(
            "  → 内容一致但签名不成立：可能是签名文件被替换，或公钥不是签名者本人的。"
        )
    else:
        print("  → 文件内容已被修改，或拿到的不是签名时的那一份。")
    print("  → 也可能只是公钥不对：请用可信渠道核对上面的公钥指纹。")
    if args.tsr:
        print("时间戳    : 未校验（签名已失败，时间戳无法挽救内容）")
    return 1


# --------------------------------------------------------------------------- #
# RFC 3161 可信时间戳（L3：证明"某时刻签名已存在"）
# --------------------------------------------------------------------------- #
DEFAULT_TSA = "https://freetsa.org/tsr"

# freetsa 根证书（内置，随包发布）：默认可离线核验证书链，无需手动下载。
# 来源：https://freetsa.org/files/cacert.pem
# SHA-256: 2151b61137ffa86bf664691ba67e7da0b19f98c758e3d228d5d8ebf27e044438
FREETSA_CA_SHA256 = "2151b61137ffa86bf664691ba67e7da0b19f98c758e3d228d5d8ebf27e044438"
FREETSA_CA_PEM = """-----BEGIN CERTIFICATE-----
MIIH/zCCBeegAwIBAgIJAMHphhYNqOmAMA0GCSqGSIb3DQEBDQUAMIGVMREwDwYD
VQQKEwhGcmVlIFRTQTEQMA4GA1UECxMHUm9vdCBDQTEYMBYGA1UEAxMPd3d3LmZy
ZWV0c2Eub3JnMSIwIAYJKoZIhvcNAQkBFhNidXNpbGV6YXNAZ21haWwuY29tMRIw
EAYDVQQHEwlXdWVyemJ1cmcxDzANBgNVBAgTBkJheWVybjELMAkGA1UEBhMCREUw
HhcNMTYwMzEzMDE1MjEzWhcNNDEwMzA3MDE1MjEzWjCBlTERMA8GA1UEChMIRnJl
ZSBUU0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNVBAMTD3d3dy5mcmVldHNhLm9y
ZzEiMCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTESMBAGA1UEBxMJ
V3VlcnpidXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYTAkRFMIICIjANBgkq
hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtgKODjAy8REQ2WTNqUudAnjhlCrpE6ql
mQfNppeTmVvZrH4zutn+NwTaHAGpjSGv4/WRpZ1wZ3BRZ5mPUBZyLgq0YrIfQ5Fx
0s/MRZPzc1r3lKWrMR9sAQx4mN4z11xFEO529L0dFJjPF9MD8Gpd2feWzGyptlel
b+PqT+++fOa2oY0+NaMM7l/xcNHPOaMz0/2olk0i22hbKeVhvokPCqhFhzsuhKsm
q4Of/o+t6dI7sx5h0nPMm4gGSRhfq+z6BTRgCrqQG2FOLoVFgt6iIm/BnNffUr7V
DYd3zZmIwFOj/H3DKHoGik/xK3E82YA2ZulVOFRW/zj4ApjPa5OFbpIkd0pmzxzd
EcL479hSA9dFiyVmSxPtY5ze1P+BE9bMU1PScpRzw8MHFXxyKqW13Qv7LWw4sbk3
SciB7GACbQiVGzgkvXG6y85HOuvWNvC5GLSiyP9GlPB0V68tbxz4JVTRdw/Xn/XT
FNzRBM3cq8lBOAVt/PAX5+uFcv1S9wFE8YjaBfWCP1jdBil+c4e+0tdywT2oJmYB
BF/kEt1wmGwMmHunNEuQNzh1FtJY54hbUfiWi38mASE7xMtMhfj/C4SvapiDN837
gYaPfs8x3KZxbX7C3YAsFnJinlwAUss1fdKar8Q/YVs7H/nU4c4Ixxxz4f67fcVq
M2ITKentbCMCAwEAAaOCAk4wggJKMAwGA1UdEwQFMAMBAf8wDgYDVR0PAQH/BAQD
AgHGMB0GA1UdDgQWBBT6VQ2MNGZRQ0z357OnbJWveuaklzCBygYDVR0jBIHCMIG/
gBT6VQ2MNGZRQ0z357OnbJWveuakl6GBm6SBmDCBlTERMA8GA1UEChMIRnJlZSBU
U0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNVBAMTD3d3dy5mcmVldHNhLm9yZzEi
MCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTESMBAGA1UEBxMJV3Vl
cnpidXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYTAkRFggkAwemGFg2o6YAw
MwYDVR0fBCwwKjAooCagJIYiaHR0cDovL3d3dy5mcmVldHNhLm9yZy9yb290X2Nh
LmNybDCBzwYDVR0gBIHHMIHEMIHBBgorBgEEAYHyJAEBMIGyMDMGCCsGAQUFBwIB
FidodHRwOi8vd3d3LmZyZWV0c2Eub3JnL2ZyZWV0c2FfY3BzLmh0bWwwMgYIKwYB
BQUHAgEWJmh0dHA6Ly93d3cuZnJlZXRzYS5vcmcvZnJlZXRzYV9jcHMucGRmMEcG
CCsGAQUFBwICMDsaOUZyZWVUU0EgdHJ1c3RlZCB0aW1lc3RhbXBpbmcgU29mdHdh
cmUgYXMgYSBTZXJ2aWNlIChTYWFTKTA3BggrBgEFBQcBAQQrMCkwJwYIKwYBBQUH
MAGGG2h0dHA6Ly93d3cuZnJlZXRzYS5vcmc6MjU2MDANBgkqhkiG9w0BAQ0FAAOC
AgEAaK9+v5OFYu9M6ztYC+L69sw1omdyli89lZAfpWMMh9CRmJhM6KBqM/ipwoLt
nxyxGsbCPhcQjuTvzm+ylN6VwTMmIlVyVSLKYZcdSjt/eCUN+41K7sD7GVmxZBAF
ILnBDmTGJmLkrU0KuuIpj8lI/E6Z6NnmuP2+RAQSHsfBQi6sssnXMo4HOW5gtPO7
gDrUpVXID++1P4XndkoKn7Svw5n0zS9fv1hxBcYIHPPQUze2u30bAQt0n0iIyRLz
aWuhtpAtd7ffwEbASgzB7E+NGF4tpV37e8KiA2xiGSRqT5ndu28fgpOY87gD3ArZ
DctZvvTCfHdAS5kEO3gnGGeZEVLDmfEsv8TGJa3AljVa5E40IQDsUXpQLi8G+UC4
1DWZu8EVT4rnYaCw1VX7ShOR1PNCCvjb8S8tfdudd9zhU3gEB0rxdeTy1tVbNLXW
99y90xcwr1ZIDUwM/xQ/noO8FRhm0LoPC73Ef+J4ZBdrvWwauF3zJe33d4ibxEcb
8/pz5WzFkeixYM2nsHhqHsBKw7JPouKNXRnl5IAE1eFmqDyC7G/VT7OF669xM6hb
Ut5G21JE4cNK6NNucS+fzg1JPX0+3VhsYZjj7D5uljRvQXrJ8iHgr/M6j2oLHvTA
I2MLdq2qjZFDOCXsxBxJpbmLGBx9ow6ZerlUxzws2AWv2pk=
-----END CERTIFICATE-----
"""

_HASH_CLASSES = {
    "sha1": "SHA1",
    "sha224": "SHA224",
    "sha256": "SHA256",
    "sha384": "SHA384",
    "sha512": "SHA512",
}


class TimestampError(Exception):
    """时间戳获取/校验失败。"""


def _asn1() -> tuple[object, object, object]:
    """懒加载 asn1crypto，保持核心功能零额外依赖。"""
    global cms, tsp, asn1x509
    if cms is None or tsp is None or asn1x509 is None:
        try:
            from asn1crypto import cms as _cms
            from asn1crypto import tsp as _tsp
            from asn1crypto import x509 as _x509
        except ImportError as exc:  # pragma: no cover
            raise TimestampError(
                "时间戳功能需要 asn1crypto：uv sync  或  pip install asn1crypto"
            ) from exc
        cms, tsp, asn1x509 = _cms, _tsp, _x509
    return cms, tsp, asn1x509


def _hash_obj(alg: str) -> hashes.HashAlgorithm:
    cls_name = _HASH_CLASSES.get(alg)
    if cls_name is None or not hasattr(hashes, cls_name):
        raise TimestampError(f"不支持的摘要算法: {alg}")
    return getattr(hashes, cls_name)()


def _post(url: str, body: bytes, timeout: float) -> bytes:
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/timestamp-query",
            "Accept": "application/timestamp-reply",
            "User-Agent": f"hashseal/{__version__}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        snippet = exc.read()[:300].decode("utf-8", "replace").strip()
        raise TimestampError(f"TSA 返回 HTTP {exc.code}: {snippet}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise TimestampError(f"连接 TSA 失败（{url}）: {exc}") from exc


def _build_request(digest: bytes, nonce: int) -> bytes:
    _, tsp_mod, _ = _asn1()
    req = tsp_mod.TimeStampReq(  # type: ignore[attr-defined]
        {
            "version": "v1",
            "message_imprint": tsp_mod.MessageImprint(  # type: ignore[attr-defined]
                {
                    "hash_algorithm": {"algorithm": "sha256"},
                    "hashed_message": digest,
                }
            ),
            "nonce": nonce,
            "cert_req": True,
        }
    )
    return req.dump()


def _extract_token(raw: bytes) -> tuple[object, object, bytes, bool]:
    """接受 TimeStampResp 或裸 TimeStampToken，返回 (token, TSTInfo, TSTInfo-DER, 是否完整响应)。"""
    cms_mod, tsp_mod, _ = _asn1()
    token = None
    is_response = False

    try:
        resp = tsp_mod.TimeStampResp.load(raw)  # type: ignore[attr-defined]
        status = resp["status"]["status"].native
        if status not in ("granted", "granted_with_mods"):
            raise TimestampError(f"TSA 拒绝了请求: {status}")
        if resp["time_stamp_token"].native is None:
            raise TimestampError("TSA 响应中没有时间戳令牌")
        token = resp["time_stamp_token"]
        is_response = True
    except TimestampError:
        raise
    except Exception:  # noqa: BLE001 - 任意 DER 解析失败都回退到令牌解析
        token = None

    if token is None:
        try:
            candidate = cms_mod.ContentInfo.load(raw)  # type: ignore[attr-defined]
            content_type = candidate["content_type"].native
        except Exception as exc:
            raise TimestampError(f"无法解析时间戳令牌: {exc}") from exc
        if content_type != "signed_data":
            raise TimestampError("不是 RFC 3161 时间戳响应或令牌")
        token = candidate

    try:
        if token["content_type"].native != "signed_data":
            raise TimestampError("时间戳令牌不是 CMS SignedData")
        signed_data = token["content"]
        eci = signed_data["encap_content_info"]
        eci_type = eci["content_type"].native
        tst_der = eci["content"].contents
    except TimestampError:
        raise
    except Exception as exc:
        raise TimestampError(f"令牌结构损坏: {exc}") from exc

    if eci_type != "tst_info":
        raise TimestampError(f"封装内容类型异常: {eci_type}")
    try:
        info = tsp_mod.TSTInfo.load(tst_der)  # type: ignore[attr-defined]
    except Exception as exc:
        raise TimestampError(f"TSTInfo 解析失败: {exc}") from exc
    return token, info, tst_der, is_response


def _signer_cert(signer_info: object, certs: list) -> object:
    sid = signer_info["sid"]
    if sid.name == "issuer_and_serial_number":
        serial = sid.chosen["serial_number"].native
        hits = [c for c in certs if c.serial_number == serial]
        if len(hits) == 1:
            return hits[0]
        issuer = sid.chosen["issuer"]
        for c in hits:
            if c.issuer == issuer:
                return c
    elif sid.name == "subject_key_identifier":
        kid = sid.chosen.native
        for c in certs:
            if c.key_identifier == kid:
                return c
    if len(certs) == 1:
        return certs[0]
    raise TimestampError("找不到与签名者信息匹配的证书")


def _check_ess_binding(cert: object, attrs: dict) -> None:
    """RFC 5035 / RFC 2634：令牌里声明的"签名证书哈希"必须就是这张证书。"""
    for name, default_alg in (
        ("signing_certificate", "sha1"),
        ("signing_certificate_v2", "sha256"),
    ):
        if name not in attrs:
            continue
        try:
            ess_ids = attrs[name]["certs"]
            ess = ess_ids[0]
            alg = default_alg
            if name == "signing_certificate_v2":
                alg_field = ess["hash_algorithm"]["algorithm"].native
                if alg_field:
                    alg = alg_field
            expected = ess["cert_hash"].native
        except Exception:  # noqa: BLE001 - 结构异常不作为硬失败，交由签名与证书链判定
            return
        if hashlib.new(alg, cert.dump()).digest() != expected:
            raise TimestampError("ESS 证书哈希与签名者证书不符：令牌可能被拼接过")
        return


def _verify_cms_signature(
    pubkey: object,
    signature: bytes,
    message: bytes,
    sig_alg: object,
    digest_alg: str,
) -> None:
    algo = sig_alg.signature_algo
    # 有些 TSA 用通用 rsaEncryption OID（不带摘要），此时摘要取自 signerInfo.digestAlgorithm
    try:
        hash_alg = sig_alg.hash_algo
    except ValueError:
        hash_alg = digest_alg
    hash_obj = _hash_obj(hash_alg) if hash_alg else None
    try:
        if algo == "rsassa_pkcs1v15":
            pubkey.verify(signature, message, padding.PKCS1v15(), hash_obj)  # type: ignore[union-attr]
        elif algo == "rsassa_pss":
            pss = padding.PSS(
                mgf=padding.MGF1(hash_obj),
                salt_length=getattr(padding.PSS, "AUTO", padding.PSS.DIGEST_LENGTH),
            )
            pubkey.verify(signature, message, pss, hash_obj)  # type: ignore[union-attr]
        elif algo == "ecdsa":
            pubkey.verify(signature, message, ec.ECDSA(hash_obj))  # type: ignore[union-attr]
        elif algo == "dsa":
            pubkey.verify(signature, message, hash_obj)  # type: ignore[union-attr]
        elif algo == "ed25519":
            pubkey.verify(signature, message)  # type: ignore[union-attr]
        else:
            raise TimestampError(f"不支持的时间戳签名算法: {algo}")
    except InvalidSignature as exc:
        raise TimestampError("时间戳令牌签名无效：令牌被篡改，或与证书不匹配") from exc
    except ValueError as exc:
        raise TimestampError(f"时间戳签名算法处理失败: {exc}") from exc


def _openssl_chain(
    token_der: bytes,
    data_path: Path,
    ca_pem: bytes,
    is_response: bool,
    untrusted_pem: bytes = b"",
) -> str:
    """用 openssl 校验 TSA 证书链（含 RFC 3161 的 EKU / 关键扩展检查）。"""
    exe = shutil.which("openssl")
    if not exe:
        return "unavailable（未找到 openssl）"
    with tempfile.TemporaryDirectory(prefix="hashseal-ts-") as td:
        token_file = Path(td) / "token.tsr"
        token_file.write_bytes(token_der)
        ca_file = Path(td) / "ca.pem"
        ca_file.write_bytes(ca_pem)
        chain_args = []
        if untrusted_pem:
            untrusted_file = Path(td) / "untrusted.pem"
            untrusted_file.write_bytes(untrusted_pem)
            chain_args = ["-untrusted", str(untrusted_file)]
        cmd = [
            exe,
            "ts",
            "-verify",
            "-in",
            str(token_file),
            "-data",
            str(data_path),
            "-CAfile",
            str(ca_file),
            *chain_args,
        ]
        if not is_response:
            cmd.append("-token_in")
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60, check=False
        )
    if proc.returncode == 0:
        return "ok"
    lines = [ln for ln in (proc.stderr or proc.stdout).splitlines() if ln.strip()]
    return "failed: " + (lines[-1] if lines else "openssl 校验失败")


def check_token(
    raw: bytes,
    digest: bytes,
    *,
    data_path: Path | None = None,
    ca_path: Path | None = None,
    ca_pem: bytes | None = None,
    ca_label: str = "",
    chain_required: bool = True,
) -> dict:
    """校验时间戳令牌并返回可展示的信息；失败抛 TimestampError。"""
    token, info, tst_der, is_response = _extract_token(raw)
    signed_data = token["content"]

    # 1) 令牌绑定的确实是我们关心的这份摘要
    imprint = info["message_imprint"]
    imprint_alg = imprint["hash_algorithm"]["algorithm"].native
    if imprint_alg != "sha256":
        raise TimestampError(f"messageImprint 使用 {imprint_alg}，期望 sha256")
    if imprint["hashed_message"].native != digest:
        raise TimestampError(
            "messageImprint 与给定文件摘要不一致：令牌不是给这份内容的"
        )

    # 2) 令牌自身的 CMS 签名
    signers = signed_data["signer_infos"]
    if not signers.native:
        raise TimestampError("令牌没有签名者信息")
    signer = signers[0]
    if signer["signed_attrs"].native is None:
        raise TimestampError("令牌缺少 signedAttrs，不符合 RFC 3161")

    attrs = {a["type"].native: a["values"][0] for a in signer["signed_attrs"]}
    if "message_digest" not in attrs:
        raise TimestampError("令牌缺少 message_digest 属性")
    digest_alg = signer["digest_algorithm"]["algorithm"].native
    try:
        expected_digest = hashlib.new(digest_alg, tst_der).digest()
    except ValueError as exc:
        raise TimestampError(f"不支持的摘要算法: {digest_alg}") from exc
    if attrs["message_digest"].native != expected_digest:
        raise TimestampError("message_digest 与 TSTInfo 不符：令牌内容被改过")

    certs = []
    if signed_data["certificates"].native is not None:
        certs = [
            asn1x509.Certificate.load(c.chosen.dump())
            for c in signed_data["certificates"]
        ]
    cert = _signer_cert(signer, certs)
    _check_ess_binding(cert, attrs)

    gen_time = info["gen_time"].native
    if not (cert.not_valid_before <= gen_time <= cert.not_valid_after):
        raise TimestampError(f"签发时点 {gen_time} 不在 TSA 证书有效期内")

    eku = cert.extended_key_usage_value
    if eku is None or "time_stamping" not in eku.native:
        raise TimestampError("签名者证书缺少 timeStamping 用途，不是合法 TSA 证书")

    signed_attrs_der = signer["signed_attrs"].dump()
    if signed_attrs_der[0] == 0xA0:  # context-specific [0] 重新打回 SET OF 标签
        signed_attrs_der = b"\x31" + signed_attrs_der[1:]

    pubkey = cx509.load_der_x509_certificate(cert.dump()).public_key()
    _verify_cms_signature(
        pubkey,
        signer["signature"].native,
        signed_attrs_der,
        signer["signature_algorithm"],
        digest_alg,
    )

    # 3) 证书链（需要 openssl + 信任根）
    if ca_pem is None and ca_path is not None:
        if not ca_path.is_file():
            raise TimestampError(f"找不到 CA 文件: {ca_path}")
        ca_pem = ca_path.read_bytes()
    chain = "skipped（未提供信任根，只做了令牌绑定与签名校验）"
    if ca_pem is not None:
        if data_path is None:
            raise TimestampError("校验证书链需要原始数据文件")
        untrusted = b"".join(
            cx509.load_der_x509_certificate(c.dump()).public_bytes(
                serialization.Encoding.PEM
            )
            for c in certs
            if c.dump() != cert.dump()
        )
        status = _openssl_chain(raw, data_path, ca_pem, is_response, untrusted)
        if status == "ok":
            chain = "ok"
        elif chain_required:
            raise TimestampError(f"TSA 证书链校验未通过: {status}")
        else:
            chain = f"skipped（{status}；用 --tsa-ca 指定信任根可强制校验）"

    subject = cert.subject.native
    tsa_name = (
        subject.get("common_name")
        or subject.get("organization_name")
        or cert.subject.human_friendly
    )

    return {
        "ok": True,
        "gen_time": gen_time.isoformat(),
        "tsa": tsa_name,
        "tsa_subject": cert.subject.human_friendly,
        "serial": str(info["serial_number"].native),
        "policy": info["policy"].native,
        "digest_alg": digest_alg,
        "sig_alg": signer["signature_algorithm"].signature_algo,
        "nonce": info["nonce"].native,
        "signer_cert_sha256": hashlib.sha256(cert.dump()).hexdigest(),
        "ca": ca_label,
        "chain": chain,
    }


SYSTEM_CA_CANDIDATES = (
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
    "/etc/ssl/ca-bundle.pem",
)


def _system_ca_pem() -> bytes:
    """读取系统 CA 库（Linux/macOS 常见路径）；读不到返回空。"""
    for path in SYSTEM_CA_CANDIDATES:
        try:
            data = Path(path).read_bytes()
        except OSError:
            continue
        if data:
            return data
    return b""


def resolve_ca(
    explicit: str | None, *, tsa: str | None = None
) -> tuple[bytes | None, str, bool]:
    """选择 TSA 信任根，返回 (PEM, 标签, 是否严格)。

    优先级：--tsa-ca > 环境变量 HASHSEAL_TSA_CA > 内置 freetsa 根。
    使用非默认 TSA 且未指定根证书时，返回 None（跳过链校验）。
    """

    def _read(path_str: str) -> tuple[bytes, str, bool]:
        p = Path(path_str)
        if not p.is_file():
            die(f"找不到 CA 文件: {p}")
        return p.read_bytes(), str(p), True

    if explicit:
        return _read(explicit)
    env = os.environ.get("HASHSEAL_TSA_CA")
    if env:
        return _read(env)
    system_pem = _system_ca_pem()
    if tsa is not None and tsa != DEFAULT_TSA:
        if system_pem:
            return system_pem, "系统 CA 库", False
        return None, "", False
    pem = FREETSA_CA_PEM.encode("ascii")
    if system_pem:
        return pem + b"\n" + system_pem, "内置 freetsa 根 + 系统 CA 库", False
    return pem, "内置 freetsa 根证书", False


def _print_token_info(info: dict) -> None:
    print(f"时间          : {info['gen_time']}")
    print(f"TSA           : {info['tsa']}")
    print(f"序列号        : {info['serial']}")
    print(f"策略          : {info['policy']}")
    print(f"令牌签名      : {info['digest_alg']} / {info['sig_alg']}")
    print(f"TSA 证书 SHA256: {info['signer_cert_sha256']}")
    if info.get("ca"):
        print(f"信任根        : {info['ca']}")
    print(f"证书链        : {info['chain']}")


def _stamp_file(
    data_path: Path,
    *,
    tsa: str,
    tsa_ca: str | None,
    timeout: float,
    out_path: Path | None = None,
    force: bool = False,
    digest_hex: str | None = None,
) -> tuple[Path, dict, str]:
    """为文件申请 RFC 3161 时间戳并落盘；失败抛 TimestampError。"""
    if digest_hex is None:
        digest_hex, _ = sha256_file(data_path)
    digest = bytes.fromhex(digest_hex)
    nonce = int.from_bytes(os.urandom(8), "big")

    ca_pem, ca_label, strict = resolve_ca(tsa_ca, tsa=tsa)

    raw = _post(tsa, _build_request(digest, nonce), timeout)
    info = check_token(
        raw,
        digest,
        data_path=data_path,
        ca_pem=ca_pem,
        ca_label=ca_label,
        chain_required=strict,
    )

    if info["nonce"] is not None and info["nonce"] != nonce:
        warn(f"TSA 回显 nonce={info['nonce']} 与请求 nonce={nonce} 不一致")

    out = out_path if out_path else Path(str(data_path) + ".tsr")
    if out.exists() and not force:
        raise TimestampError(f"{out} 已存在（覆盖加 --force）")
    try:
        out.write_bytes(raw)
    except OSError as exc:
        raise TimestampError(f"无法写入 {out}: {exc}") from exc
    return out, info, digest_hex


def cmd_timestamp(args: argparse.Namespace) -> int:
    p = Path(args.file)
    if not p.is_file():
        die(f"文件不存在或不是普通文件: {p}")
    digest_hex, size = sha256_file(p)

    try:
        out, info, _ = _stamp_file(
            p,
            tsa=args.tsa,
            tsa_ca=args.tsa_ca,
            timeout=args.timeout,
            out_path=Path(args.out) if args.out else None,
            force=args.force,
            digest_hex=digest_hex,
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
    print("提示：把 .tsr 与文件/签名一起分发；验证用 check-timestamp。")
    return 0


def cmd_check_timestamp(args: argparse.Namespace) -> int:
    p = Path(args.file)
    if not p.is_file():
        die(f"文件不存在或不是普通文件: {p}")
    token_path = Path(args.tsr)
    if not token_path.is_file():
        die(f"找不到时间戳令牌: {token_path}")

    digest_hex, size = sha256_file(p)
    digest = bytes.fromhex(digest_hex)

    ca_pem, ca_label, strict = resolve_ca(args.tsa_ca)

    try:
        info = check_token(
            token_path.read_bytes(),
            digest,
            data_path=p,
            ca_pem=ca_pem,
            ca_label=ca_label,
            chain_required=strict,
        )
    except TimestampError as exc:
        if args.json:
            print(
                json.dumps(
                    {
                        "file": str(p),
                        "token": str(token_path),
                        "ok": False,
                        "error": str(exc),
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
        else:
            print(f"文件    : {p}")
            print(f"SHA-256 : {digest_hex}")
            print(f"结果    : ❌ {exc}")
        return 1

    if args.json:
        print(
            json.dumps(
                {"file": str(p), "size": size, "token": str(token_path), **info},
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        print(f"文件    : {p}")
        print(f"大小    : {size} 字节")
        print(f"SHA-256 : {digest_hex}")
        print("结果    : ✅ 令牌有效，且确实对应这份内容")
        _print_token_info(info)
    return 0


def cmd_ots(args: argparse.Namespace) -> int:
    """透传 OpenTimestamps 客户端（去中心化时间戳，需 uv sync --extra ots）。"""
    exe = shutil.which("ots")
    if not exe:
        die(
            "未安装 ots。执行：uv sync --extra ots  或  pip install opentimestamps-client"
        )
    if not args.ots_args:
        die("用法：hashseal ots stamp|verify|upgrade FILE ...")
    proc = subprocess.run([exe, *args.ots_args], check=False)
    return proc.returncode


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="hashseal",
        description="SHA-256 + Ed25519 文件一致性 / 来源校验工具",
    )
    ap.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {__version__}"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    kg = sub.add_parser("keygen", help="生成密钥对（只做一次）")
    kg.add_argument("--private", default=DEFAULT_PRIVATE)
    kg.add_argument("--public", default=DEFAULT_PUBLIC)
    kg.add_argument("--force", action="store_true")
    kg.set_defaults(func=cmd_keygen)

    fp = sub.add_parser("fingerprint", help="打印公钥指纹，供电话/当面核对")
    fp.add_argument("public", nargs="?", default=DEFAULT_PUBLIC)
    fp.set_defaults(func=cmd_fingerprint)

    h = sub.add_parser("hash", help="输出 sha256sum 兼容的校验和")
    h.add_argument("files", nargs="+")
    h.add_argument("-v", "--verbose", action="store_true")
    h.set_defaults(func=cmd_hash)

    mf = sub.add_parser("manifest", help="为一组文件生成 MANIFEST.sha256")
    mf.add_argument("paths", nargs="+")
    mf.add_argument("-o", "--output", default="MANIFEST.sha256")
    mf.add_argument("--base", help="记录相对路径的基准目录")
    mf.set_defaults(func=cmd_manifest)

    sg = sub.add_parser("sign", help="为文件生成 .sig 分离签名")
    sg.add_argument("files", nargs="+")
    sg.add_argument("-k", "--key", default=DEFAULT_PRIVATE)
    sg.add_argument("--sig", help="签名输出路径（仅单文件）")
    sg.add_argument("--signer", default="", help="署名信息，仅记录用途")
    sg.add_argument("--name", help="签名时记录的文件名（默认取实际文件名）")
    sg.add_argument(
        "--timestamp", action="store_true", help="签名后立即申请 RFC 3161 时间戳"
    )
    sg.add_argument(
        "--tsa",
        default=os.environ.get("HASHSEAL_TSA") or DEFAULT_TSA,
        help=f"配合 --timestamp 使用的 TSA（默认 {DEFAULT_TSA}）",
    )
    sg.add_argument("--tsa-ca", help="配合 --timestamp 覆盖信任根（PEM）")
    sg.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="配合 --timestamp 的网络超时秒数",
    )
    sg.add_argument("--tsr", help="时间戳输出路径（仅单文件，且需 --timestamp）")
    sg.add_argument("--force", action="store_true", help="覆盖已存在的 .sig / .tsr")
    sg.set_defaults(func=cmd_sign)

    vf = sub.add_parser("verify", help="验证文件与 .sig 是否一致")
    vf.add_argument("file")
    vf.add_argument("--sig")
    vf.add_argument("-p", "--pubkey", default=DEFAULT_PUBLIC)
    vf.add_argument("--name", help="文件被改名时，指定签名时记录的原文件名")
    vf.add_argument("--tsr", help="同时校验对 .sig 的 RFC 3161 时间戳令牌")
    vf.add_argument("--tsa-ca", help="覆盖内置信任根（PEM）；自定义 TSA 时建议显式给出")
    vf.add_argument("--json", action="store_true", help="输出机器可读结果")
    vf.set_defaults(func=cmd_verify)

    ts = sub.add_parser("timestamp", help="向 TSA 申请 RFC 3161 可信时间戳")
    ts.add_argument("file")
    ts.add_argument("-o", "--out", help="令牌输出路径（默认 <file>.tsr）")
    ts.add_argument(
        "--tsa",
        default=os.environ.get("HASHSEAL_TSA") or DEFAULT_TSA,
        help=f"TSA 地址（默认 {DEFAULT_TSA}，可用 HASHSEAL_TSA 覆盖）"
    )
    ts.add_argument("--tsa-ca", help="TSA 信任根 PEM；给出则立即校验证书链")
    ts.add_argument("--timeout", type=float, default=30.0, help="网络超时秒数")
    ts.add_argument("--force", action="store_true")
    ts.add_argument("--json", action="store_true")
    ts.set_defaults(func=cmd_timestamp)

    ct = sub.add_parser("check-timestamp", help="校验时间戳令牌与文件是否对应")
    ct.add_argument("file")
    ct.add_argument("--tsr", required=True, help="时间戳令牌（.tsr）")
    ct.add_argument("--tsa-ca", help="覆盖内置信任根（PEM）；自定义 TSA 时建议显式给出")
    ct.add_argument("--json", action="store_true")
    ct.set_defaults(func=cmd_check_timestamp)

    ot = sub.add_parser("ots", help="透传 OpenTimestamps 客户端（uv sync --extra ots）")
    ot.add_argument("ots_args", nargs=argparse.REMAINDER)
    ot.set_defaults(func=cmd_ots)

    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        raise SystemExit(0)
