"""hashseal core: constants, hashing, keys and signature records."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import sys
import tempfile
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

FORMAT = "hashseal/2"
LEGACY_FORMATS = {"hashseal/1", "fileproof/1"}
ALLOWED_FORMATS = {FORMAT} | LEGACY_FORMATS
ALG = "ed25519"
HASH = "sha256"
CHUNK = 8 << 20  # 8 MiB

MANIFEST_NAME = "MANIFEST.sha256"
DEFAULT_PRIVATE = "hashseal_private.pem"
DEFAULT_PUBLIC = "hashseal_public.pem"
DEFAULT_TSA = "https://timestamp.digicert.com"

# 目录遍历时永远跳过的缓存目录与签名产物
SKIP_DIRS = {
    ".git",
    ".venv",
    "__pycache__",
    ".ruff_cache",
    ".mypy_cache",
    "node_modules",
}
SKIP_SUFFIXES = {".sig", ".tsr", ".ots"}

# 默认排除的敏感文件（可用 --exclude 追加）
DEFAULT_EXCLUDES = (
    "*_private.pem",
    "hashseal_private.pem",
    ".env",
    ".env.*",
    "id_rsa",
    "id_ed25519",
)


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


def validate_signer(signer: str) -> str:
    if "\n" in signer or "\r" in signer:
        die("--signer 不能包含换行符")
    return signer


def canonical_payload(
    fmt: str,
    alg: str,
    hash_name: str,
    size: int,
    name: str,
    digest: str,
    signer: str = "",
) -> bytes:
    """被签名的字节串。字段固定顺序、行分隔，避免 JSON 序列化差异带来的坑。

    v2（hashseal/2）把 signer 纳入签名，避免署名被随意篡改；
    v1 / fileproof/1 保持原格式以便校验历史签名。
    """
    fields = [
        fmt,
        f"alg: {alg}",
        f"hash: {hash_name}",
        f"size: {size}",
        f"name: {name}",
        f"digest: {digest}",
    ]
    if fmt == FORMAT:
        fields.append(f"signer: {signer}")
    return ("\n".join(fields) + "\n").encode("utf-8")


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def atomic_write_bytes(path: Path, data: bytes, mode: int | None = None) -> None:
    """原子写入：同目录临时文件 + fsync + os.replace，避免半写文件。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def atomic_write_text(path: Path, text: str, mode: int | None = None) -> None:
    atomic_write_bytes(path, text.encode("utf-8"), mode)


# --------------------------------------------------------------------------- #
# 密钥
# --------------------------------------------------------------------------- #
def _password_bytes(password: str | None) -> bytes | None:
    return password.encode("utf-8") if password else None


def generate_keypair(
    private_path: Path, public_path: Path, password: str | None = None
) -> ed25519.Ed25519PrivateKey:
    key = ed25519.Ed25519PrivateKey.generate()
    encryption = (
        serialization.BestAvailableEncryption(_password_bytes(password))
        if password
        else serialization.NoEncryption()
    )
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption,
    )
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    atomic_write_bytes(private_path, priv_pem, mode=stat.S_IRUSR | stat.S_IWUSR)
    atomic_write_bytes(public_path, pub_pem)
    return key


def is_encrypted_key(path: Path) -> bool:
    """通过 PEM 头判断私钥是否加密，避免无谓的口令提示。"""
    try:
        return b"ENCRYPTED PRIVATE KEY" in path.read_bytes()
    except OSError:
        return False


def load_private(path: Path, password: str | None = None) -> ed25519.Ed25519PrivateKey:
    if path.is_dir():
        die(f"需要的是私钥文件，但给的是目录: {path}")
    if not path.exists():
        die(f"找不到私钥 {path}（先运行 hashseal keygen）")
    try:
        key = serialization.load_pem_private_key(
            path.read_bytes(), password=_password_bytes(password)
        )
    except TypeError:
        if password:
            # 给了口令但私钥其实未加密：按未加密方式重试
            return load_private(path, None)
        die("私钥已加密，需要口令。请用 --password-file 或环境变量 HASHSEAL_KEY_PASSWORD")
    except ValueError as exc:
        die(f"无法解密私钥（口令错误或文件损坏）: {exc}")
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        die(f"{path} 不是 Ed25519 私钥")
    return key


def load_public(path: Path) -> ed25519.Ed25519PublicKey:
    if path.is_dir():
        die(f"需要的是公钥文件，但给的是目录: {path}")
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
    return "SHA256:" + b64e(hashlib.sha256(der).digest()).rstrip("=")


def normalize_fingerprint(text: str) -> str:
    value = text.strip()
    if value.upper().startswith("SHA256:"):
        value = value[7:]
    return value.strip().rstrip("=")


def fingerprint_matches(expected: str, key: ed25519.Ed25519PublicKey) -> bool:
    return normalize_fingerprint(expected) == normalize_fingerprint(
        public_fingerprint(key)
    )


# --------------------------------------------------------------------------- #
# 签名记录
# --------------------------------------------------------------------------- #
def sig_path_for(file_path: Path) -> Path:
    return Path(str(file_path) + ".sig")


def build_record(
    private_key: ed25519.Ed25519PrivateKey,
    data_path: Path,
    *,
    signer: str = "",
    signed_name: str | None = None,
) -> dict:
    digest, size = sha256_file(data_path)
    name = norm_name(signed_name) if signed_name else norm_name(data_path.name)
    signer = validate_signer(signer)
    payload = canonical_payload(FORMAT, ALG, HASH, size, name, digest, signer)
    return {
        "format": FORMAT,
        "alg": ALG,
        "hash": HASH,
        "size": size,
        "name": name,
        "digest": digest,
        "signer": signer,
        "created": now_iso(),
        "sig": b64e(private_key.sign(payload)),
    }


def parse_record(sig_path: Path) -> dict:
    try:
        record = json.loads(sig_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        die(f"签名文件无法解析: {exc}")
    fmt = record.get("format")
    if fmt not in ALLOWED_FORMATS:
        die(f"不认识的签名格式: {fmt!r}（支持 {sorted(ALLOWED_FORMATS)}）")
    if record.get("alg") != ALG or record.get("hash") != HASH:
        die(f"不支持的算法组合: alg={record.get('alg')!r} hash={record.get('hash')!r}")
    return record


def verify_record(
    record: dict,
    data_path: Path,
    public_key: ed25519.Ed25519PublicKey,
    *,
    name: str | None = None,
) -> dict:
    fmt = record["format"]
    signer = record.get("signer") or ""
    check_name = norm_name(name) if name else norm_name(data_path.name)
    digest, size = sha256_file(data_path)
    payload = canonical_payload(fmt, ALG, HASH, size, check_name, digest, signer)
    try:
        public_key.verify(b64d(record.get("sig", "")), payload)
        ok = True
    except (InvalidSignature, ValueError):
        ok = False

    return {
        "ok": ok,
        "format": fmt,
        "signer_signed": fmt == FORMAT,
        "digest": digest,
        "size": size,
        "name": check_name,
        "expected": {
            "name": record.get("name"),
            "size": record.get("size"),
            "digest": record.get("digest"),
            "signer": signer,
            "created": record.get("created"),
        },
    }
