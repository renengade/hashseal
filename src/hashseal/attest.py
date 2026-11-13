"""in-toto Statement + DSSE envelope support."""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from . import __version__
from .core import (
    MANIFEST_NAME,
    b64d,
    b64e,
    parse_record,
    public_fingerprint,
    sha256_file,
)
from .manifest import parse_manifest

DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
DEFAULT_PREDICATE = "https://hashseal.dev/attestation/v1"


class AttestError(Exception):
    """Attestation creation or verification failed."""


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding."""
    type_bytes = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(type_bytes)).encode("ascii")
        + b" "
        + type_bytes
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


def build_statement(root: Path, *, predicate_type: str = DEFAULT_PREDICATE) -> dict:
    manifest = root / MANIFEST_NAME
    sig = Path(str(manifest) + ".sig")
    if not manifest.is_file() or not sig.is_file():
        raise AttestError(f"{root} 尚未签名（先执行 hashseal sign {root}）")
    entries = parse_manifest(manifest)
    record = parse_record(sig)
    tsr = Path(str(sig) + ".tsr")
    predicate = {
        "tool": {"name": "hashseal", "version": __version__},
        "manifest": {
            "name": MANIFEST_NAME,
            "sha256": sha256_file(manifest)[0],
            "signature_format": record.get("format"),
            "signer": record.get("signer") or None,
        },
        "timestamp": {
            "present": tsr.is_file(),
            "sha256": sha256_file(tsr)[0] if tsr.is_file() else None,
        },
    }
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": rel, "digest": {"sha256": digest}} for digest, rel in entries],
        "predicateType": predicate_type,
        "predicate": predicate,
    }


def sign_statement(statement: dict, private_key: ed25519.Ed25519PrivateKey) -> dict:
    payload = json.dumps(
        statement, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    signature = private_key.sign(pae(DSSE_PAYLOAD_TYPE, payload))
    return {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": b64e(payload),
        "signatures": [
            {
                "keyid": public_fingerprint(private_key.public_key()),
                "sig": b64e(signature),
            }
        ],
    }


def verify_envelope(envelope: dict, public_key: ed25519.Ed25519PublicKey) -> dict:
    if envelope.get("payloadType") != DSSE_PAYLOAD_TYPE:
        raise AttestError(f"不支持的 payloadType: {envelope.get('payloadType')!r}")
    payload_text = envelope.get("payload")
    signatures = envelope.get("signatures") or []
    if not payload_text or not signatures:
        raise AttestError("DSSE envelope 缺少 payload 或签名")
    try:
        payload = b64d(payload_text)
        signature = b64d(signatures[0].get("sig", ""))
        public_key.verify(signature, pae(DSSE_PAYLOAD_TYPE, payload))
        statement = json.loads(payload)
    except (InvalidSignature, ValueError, KeyError) as exc:
        raise AttestError("证明签名无效或内容被篡改") from exc
    if statement.get("_type") != STATEMENT_TYPE:
        raise AttestError(f"不支持的 Statement 类型: {statement.get('_type')!r}")
    return statement
