"""RFC 3161 timestamp support: request, parse, verify, chain validation."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from cryptography import x509 as cx509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

from . import __version__
from .core import (
    MANIFEST_NAME,
    atomic_write_bytes,
    die,
    fmt_time,
    sha256_file,
    warn,
)
from .manifest import find_manifest

# asn1crypto 懒加载，核心签名/校验不强依赖它
cms = tsp = asn1x509 = None  # type: ignore[assignment]

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


def _post(url: str, body: bytes, timeout: float, retries: int = 2) -> bytes:
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
    last: Exception | None = None
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            snippet = exc.read()[:300].decode("utf-8", "replace").strip()
            if exc.code < 500 or attempt >= retries:
                raise TimestampError(f"TSA 返回 HTTP {exc.code}: {snippet}") from exc
            last = exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = exc
            if attempt >= retries:
                break
        time.sleep(min(2 ** attempt, 5))
    raise TimestampError(f"连接 TSA 失败（{url}）: {last}") from last


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
    if digest_alg not in {"sha256", "sha384", "sha512"}:
        raise TimestampError(f"拒绝弱摘要算法: {digest_alg}（要求 sha256 及以上）")
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


def resolve_ca(explicit: str | None) -> tuple[bytes | None, str, bool]:
    """选择 TSA 信任根，返回 (PEM, 标签, 是否严格)。

    优先级：--tsa-ca > 环境变量 HASHSEAL_TSA_CA > 内置 freetsa 根 + 系统 CA 库。
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
    pem = FREETSA_CA_PEM.encode("ascii")
    if system_pem:
        return pem + b"\n" + system_pem, "内置 freetsa 根 + 系统 CA 库", False
    return pem, "内置 freetsa 根证书", False


def _print_token_info(info: dict) -> None:
    print(f"时间          : {fmt_time(info['gen_time'])}")
    print(f"TSA           : {info['tsa']}")
    if info.get("tsa_url"):
        print(f"TSA 地址      : {info['tsa_url']}")
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
    tsa: str | list[str],
    tsa_ca: str | None,
    timeout: float,
    out_path: Path | None = None,
    force: bool = False,
    digest_hex: str | None = None,
    retries: int = 2,
) -> tuple[Path, dict, str]:
    """为文件申请 RFC 3161 时间戳并落盘；失败抛 TimestampError。"""
    if digest_hex is None:
        digest_hex, _ = sha256_file(data_path)
    digest = bytes.fromhex(digest_hex)
    nonce = int.from_bytes(os.urandom(8), "big")

    ca_pem, ca_label, strict = resolve_ca(tsa_ca)
    endpoints = [tsa] if isinstance(tsa, str) else list(tsa)
    if not endpoints:
        raise TimestampError("没有可用的 TSA 地址")
    body = _build_request(digest, nonce)

    errors: list[str] = []
    info: dict | None = None
    for index, endpoint in enumerate(endpoints):
        try:
            raw = _post(endpoint, body, timeout, retries=retries)
            info = check_token(
                raw,
                digest,
                data_path=data_path,
                ca_pem=ca_pem,
                ca_label=ca_label,
                chain_required=strict,
            )
            info["tsa_url"] = endpoint
            break
        except TimestampError as exc:
            errors.append(f"{endpoint}: {exc}")
            if index < len(endpoints) - 1:
                warn(f"TSA {endpoint} 失败，切换到 {endpoints[index + 1]}")
    if info is None:
        raise TimestampError("所有 TSA 均失败：" + "；".join(errors))

    if info["nonce"] is not None and info["nonce"] != nonce:
        warn(f"TSA 回显 nonce={info['nonce']} 与请求 nonce={nonce} 不一致")

    out = out_path if out_path else Path(str(data_path) + ".tsr")
    if out.is_dir():
        raise TimestampError(f"令牌输出路径是目录，需要文件路径: {out}")
    if out.exists() and not force:
        raise TimestampError(f"{out} 已存在（覆盖加 --force）")
    try:
        atomic_write_bytes(out, raw)
    except OSError as exc:
        raise TimestampError(f"无法写入 {out}: {exc}") from exc
    return out, info, digest_hex


def _dir_timestamp_target(root: Path) -> tuple[Path, str]:
    """目录的时间戳对象：优先清单签名，其次清单本身。"""
    found = find_manifest(root)
    if found is None:
        die(f"{root} 里没有 {MANIFEST_NAME}，请先执行: hashseal sign {root}")
    manifest, _meta_dir = found
    sig = Path(str(manifest) + ".sig")
    if sig.is_file():
        return sig, "清单签名"
    warn("目录清单尚未签名；本次只证明清单在该时刻已存在，建议先 hashseal sign")
    return manifest, "清单"

def token_metadata(raw: bytes) -> dict:
    """只解析令牌元数据，不做密码学验证（用于 inspect）。"""
    token, info, _tst_der, is_response = _extract_token(raw)
    signed_data = token["content"]
    certs: list = []
    if signed_data["certificates"].native is not None:
        certs = [asn1x509.Certificate.load(c.chosen.dump()) for c in signed_data["certificates"]]
    signer = signed_data["signer_infos"][0]
    cert = _signer_cert(signer, certs)
    subject = cert.subject.native
    return {
        "token_format": "TimeStampResp" if is_response else "TimeStampToken",
        "gen_time": info["gen_time"].native.isoformat(),
        "tsa": subject.get("common_name")
        or subject.get("organization_name")
        or cert.subject.human_friendly,
        "serial": str(info["serial_number"].native),
        "policy": info["policy"].native,
        "digest_alg": signer["digest_algorithm"]["algorithm"].native,
        "sig_alg": signer["signature_algorithm"].signature_algo,
        "nonce": info["nonce"].native,
        "signer_cert_sha256": hashlib.sha256(cert.dump()).hexdigest(),
    }
