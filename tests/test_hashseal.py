"""hashseal 的最小自测：python3 -m unittest -v test_hashseal"""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import hashseal

FIXTURES = Path(__file__).resolve().parent / "fixtures"
HAS_OPENSSL = shutil.which("openssl") is not None


class FileProofTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="hashseal-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.priv = self.tmp / "priv.pem"
        self.pub = self.tmp / "pub.pem"
        self._run("keygen", "--private", str(self.priv), "--public", str(self.pub))
        self.target = self.tmp / "app.py"
        self.target.write_text('print("hello")\n', encoding="utf-8")

    def _run(self, *argv: str) -> tuple[int, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            try:
                rc = hashseal.main(list(argv))
            except SystemExit as exc:
                rc = int(exc.code or 0)
        return rc, out.getvalue() + err.getvalue()

    def _sign(self, *extra: str) -> None:
        rc, out = self._run(
            "sign", str(self.target), "-k", str(self.priv), "--force", *extra
        )
        self.assertEqual(rc, 0, out)

    def _verify(self, *extra: str) -> tuple[int, str]:
        return self._run("verify", str(self.target), "-p", str(self.pub), *extra)

    def test_roundtrip(self) -> None:
        self._sign()
        rc, out = self._verify()
        self.assertEqual(rc, 0, out)
        self.assertIn("通过", out)

    def test_new_signature_uses_hashseal_format(self) -> None:
        self._sign()
        record = json.loads(Path(str(self.target) + ".sig").read_text(encoding="utf-8"))
        self.assertEqual(record["format"], "hashseal/2")

    def test_sign_without_timestamp_never_calls_network(self) -> None:
        with mock.patch.object(hashseal.tsa, "_post", side_effect=AssertionError("不应联网")):
            self._sign()
        self.assertTrue(Path(str(self.target) + ".sig").exists())

    def test_sign_timestamp_failure_keeps_signature(self) -> None:
        with mock.patch.object(
            hashseal.tsa, "_post", side_effect=hashseal.TimestampError("模拟断网")
        ):
            rc, out = self._run(
                "sign", str(self.target), "-k", str(self.priv), "--force",
                "--timestamp", "--timeout", "1",
            )
        self.assertEqual(rc, 1, out)
        self.assertIn("时间戳失败", out)
        self.assertTrue(Path(str(self.target) + ".sig").exists())

    def test_tsr_requires_timestamp_flag(self) -> None:
        rc, out = self._run(
            "sign", str(self.target), "-k", str(self.priv), "--tsr", "x.tsr"
        )
        self.assertEqual(rc, 2, out)
        self.assertIn("--timestamp", out)

    def test_hash_matches_hashlib(self) -> None:
        data = self.target.read_bytes()
        rc, out = self._run("hash", str(self.target))
        self.assertEqual(rc, 0)
        self.assertIn(hashlib.sha256(data).hexdigest(), out)

    def test_gen_time_shows_local_and_utc(self) -> None:
        text = hashseal._fmt_gen_time("2026-11-12T01:13:26+00:00")
        self.assertIn("UTC 2026-11-12 01:13:26", text)
        self.assertIn("2026-11-12", text)

    def test_fingerprint_directory_is_clean_error(self) -> None:
        d = self.tmp / "dir"
        d.mkdir()
        rc, out = self._run("fingerprint", str(d))
        self.assertEqual(rc, 2, out)
        self.assertIn("目录", out)
        self.assertNotIn("Traceback", out)

    def test_hash_directory_recurses_and_skips_artifacts(self) -> None:
        d = self.tmp / "hashdir"
        (d / "sub").mkdir(parents=True)
        (d / "a.txt").write_text("a\n", encoding="utf-8")
        (d / "sub" / "b.txt").write_text("b\n", encoding="utf-8")
        (d / "a.txt.sig").write_text("artifact", encoding="utf-8")
        rc, out = self._run("hash", str(d))
        self.assertEqual(rc, 0, out)
        self.assertIn("a.txt", out)
        self.assertIn("b.txt", out)
        self.assertNotIn(".sig", out)

    def test_keygen_rejects_directory_target(self) -> None:
        d = self.tmp / "keydir"
        d.mkdir()
        rc, out = self._run("keygen", "--private", str(d), "--public", str(self.pub))
        self.assertEqual(rc, 2, out)
        self.assertIn("目录", out)

    def test_sign_sig_directory_is_clean_error(self) -> None:
        d = self.tmp / "sigdir"
        d.mkdir()
        rc, out = self._run(
            "sign", str(self.target), "-k", str(self.priv), "--sig", str(d)
        )
        self.assertEqual(rc, 2, out)
        self.assertIn("--sig", out)

    def test_verify_pubkey_directory_is_clean_error(self) -> None:
        self._sign()
        d = self.tmp / "pubdir"
        d.mkdir()
        rc, out = self._run("verify", str(self.target), "-p", str(d))
        self.assertEqual(rc, 2, out)
        self.assertIn("公钥文件", out)

    def test_manifest_output_directory_is_clean_error(self) -> None:
        d = self.tmp / "outdir"
        d.mkdir()
        rc, out = self._run("manifest", str(self.tmp), "-o", str(d))
        self.assertEqual(rc, 2, out)
        self.assertIn("目录", out)

    def test_default_tsa_is_digicert(self) -> None:
        self.assertEqual(hashseal.DEFAULT_TSA, "http://timestamp.digicert.com")

    def test_directory_sign_and_verify(self) -> None:
        d = self.tmp / "pkg"
        (d / "sub").mkdir(parents=True)
        (d / "a.txt").write_text("a\n", encoding="utf-8")
        (d / "sub" / "b.txt").write_text("b\n", encoding="utf-8")

        rc, out = self._run("sign", str(d), "-k", str(self.priv), "--force")
        self.assertEqual(rc, 0, out)
        self.assertTrue((d / ".hashseal" / "MANIFEST.sha256").is_file())
        self.assertTrue((d / ".hashseal" / "MANIFEST.sha256.sig").is_file())
        self.assertNotIn(".sig", (d / ".hashseal" / "MANIFEST.sha256").read_text(encoding="utf-8"))

        rc, out = self._run("verify", str(d), "-p", str(self.pub))
        self.assertEqual(rc, 0, out)
        self.assertIn("2 个文件全部一致", out)

    def test_resign_without_force_is_noop(self) -> None:
        d = self.tmp / "pkg"
        d.mkdir()
        (d / "a.txt").write_text("v1\n", encoding="utf-8")
        self._run("sign", str(d), "-k", str(self.priv))
        manifest = d / ".hashseal" / "MANIFEST.sha256"
        sig = d / ".hashseal" / "MANIFEST.sha256.sig"
        before = (manifest.read_bytes(), sig.read_bytes())

        (d / "a.txt").write_text("v2\n", encoding="utf-8")
        rc, out = self._run("sign", str(d), "-k", str(self.priv))
        self.assertEqual(rc, 2, out)
        self.assertIn("--force", out)
        # 关键：拒绝时不能留下“清单已改、签名未改”的半更新状态
        self.assertEqual((manifest.read_bytes(), sig.read_bytes()), before)

    def test_resign_with_force_updates(self) -> None:
        d = self.tmp / "pkg"
        d.mkdir()
        (d / "a.txt").write_text("v1\n", encoding="utf-8")
        self._run("sign", str(d), "-k", str(self.priv))
        (d / "a.txt").write_text("v2\n", encoding="utf-8")
        rc, out = self._run("sign", str(d), "-k", str(self.priv), "--force")
        self.assertEqual(rc, 0, out)
        rc, out = self._run("verify", str(d), "-p", str(self.pub))
        self.assertEqual(rc, 0, out)

    def test_timestamp_dir_without_manifest_errors(self) -> None:
        d = self.tmp / "empty"
        d.mkdir()
        rc, out = self._run("timestamp", str(d), "--timeout", "1")
        self.assertEqual(rc, 2, out)
        self.assertIn("请先执行", out)

    def test_timestamp_dir_targets_manifest_sig(self) -> None:
        d = self.tmp / "pkg"
        d.mkdir()
        (d / "a.txt").write_text("a\n", encoding="utf-8")
        self._run("sign", str(d), "-k", str(self.priv))
        with mock.patch.object(
            hashseal.tsa, "_post", side_effect=hashseal.TimestampError("模拟断网")
        ):
            rc, out = self._run("timestamp", str(d), "--timeout", "1")
        self.assertEqual(rc, 2, out)
        self.assertIn("MANIFEST.sha256.sig", out)
        self.assertIn("模拟断网", out)

    def test_check_timestamp_dir_auto_detects_token(self) -> None:
        d = self.tmp / "pkg"
        d.mkdir()
        (d / "a.txt").write_text("a\n", encoding="utf-8")
        self._run("sign", str(d), "-k", str(self.priv))

        rc, out = self._run("verify", str(d), "--ts-only")
        self.assertEqual(rc, 2, out)
        self.assertIn("找不到时间戳令牌", out)

        shutil.copy2(FIXTURES / "app.py.sig.tsr", d / ".hashseal" / "MANIFEST.sha256.sig.tsr")
        rc, out = self._run("verify", str(d), "--ts-only")
        self.assertEqual(rc, 1, out)
        self.assertIn("messageImprint", out)

    def test_directory_verify_detects_tamper(self) -> None:
        d = self.tmp / "pkg"
        d.mkdir()
        (d / "a.txt").write_text("a\n", encoding="utf-8")
        self._run("sign", str(d), "-k", str(self.priv), "--force")
        (d / "a.txt").write_text("hacked\n", encoding="utf-8")
        rc, out = self._run("verify", str(d), "-p", str(self.pub))
        self.assertEqual(rc, 1, out)
        self.assertIn("内容不一致", out)

    def test_directory_verify_detects_missing_file(self) -> None:
        d = self.tmp / "pkg"
        d.mkdir()
        (d / "a.txt").write_text("a\n", encoding="utf-8")
        (d / "b.txt").write_text("b\n", encoding="utf-8")
        self._run("sign", str(d), "-k", str(self.priv), "--force")
        (d / "b.txt").unlink()
        rc, out = self._run("verify", str(d), "-p", str(self.pub))
        self.assertEqual(rc, 1, out)
        self.assertIn("文件缺失", out)

    def test_directory_sign_timestamp_failure_keeps_manifest(self) -> None:
        d = self.tmp / "pkg"
        d.mkdir()
        (d / "a.txt").write_text("a\n", encoding="utf-8")
        with mock.patch.object(
            hashseal.tsa, "_post", side_effect=hashseal.TimestampError("模拟断网")
        ):
            rc, out = self._run(
                "sign", str(d), "-k", str(self.priv), "--force",
                "--timestamp", "--timeout", "1",
            )
        self.assertEqual(rc, 1, out)
        self.assertTrue((d / ".hashseal" / "MANIFEST.sha256").is_file())
        self.assertTrue((d / ".hashseal" / "MANIFEST.sha256.sig").is_file())

    def test_directory_verify_json(self) -> None:
        d = self.tmp / "pkg"
        d.mkdir()
        (d / "a.txt").write_text("a\n", encoding="utf-8")
        self._run("sign", str(d), "-k", str(self.priv), "--force")
        rc, out = self._run("verify", str(d), "-p", str(self.pub), "--json")
        self.assertEqual(rc, 0, out)
        payload = json.loads(out)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["files"]["checked"], 1)

    def test_single_byte_change_detected(self) -> None:
        self._sign()
        self.target.write_bytes(self.target.read_bytes() + b" ")
        rc, out = self._verify()
        self.assertEqual(rc, 1, out)
        self.assertIn("SHA-256 不同", out)

    def test_same_size_change_detected(self) -> None:
        self._sign()
        self.target.write_text('print("HELLO")\n', encoding="utf-8")  # 长度相同
        rc, out = self._verify()
        self.assertEqual(rc, 1, out)

    def test_rename_detected_then_allowed(self) -> None:
        self._sign()
        moved = self.tmp / "renamed.py"
        shutil.copy2(self.target, moved)
        shutil.copy2(str(self.target) + ".sig", str(moved) + ".sig")
        rc, out = self._run("verify", str(moved), "-p", str(self.pub))
        self.assertEqual(rc, 1, out)
        self.assertIn("名称不同", out)
        rc, out = self._run(
            "verify", str(moved), "-p", str(self.pub), "--name", "app.py"
        )
        self.assertEqual(rc, 0, out)

    def test_wrong_key_rejected(self) -> None:
        self._sign()
        other_priv = self.tmp / "other_priv.pem"
        other_pub = self.tmp / "other_pub.pem"
        self._run("keygen", "--private", str(other_priv), "--public", str(other_pub))
        rc, out = self._run("verify", str(self.target), "-p", str(other_pub))
        self.assertEqual(rc, 1, out)

    def test_signature_json_tampering_does_not_break_crypto(self) -> None:
        self._sign()
        sig = Path(str(self.target) + ".sig")
        record = json.loads(sig.read_text(encoding="utf-8"))
        record["digest"] = "0" * 64
        sig.write_text(json.dumps(record), encoding="utf-8")
        rc, out = self._verify()
        self.assertEqual(rc, 0, out)
        self.assertIn("元数据", out)

    def test_missing_sig_is_usage_error(self) -> None:
        rc, _ = self._verify()
        self.assertEqual(rc, 2)

    def test_keygen_refuses_overwrite(self) -> None:
        rc, out = self._run(
            "keygen", "--private", str(self.priv), "--public", str(self.pub)
        )
        self.assertEqual(rc, 2, out)


class TimestampTest(unittest.TestCase):
    """离线验证 RFC 3161 令牌（夹具来自 freetsa，见 tests/fixtures/README.md）。"""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="hashseal-ts-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        for name in (
            "app.py",
            "app.py.sig",
            "app.py.sig.tsr",
            "public.pem",
            "freetsa_ca.pem",
        ):
            shutil.copy2(FIXTURES / name, self.tmp / name)
        self.data = self.tmp / "app.py"
        self.sig = self.tmp / "app.py.sig"
        self.tsr = self.tmp / "app.py.sig.tsr"
        self.pub = self.tmp / "public.pem"
        self.ca = self.tmp / "freetsa_ca.pem"

    def _run(self, *argv: str) -> tuple[int, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            try:
                rc = hashseal.main(list(argv))
            except SystemExit as exc:
                rc = int(exc.code or 0)
        return rc, out.getvalue() + err.getvalue()

    def test_legacy_fileproof_format_accepted(self) -> None:
        record = json.loads(self.sig.read_text(encoding="utf-8"))
        self.assertEqual(record["format"], "fileproof/1")
        rc, out = self._run("verify", str(self.data), "-p", str(self.pub))
        self.assertEqual(rc, 0, out)

    def test_builtin_ca_matches_pin(self) -> None:
        data = hashseal.FREETSA_CA_PEM.encode("ascii")
        self.assertEqual(hashlib.sha256(data).hexdigest(), hashseal.FREETSA_CA_SHA256)

    @unittest.skipUnless(HAS_OPENSSL, "需要 openssl 校验 TSA 证书链")
    def test_builtin_ca_verifies_chain(self) -> None:
        info = hashseal.check_token(
            self.tsr.read_bytes(),
            hashlib.sha256(self.sig.read_bytes()).digest(),
            data_path=self.sig,
            ca_pem=hashseal.FREETSA_CA_PEM.encode("ascii"),
            ca_label="builtin",
        )
        self.assertEqual(info["chain"], "ok")

    def test_verify_without_ca_uses_builtin_root(self) -> None:
        rc, out = self._run(
            "verify", str(self.data), "-p", str(self.pub), "--tsr", str(self.tsr)
        )
        self.assertEqual(rc, 0, out)
        self.assertIn("内置 freetsa 根", out)

    def test_token_binds_signature(self) -> None:
        info = hashseal.check_token(
            self.tsr.read_bytes(), hashlib.sha256(self.sig.read_bytes()).digest()
        )
        self.assertTrue(info["ok"])
        self.assertTrue(info["gen_time"].startswith("2026-"))

    def test_rsa_token_with_generic_rsa_encryption(self) -> None:
        """DigiCert 用 rsaEncryption 通用 OID，摘要需回退到 digestAlgorithm。"""
        token = FIXTURES / "app.py.sig.digicert.tsr"
        if not token.exists():
            self.skipTest("缺少 DigiCert 夹具")
        info = hashseal.check_token(
            token.read_bytes(), hashlib.sha256(self.sig.read_bytes()).digest()
        )
        self.assertTrue(info["ok"])
        self.assertEqual(info["sig_alg"], "rsassa_pkcs1v15")

    def test_token_rejects_other_data(self) -> None:
        with self.assertRaises(hashseal.TimestampError):
            hashseal.check_token(
                self.tsr.read_bytes(), hashlib.sha256(self.data.read_bytes()).digest()
            )

    def test_tampered_token_rejected(self) -> None:
        raw = bytearray(self.tsr.read_bytes())
        raw[len(raw) // 2] ^= 0xFF
        with self.assertRaises(hashseal.TimestampError):
            hashseal.check_token(
                bytes(raw), hashlib.sha256(self.sig.read_bytes()).digest()
            )

    def test_token_only_input_supported(self) -> None:
        from asn1crypto import tsp

        resp = tsp.TimeStampResp.load(self.tsr.read_bytes())
        token_der = resp["time_stamp_token"].dump()
        info = hashseal.check_token(
            token_der, hashlib.sha256(self.sig.read_bytes()).digest()
        )
        self.assertTrue(info["ok"])

    @unittest.skipUnless(HAS_OPENSSL, "需要 openssl 校验 TSA 证书链")
    def test_chain_ok(self) -> None:
        info = hashseal.check_token(
            self.tsr.read_bytes(),
            hashlib.sha256(self.sig.read_bytes()).digest(),
            data_path=self.sig,
            ca_path=self.ca,
        )
        self.assertEqual(info["chain"], "ok")

    @unittest.skipUnless(HAS_OPENSSL, "需要 openssl 校验 TSA 证书链")
    def test_chain_rejects_wrong_root(self) -> None:
        with self.assertRaises(hashseal.TimestampError):
            hashseal.check_token(
                self.tsr.read_bytes(),
                hashlib.sha256(self.sig.read_bytes()).digest(),
                data_path=self.sig,
                ca_path=self.pub,  # 拿公钥冒充 CA，必然失败
            )

    def test_verify_with_timestamp_cli(self) -> None:
        rc, out = self._run(
            "verify",
            str(self.data),
            "-p",
            str(self.pub),
            "--tsr",
            str(self.tsr),
            "--tsa-ca",
            str(self.ca),
        )
        self.assertEqual(rc, 0, out)
        self.assertIn("时间戳", out)
        self.assertIn("见证", out)

    def test_verify_fails_when_content_changed_even_with_timestamp(self) -> None:
        self.data.write_bytes(self.data.read_bytes() + b"# tampered\n")
        rc, out = self._run(
            "verify",
            str(self.data),
            "-p",
            str(self.pub),
            "--tsr",
            str(self.tsr),
            "--tsa-ca",
            str(self.ca),
        )
        self.assertEqual(rc, 1, out)
        self.assertIn("未校验", out)

    def test_check_timestamp_cli_ok_and_mismatch(self) -> None:
        rc, out = self._run(
            "verify",
            str(self.sig),
            "--ts-only",
            "--tsr",
            str(self.tsr),
            "--tsa-ca",
            str(self.ca),
        )
        self.assertEqual(rc, 0, out)
        self.assertIn("✅", out)

        rc, out = self._run("verify", str(self.data), "--ts-only", "--tsr", str(self.tsr))
        self.assertEqual(rc, 1, out)
        self.assertIn("messageImprint", out)

    def test_check_timestamp_json(self) -> None:
        rc, out = self._run(
            "verify", str(self.sig), "--ts-only", "--tsr", str(self.tsr), "--json"
        )
        self.assertEqual(rc, 0, out)
        payload = json.loads(out)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["tsa"], "www.freetsa.org")


if __name__ == "__main__":
    unittest.main()
