"""Regression tests for the P0/P1 hardening work."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import hashseal


class HardeningTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="hashseal-hardening-"))
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
        rc, out = self._run("sign", str(self.target), "-k", str(self.priv), "--force", *extra)
        self.assertEqual(rc, 0, out)

    def _make_dir(self) -> Path:
        d = self.tmp / "pkg"
        d.mkdir()
        (d / "a.txt").write_text("a\n", encoding="utf-8")
        return d

    # ------------------------------------------------------------------ P0
    def test_unlisted_file_is_detected(self) -> None:
        d = self._make_dir()
        self._run("sign", str(d), "-k", str(self.priv), "--force")
        (d / "extra.txt").write_text("evil\n", encoding="utf-8")
        rc, out = self._run("verify", str(d), "-p", str(self.pub))
        self.assertEqual(rc, 1, out)
        self.assertIn("未列入清单", out)

        rc, out = self._run("verify", str(d), "-p", str(self.pub), "--allow-unlisted")
        self.assertEqual(rc, 0, out)

    def test_manifest_path_traversal_is_rejected(self) -> None:
        d = self._make_dir()
        outside = self.tmp / "outside.txt"
        outside.write_text("outside\n", encoding="utf-8")
        digest = hashlib.sha256(outside.read_bytes()).hexdigest()
        (d / "MANIFEST.sha256").write_text(f"{digest}  ../outside.txt\n", encoding="utf-8")
        self._run("sign", str(d / "MANIFEST.sha256"), "-k", str(self.priv), "--force")

        rc, out = self._run("verify", str(d), "-p", str(self.pub))
        self.assertEqual(rc, 2, out)
        self.assertIn("路径逃逸", out)

    def test_v2_signer_is_signed(self) -> None:
        self._sign("--signer", "A <a@example.com>")
        sig = Path(str(self.target) + ".sig")
        record = json.loads(sig.read_text(encoding="utf-8"))
        self.assertEqual(record["format"], "hashseal/2")
        record["signer"] = "Mallory <evil@example.com>"
        sig.write_text(json.dumps(record), encoding="utf-8")

        rc, out = self._run("verify", str(self.target), "-p", str(self.pub))
        self.assertEqual(rc, 1, out)

    # ------------------------------------------------------------------ P1
    def test_key_alias_for_verify(self) -> None:
        self._sign()
        for flag in ("-k", "--key"):
            rc, out = self._run("verify", str(self.target), flag, str(self.pub))
            self.assertEqual(rc, 0, out)
        rc, out = self._run("verify", str(self.target), "-p", str(self.pub))
        self.assertEqual(rc, 0, out)

    def test_encrypted_private_key(self) -> None:
        pw_file = self.tmp / "pw.txt"
        pw_file.write_text("correct horse battery staple\n", encoding="utf-8")
        priv = self.tmp / "enc_priv.pem"
        pub = self.tmp / "enc_pub.pem"
        rc, out = self._run(
            "keygen",
            "--private",
            str(priv),
            "--public",
            str(pub),
            "--password-file",
            str(pw_file),
        )
        self.assertEqual(rc, 0, out)

        rc, out = self._run(
            "sign", str(self.target), "-k", str(priv), "--password-file", str(pw_file)
        )
        self.assertEqual(rc, 0, out)
        rc, out = self._run("verify", str(self.target), "-p", str(pub))
        self.assertEqual(rc, 0, out)

        rc, out = self._run("sign", str(self.target), "-k", str(priv), "--force")
        self.assertEqual(rc, 2, out)
        self.assertIn("口令", out)

    def test_empty_password_file_rejected(self) -> None:
        pw = self.tmp / "empty.pass"
        pw.write_text("", encoding="utf-8")
        rc, out = self._run(
            "keygen",
            "--private", str(self.tmp / "empty_priv.pem"),
            "--public", str(self.tmp / "empty_pub.pem"),
            "--password-file", str(pw),
        )
        self.assertEqual(rc, 2, out)
        self.assertIn("为空", out)

    def test_expect_fingerprint(self) -> None:
        self._sign()
        rc, out = self._run("fingerprint", str(self.pub))
        self.assertEqual(rc, 0)
        fp = out.strip().splitlines()[-1]

        rc, out = self._run(
            "verify", str(self.target), "-p", str(self.pub), "--expect-fingerprint", fp
        )
        self.assertEqual(rc, 0, out)

        rc, out = self._run(
            "verify",
            str(self.target),
            "-p",
            str(self.pub),
            "--expect-fingerprint",
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        self.assertEqual(rc, 1, out)
        self.assertIn("不一致", out)

    def test_legacy_root_manifest_still_verifies(self) -> None:
        d = self._make_dir()
        manifest = d / "MANIFEST.sha256"
        self._run("manifest", str(d), "-o", str(manifest), "--base", str(d))
        self._run("sign", str(manifest), "-k", str(self.priv), "--force")
        rc, out = self._run("verify", str(d), "-p", str(self.pub))
        self.assertEqual(rc, 0, out)

    def test_sensitive_files_are_excluded(self) -> None:
        d = self._make_dir()
        (d / "hashseal_private.pem").write_text("SECRET", encoding="utf-8")
        (d / ".env").write_text("TOKEN=1", encoding="utf-8")
        self._run("sign", str(d), "-k", str(self.priv), "--force")
        manifest = (d / ".hashseal" / "MANIFEST.sha256").read_text(encoding="utf-8")
        self.assertNotIn("private", manifest)
        self.assertNotIn(".env", manifest)
        self.assertNotIn(".hashseal", manifest)

        rc, out = self._run("verify", str(d), "-p", str(self.pub))
        self.assertEqual(rc, 0, out)

    def test_expanduser_paths(self) -> None:
        import argparse
        import os

        from hashseal.cli import _pub_path

        with mock.patch.dict(os.environ, {"HOME": str(self.tmp), "USERPROFILE": str(self.tmp)}):
            pub = self.tmp / "pub.pem"
            pub.write_bytes(self.pub.read_bytes())
            args = argparse.Namespace(pubkey="~/pub.pem")
            self.assertEqual(_pub_path(args), pub)

        self._sign()
        with mock.patch.dict(os.environ, {"HOME": str(self.tmp), "USERPROFILE": str(self.tmp)}):
            rc, out = self._run("verify", str(self.target), "-k", "~/pub.pem")
        self.assertEqual(rc, 0, out)

    def test_bundle_pubkey_no_collision(self) -> None:
        import zipfile

        d = self._make_dir()
        (d / "public.pem").write_text("payload public.pem", encoding="utf-8")
        self._run("sign", str(d), "-k", str(self.priv), "--force")
        bundle = self.tmp / "b.zip"
        rc, out = self._run(
            "bundle", str(d), "-o", str(bundle), "-k", str(self.pub)
        )
        self.assertEqual(rc, 0, out)
        names = zipfile.ZipFile(bundle).namelist()
        self.assertEqual(names.count("public.pem"), 1)
        self.assertIn(".hashseal/hashseal-public.pem", names)
        self.assertNotIn("hashseal-public.pem", names)

        rc, out = self._run("unpack", str(bundle), "-d", str(self.tmp / "out"), "-k", str(self.pub))
        self.assertEqual(rc, 0, out)
        self.assertEqual(
            (self.tmp / "out" / "public.pem").read_text(encoding="utf-8"),
            "payload public.pem",
        )

    def test_bundle_meta_in_meta_dir_and_manual_verify(self) -> None:
        import zipfile

        d = self._make_dir()
        self._run("sign", str(d), "-k", str(self.priv), "--force")
        bundle = self.tmp / "layout.zip"
        rc, out = self._run("bundle", str(d), "-o", str(bundle), "-k", str(self.pub))
        self.assertEqual(rc, 0, out)

        names = zipfile.ZipFile(bundle).namelist()
        self.assertIn(".hashseal/hashseal-bundle.json", names)
        self.assertIn(".hashseal/hashseal-public.pem", names)
        self.assertNotIn("hashseal-bundle.json", names)
        self.assertNotIn("hashseal-public.pem", names)

        manual = self.tmp / "manual"
        manual.mkdir()
        with zipfile.ZipFile(bundle) as zf:
            zf.extractall(manual)
        rc, out = self._run("verify", str(manual), "-p", str(self.pub))
        self.assertEqual(rc, 0, out)
        self.assertNotIn("未列入", out)

    def test_cli_emoji_survives_gbk_stdout(self) -> None:
        from hashseal.cli import _harden_stdio

        buf = io.BytesIO()
        stream = io.TextIOWrapper(buf, encoding="gbk", errors="strict")
        with mock.patch("sys.stdout", stream):
            _harden_stdio()
            print("✅ ok")
            stream.flush()
        self.assertIn(b"?", buf.getvalue())

    def test_sbom_default_output_next_to_dir(self) -> None:
        d = self._make_dir()
        self._run("sign", str(d), "-k", str(self.priv), "--force")
        expected = d.parent / (d.name + ".cdx.json")
        rc, out = self._run("sbom", str(d))
        self.assertEqual(rc, 0, out)
        self.assertTrue(expected.is_file(), out)
        # Windows 8.3 短路径（RUNNER~1）会被 resolve() 展开，按文件名断言即可
        self.assertIn("pkg.cdx.json", out)
        data = json.loads(expected.read_text(encoding="utf-8"))
        self.assertEqual(data["bomFormat"], "CycloneDX")

    def test_sbom_explicit_output_still_wins(self) -> None:
        d = self._make_dir()
        self._run("sign", str(d), "-k", str(self.priv), "--force")
        out_file = self.tmp / "custom.cdx.json"
        rc, out = self._run("sbom", str(d), "-o", str(out_file))
        self.assertEqual(rc, 0, out)
        self.assertTrue(out_file.is_file(), out)

    def test_unknown_file_in_meta_dir_is_unlisted(self) -> None:
        d = self._make_dir()
        self._run("sign", str(d), "-k", str(self.priv), "--force")
        (d / ".hashseal" / "evil.txt").write_text("hidden\n", encoding="utf-8")
        rc, out = self._run("verify", str(d), "-p", str(self.pub))
        self.assertEqual(rc, 1, out)
        self.assertIn(".hashseal/evil.txt", out)

    def test_unknown_sig_suffix_in_meta_dir_is_unlisted(self) -> None:
        d = self._make_dir()
        self._run("sign", str(d), "-k", str(self.priv), "--force")
        # .sig 后缀在普通目录会被跳过；.hashseal/ 下不能借此藏文件
        (d / ".hashseal" / "evil.sig").write_text("hidden\n", encoding="utf-8")
        rc, out = self._run("verify", str(d), "-p", str(self.pub))
        self.assertEqual(rc, 1, out)
        self.assertIn(".hashseal/evil.sig", out)

    def test_legacy_bundle_meta_not_unlisted(self) -> None:
        d = self._make_dir()
        self._run("sign", str(d), "-k", str(self.priv), "--force")
        (d / "hashseal-bundle.json").write_text("{}\n", encoding="utf-8")
        (d / "hashseal-public.pem").write_text(self.pub.read_text(encoding="utf-8"), encoding="utf-8")
        rc, out = self._run("verify", str(d), "-p", str(self.pub))
        self.assertEqual(rc, 0, out)

    def test_unpack_uses_embedded_key_in_meta_dir(self) -> None:
        d = self._make_dir()
        self._run("sign", str(d), "-k", str(self.priv), "--force")
        bundle = self.tmp / "embedded.zip"
        rc, out = self._run("bundle", str(d), "-o", str(bundle), "-k", str(self.pub))
        self.assertEqual(rc, 0, out)

        dest = self.tmp / "embedded-out"
        rc, out = self._run("unpack", str(bundle), "-d", str(dest), "--trust-embedded-key")
        self.assertEqual(rc, 0, out)
        self.assertTrue((dest / ".hashseal" / "hashseal-public.pem").is_file())

    def test_unpack_streams_large_file(self) -> None:
        import hashlib

        d = self.tmp / "bigdir"
        d.mkdir()
        big = d / "big.bin"
        big.write_bytes(os.urandom(3 * 1024 * 1024))
        digest = hashlib.sha256(big.read_bytes()).hexdigest()
        self._run("sign", str(d), "-k", str(self.priv), "--force")
        bundle = self.tmp / "big.zip"
        self._run("bundle", str(d), "-o", str(bundle), "-k", str(self.pub))
        rc, out = self._run("unpack", str(bundle), "-d", str(self.tmp / "out"), "-k", str(self.pub))
        self.assertEqual(rc, 0, out)
        self.assertEqual(hashlib.sha256((self.tmp / "out" / "big.bin").read_bytes()).hexdigest(), digest)

    def test_inspect_tsr_no_chain_field(self) -> None:
        token = Path(__file__).parent / "fixtures" / "app.py.sig.tsr"
        rc, out = self._run("inspect", str(token))
        self.assertEqual(rc, 0, out)
        self.assertNotIn("chain", out)

    def test_diff_and_inspect(self) -> None:
        d = self._make_dir()
        self._run("sign", str(d), "-k", str(self.priv), "--force")
        before = self.tmp / "before.sha256"
        shutil.copy2(d / ".hashseal" / "MANIFEST.sha256", before)

        (d / "a.txt").write_text("changed\n", encoding="utf-8")
        (d / "b.txt").write_text("new\n", encoding="utf-8")
        self._run("manifest", str(d), "-o", str(self.tmp / "after.sha256"), "--base", str(d))
        rc, out = self._run("diff", str(before), str(self.tmp / "after.sha256"), "--json")
        self.assertEqual(rc, 1, out)
        payload = json.loads(out)
        self.assertIn("a.txt", payload["changed"])
        self.assertIn("b.txt", payload["added"])

        rc, out = self._run("inspect", str(d / ".hashseal" / "MANIFEST.sha256.sig"))
        self.assertEqual(rc, 0, out)
        self.assertIn("hashseal/2", out)

    def test_inspect_timestamp_token(self) -> None:
        token = Path(__file__).parent / "fixtures" / "app.py.sig.tsr"
        rc, out = self._run("inspect", str(token))
        self.assertEqual(rc, 0, out)
        self.assertIn("gen_time", out)
        self.assertIn("UTC", out)


if __name__ == "__main__":
    unittest.main()
