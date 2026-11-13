"""Regression tests for the P0/P1 hardening work."""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

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

    def test_sensitive_files_are_excluded(self) -> None:
        d = self._make_dir()
        (d / "hashseal_private.pem").write_text("SECRET", encoding="utf-8")
        (d / ".env").write_text("TOKEN=1", encoding="utf-8")
        self._run("sign", str(d), "-k", str(self.priv), "--force")
        manifest = (d / "MANIFEST.sha256").read_text(encoding="utf-8")
        self.assertNotIn("private", manifest)
        self.assertNotIn(".env", manifest)

        rc, out = self._run("verify", str(d), "-p", str(self.pub))
        self.assertEqual(rc, 0, out)

    def test_diff_and_inspect(self) -> None:
        d = self._make_dir()
        self._run("sign", str(d), "-k", str(self.priv), "--force")
        before = self.tmp / "before.sha256"
        shutil.copy2(d / "MANIFEST.sha256", before)

        (d / "a.txt").write_text("changed\n", encoding="utf-8")
        (d / "b.txt").write_text("new\n", encoding="utf-8")
        self._run("manifest", str(d), "-o", str(self.tmp / "after.sha256"), "--base", str(d))
        rc, out = self._run("diff", str(before), str(self.tmp / "after.sha256"), "--json")
        self.assertEqual(rc, 1, out)
        payload = json.loads(out)
        self.assertIn("a.txt", payload["changed"])
        self.assertIn("b.txt", payload["added"])

        rc, out = self._run("inspect", str(d / "MANIFEST.sha256.sig"))
        self.assertEqual(rc, 0, out)
        self.assertIn("hashseal/2", out)

    def test_inspect_timestamp_token(self) -> None:
        token = Path(__file__).parent / "fixtures" / "app.py.sig.tsr"
        rc, out = self._run("inspect", str(token))
        self.assertEqual(rc, 0, out)
        self.assertIn("gen_time", out)


if __name__ == "__main__":
    unittest.main()
