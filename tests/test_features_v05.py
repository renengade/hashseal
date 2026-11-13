"""Tests for 0.5.0 features: config, audit, status, renew, bundle/unpack."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import hashseal
from hashseal import cli


class FeatureTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="hashseal-v05-"))
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)
        self.priv = self.tmp / "priv.pem"
        self.pub = self.tmp / "pub.pem"
        self._run("keygen", "--private", str(self.priv), "--public", str(self.pub))
        self.target = self.tmp / "a.txt"
        self.target.write_text("hello\n", encoding="utf-8")

    def _run(self, *argv: str) -> tuple[int, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            try:
                rc = hashseal.main(list(argv))
            except SystemExit as exc:
                rc = int(exc.code or 0) if isinstance(exc.code, int) else 2
        return rc, out.getvalue() + err.getvalue()

    def _sign(self, *extra: str) -> None:
        rc, out = self._run("sign", str(self.target), "-k", str(self.priv), "--force", *extra)
        self.assertEqual(rc, 0, out)

    def _dir(self) -> Path:
        d = self.tmp / "pkg"
        d.mkdir()
        (d / "x.txt").write_text("x\n", encoding="utf-8")
        (d / "y.txt").write_text("y\n", encoding="utf-8")
        return d

    # ------------------------------------------------------------- status
    def test_status_file_and_tamper(self) -> None:
        self._sign()
        rc, out = self._run("status", str(self.target), "-p", str(self.pub))
        self.assertEqual(rc, 0, out)
        self.assertIn("签名有效", out)
        self.target.write_text("tampered\n", encoding="utf-8")
        rc, out = self._run("status", str(self.target), "-p", str(self.pub))
        self.assertEqual(rc, 1, out)

    def test_status_dir_detects_extra(self) -> None:
        d = self._dir()
        self._run("sign", str(d), "-k", str(self.priv), "--force")
        rc, out = self._run("status", str(d), "-p", str(self.pub))
        self.assertEqual(rc, 0, out)
        (d / "extra.txt").write_text("evil\n", encoding="utf-8")
        rc, out = self._run("status", str(d), "-p", str(self.pub))
        self.assertEqual(rc, 1, out)
        self.assertIn("未列入清单", out)

    # ---------------------------------------------------------------- config
    def test_config_pubkey_and_command(self) -> None:
        cfg = self.tmp / "config.toml"
        cfg.write_text(f'[hashseal]\npubkey = "{self.pub}"\ntsa = "https://example.invalid"\n', encoding="utf-8")
        self._sign()
        with mock.patch.dict(os.environ, {"HASHSEAL_CONFIG": str(cfg)}):
            rc, out = self._run("verify", str(self.target))
            self.assertEqual(rc, 0, out)
            rc, out = self._run("config")
            self.assertEqual(rc, 0, out)
            self.assertIn(str(cfg), out)
            self.assertIn("example.invalid", out)

    # ----------------------------------------------------------------- audit
    def test_audit_log_written(self) -> None:
        log = self.tmp / "audit.jsonl"
        with mock.patch.dict(
            os.environ,
            {"HASHSEAL_AUDIT_LOG": str(log), "HASHSEAL_NO_AUDIT": ""},
        ):
            self._sign()
        line = json.loads(log.read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual(line["event"], "sign")
        self.assertTrue(line["ok"])

    # ----------------------------------------------------------------- renew
    def test_renew_targets_signature(self) -> None:
        self._sign()
        sig = Path(str(self.target) + ".sig")
        fake_info = {"gen_time": "2026-01-01T00:00:00+00:00", "tsa": "Fake TSA"}
        with mock.patch.object(
            cli, "_stamp_file", return_value=(Path(str(sig) + ".tsr"), fake_info, "x")
        ) as stamp:
            rc, out = self._run(
                "renew", str(self.target), "--timeout", "1"
            )
        self.assertEqual(rc, 0, out)
        self.assertEqual(stamp.call_args.args[0], sig)

    # ----------------------------------------------------------- bundle
    def test_bundle_unpack_roundtrip(self) -> None:
        d = self._dir()
        self._run("sign", str(d), "-k", str(self.priv), "--force")
        bundle = self.tmp / "pkg.zip"
        rc, out = self._run(
            "bundle", str(d), "-o", str(bundle), "-p", str(self.pub), "--include-pubkey"
        )
        self.assertEqual(rc, 0, out)
        self.assertTrue(bundle.is_file())

        dest = self.tmp / "out"
        rc, out = self._run("unpack", str(bundle), "-d", str(dest))
        self.assertEqual(rc, 0, out)
        self.assertIn("通过", out)
        self.assertTrue((dest / "x.txt").is_file())

    def test_sbom_generation(self) -> None:
        d = self._dir()
        self._run("sign", str(d), "-k", str(self.priv), "--force")
        out = self.tmp / "sbom.json"
        rc, text = self._run("sbom", str(d), "-o", str(out))
        self.assertEqual(rc, 0, text)
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(data["bomFormat"], "CycloneDX")
        self.assertEqual(len(data["components"]), 2)
        self.assertTrue(any(c["name"] == "x.txt" for c in data["components"]))

    def test_unpack_rejects_zip_slip(self) -> None:
        bad = self.tmp / "bad.zip"
        with zipfile.ZipFile(bad, "w") as zf:
            zf.writestr("hashseal-bundle.json", json.dumps({"format": "hashseal-bundle/1"}))
            zf.writestr("../evil.txt", "evil")
        rc, out = self._run("unpack", str(bad), "-d", str(self.tmp / "badout"), "--no-verify")
        self.assertEqual(rc, 2, out)
        self.assertIn("非法路径", out)


if __name__ == "__main__":
    unittest.main()
