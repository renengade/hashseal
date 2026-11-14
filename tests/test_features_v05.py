"""Tests for 0.5.0 features: config, audit, status, renew, bundle/unpack."""

from __future__ import annotations

import base64
import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import hashseal
from hashseal import audit, cli, tsa


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

    def test_audit_command_formats_time(self) -> None:
        log = self.tmp / "audit-command.jsonl"
        with mock.patch.dict(os.environ, {"HASHSEAL_AUDIT_LOG": str(log)}):
            self._sign()
            rc, out = self._run("audit")
        self.assertEqual(rc, 0, out)
        self.assertIn("UTC", out)
        rc, out = self._run("audit", "--json")
        self.assertIn('"ts_local"', out)

    def test_inspect_shows_local_and_utc(self) -> None:
        self._sign()
        rc, out = self._run("inspect", str(self.target) + ".sig")
        self.assertEqual(rc, 0, out)
        self.assertIn("UTC", out)

    def test_hash_is_audited(self) -> None:
        log = self.tmp / "hash-audit.jsonl"
        with mock.patch.dict(os.environ, {"HASHSEAL_AUDIT_LOG": str(log)}):
            rc, out = self._run("hash", str(self.target))
        self.assertEqual(rc, 0, out)
        record = json.loads(log.read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual(record["event"], "hash")
        self.assertEqual(record["files"], 1)
        self.assertTrue(record["ok"])

    def test_audit_context_has_operator(self) -> None:
        with mock.patch.object(audit, "_primary_ip", return_value="198.51.100.7"):
            context = audit.audit_context()
        self.assertTrue(context["user"])
        self.assertEqual(context["ip"], "198.51.100.7")
        self.assertTrue(context["hostname"])

    def test_tsa_fallback(self) -> None:
        out = self.tmp / "fallback.tsr"
        info = {"nonce": None, "tsa": "Fake TSA", "chain": "ok"}
        with (
            mock.patch.object(tsa, "_post", side_effect=[tsa.TimestampError("boom"), b"token"]) as post,
            mock.patch.object(tsa, "check_token", return_value=info),
            mock.patch.object(tsa, "resolve_ca", return_value=(None, "", False)),
        ):
            path, result, _ = tsa._stamp_file(
                self.target,
                tsa=["http://a.invalid", "http://b.invalid"],
                tsa_ca=None,
                timeout=1,
                out_path=out,
                force=True,
            )
        self.assertEqual(path, out)
        self.assertEqual(result["tsa_url"], "http://b.invalid")
        self.assertEqual(post.call_count, 2)
        self.assertTrue(out.is_file())

    def test_tsa_all_fail(self) -> None:
        with (
            mock.patch.object(tsa, "_post", side_effect=tsa.TimestampError("down")),
            mock.patch.object(tsa, "resolve_ca", return_value=(None, "", False)),
            self.assertRaises(tsa.TimestampError),
        ):
            tsa._stamp_file(
                self.target,
                tsa=["http://a.invalid", "http://b.invalid"],
                tsa_ca=None,
                timeout=1,
                out_path=self.tmp / "x.tsr",
                force=True,
            )

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
        with (
            mock.patch.dict(os.environ, {"HASHSEAL_AUDIT_LOG": str(log)}),
            mock.patch.object(audit, "_primary_ip", return_value="203.0.113.9"),
        ):
            self._sign()
        line = json.loads(log.read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual(line["event"], "sign")
        self.assertTrue(line["ok"])
        self.assertIn("UTC", line["ts_local"])
        self.assertTrue(line["user"])
        self.assertEqual(line["ip"], "203.0.113.9")
        self.assertTrue(line["hostname"])

    def test_audit_rotation(self) -> None:
        log = self.tmp / "rot.jsonl"
        cfg = {"audit_sink": "file", "audit_file": str(log), "audit_max_bytes": 200}
        with mock.patch.dict(os.environ, {"HASHSEAL_AUDIT_LOG": str(log)}):
            for i in range(6):
                audit.write_event("test", config=cfg, n=i)
        self.assertTrue(log.is_file())
        self.assertTrue(list(log.parent.glob("rot-*.jsonl")))

    def test_audit_rotates_by_entry_date(self) -> None:
        from datetime import datetime, timedelta

        log = self.tmp / "daily.jsonl"
        yesterday = (datetime.now() - timedelta(days=1)).date().isoformat()
        log.write_text(
            '{"ts":"' + yesterday + 'T10:00:00+00:00","event":"old"}\n',
            encoding="utf-8",
        )
        cfg = {"audit_sink": "file", "audit_file": str(log)}
        with mock.patch.dict(os.environ, {"HASHSEAL_AUDIT_LOG": str(log)}):
            audit.write_event("new", config=cfg)
        self.assertTrue((self.tmp / f"daily-{yesterday}.jsonl").is_file())
        self.assertIn("new", log.read_text(encoding="utf-8"))

    def test_audit_retention_deletes_old_archive(self) -> None:
        log = self.tmp / "retain.jsonl"
        old = self.tmp / "retain-2000-01-01.jsonl"
        old.write_text("{}\n", encoding="utf-8")
        cfg = {"audit_sink": "file", "audit_file": str(log), "audit_retention_days": 90}
        with mock.patch.dict(os.environ, {"HASHSEAL_AUDIT_LOG": str(log)}):
            audit.write_event("test", config=cfg)
        self.assertFalse(old.exists())

    def test_audit_reads_archived_files(self) -> None:
        log = self.tmp / "read.jsonl"
        archive = self.tmp / "read-2026-11-13.jsonl"
        archive.write_text('{"event":"old"}\n', encoding="utf-8")
        log.write_text('{"event":"new"}\n', encoding="utf-8")
        lines = audit.read_events(log, 10)
        self.assertEqual(len(lines), 2)
        self.assertIn("old", lines[0])
        self.assertIn("new", lines[1])

    def test_syslog_sink_does_not_write_file(self) -> None:
        log = self.tmp / "syslog.jsonl"
        cfg = {"audit_sink": "syslog", "audit_file": str(log)}
        with (
            mock.patch("syslog.syslog") as syslog_write,
            mock.patch("syslog.openlog"),
        ):
            audit.write_event("sign", config=cfg, path="x")
        self.assertTrue(syslog_write.called)
        self.assertFalse(log.exists())

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
        props = {p["name"]: p["value"] for p in data["metadata"]["properties"]}
        self.assertIn("UTC", props["hashseal:local_time"])

    def test_sbom_with_dependencies(self) -> None:
        d = self._dir()
        (d / "uv.lock").write_text(
            'version = 1\n'
            '[[package]]\nname = "requests"\nversion = "2.32.0"\n'
            '[[package]]\nname = "urllib3"\nversion = "2.2.1"\n',
            encoding="utf-8",
        )
        self._run("sign", str(d), "-k", str(self.priv), "--force")
        out = self.tmp / "sbom-deps.json"
        rc, text = self._run("sbom", str(d), "-o", str(out), "--deps")
        self.assertEqual(rc, 0, text)
        data = json.loads(out.read_text(encoding="utf-8"))
        libs = [c for c in data["components"] if c["type"] == "library"]
        self.assertEqual({c["name"] for c in libs}, {"requests", "urllib3"})
        self.assertIn("pkg:pypi/requests@2.32.0", {c.get("purl") for c in libs})

    def test_attest_roundtrip_and_tamper(self) -> None:
        d = self._dir()
        self._run("sign", str(d), "-k", str(self.priv), "--force")
        att = self.tmp / "att.json"
        rc, out = self._run("attest", str(d), "-o", str(att), "-k", str(self.priv))
        self.assertEqual(rc, 0, out)
        rc, out = self._run("attest-verify", str(att), "-p", str(self.pub))
        self.assertEqual(rc, 0, out)
        self.assertIn("证明有效", out)

        env = json.loads(att.read_text(encoding="utf-8"))
        payload = json.loads(base64.b64decode(env["payload"]))
        payload["subject"][0]["digest"]["sha256"] = "0" * 64
        env["payload"] = base64.b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).decode()
        att.write_text(json.dumps(env), encoding="utf-8")
        rc, out = self._run("attest-verify", str(att), "-p", str(self.pub))
        self.assertEqual(rc, 1, out)
        self.assertIn("无效", out)

    def test_interactive_password_prompt(self) -> None:
        pw = self.tmp / "pw.txt"
        pw.write_text("testpassword123", encoding="utf-8")
        priv = self.tmp / "enc.pem"
        pub = self.tmp / "enc.pub"
        self._run("keygen", "--private", str(priv), "--public", str(pub), "--password-file", str(pw))
        with (
            mock.patch.object(sys.stdin, "isatty", return_value=True),
            mock.patch("getpass.getpass", return_value="testpassword123"),
        ):
            rc, out = self._run("sign", str(self.target), "-k", str(priv))
        self.assertEqual(rc, 0, out)

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
