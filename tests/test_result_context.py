"""result.py 上下文与 CLI 集成测试：结构化结果、错误/警告收集、审计 source。"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import hashseal
from hashseal.audit import audit_path, read_events
from hashseal.result import CommandContext


class ContextTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="hashseal-ctx-test-"))
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)

    def _run(self, *argv: str, context: CommandContext | None = None) -> tuple[int, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            try:
                rc = hashseal.main(list(argv), context=context)
            except SystemExit as exc:
                rc = int(exc.code or 0)
        return rc, out.getvalue() + err.getvalue()

    def test_collect_result_keygen_and_fingerprint(self) -> None:
        ctx = CommandContext(source="gui", collect=True)
        rc, out = self._run(
            "keygen",
            "--private",
            str(self.tmp / "p.pem"),
            "--public",
            str(self.tmp / "pub.pem"),
            context=ctx,
        )
        self.assertEqual(rc, 0, out)
        payload = ctx.result
        assert payload is not None
        self.assertEqual(payload["private"], str(self.tmp / "p.pem"))
        self.assertTrue(payload["fingerprint"].startswith("SHA256:"))
        self.assertFalse(payload["encrypted"])

        ctx2 = CommandContext(source="gui", collect=True)
        rc, out = self._run("fingerprint", "-k", str(self.tmp / "pub.pem"), context=ctx2)
        self.assertEqual(rc, 0, out)
        assert ctx2.result is not None
        self.assertEqual(ctx2.result["fingerprint"], payload["fingerprint"])

    def test_default_context_does_not_collect(self) -> None:
        ctx = CommandContext()
        rc, out = self._run(
            "keygen",
            "--private",
            str(self.tmp / "a.pem"),
            "--public",
            str(self.tmp / "apub.pem"),
            context=ctx,
        )
        self.assertEqual(rc, 0, out)
        self.assertIsNone(ctx.result)

    def test_die_captures_error(self) -> None:
        ctx = CommandContext(collect=True)
        rc, out = self._run("verify", str(self.tmp / "missing.bin"), context=ctx)
        self.assertEqual(rc, 2)
        self.assertIn("错误", out)
        self.assertIsNotNone(ctx.error)
        self.assertIn("不存在", ctx.error or "")

    def test_warnings_collected_when_collect(self) -> None:
        ctx = CommandContext(collect=True)
        rc, out = self._run(
            "keygen",
            "--private",
            str(self.tmp / "w.pem"),
            "--public",
            str(self.tmp / "wpub.pem"),
            context=ctx,
        )
        self.assertEqual(rc, 0, out)
        self.assertEqual(ctx.warnings, [])

        # 短口令触发警告
        ctx2 = CommandContext(collect=True, password="123")
        rc, out = self._run(
            "keygen",
            "--private",
            str(self.tmp / "w2.pem"),
            "--public",
            str(self.tmp / "w2pub.pem"),
            context=ctx2,
        )
        self.assertEqual(rc, 0, out)
        self.assertTrue(any("口令" in w for w in ctx2.warnings), ctx2.warnings)
        # collect=True 时警告不再打印到 stderr
        self.assertNotIn("警告", out)

    def test_password_from_context(self) -> None:
        from hashseal.core import is_encrypted_key

        ctx = CommandContext(collect=True, password="secret-passphrase")
        rc, out = self._run(
            "keygen",
            "--private",
            str(self.tmp / "enc.pem"),
            "--public",
            str(self.tmp / "encpub.pem"),
            context=ctx,
        )
        self.assertEqual(rc, 0, out)
        self.assertTrue(is_encrypted_key(self.tmp / "enc.pem"))

        ctx2 = CommandContext(collect=True, password="secret-passphrase")
        rc, out = self._run(
            "sign", str(self.tmp / "f.txt"), "-k", str(self.tmp / "enc.pem"), context=ctx2
        )
        (self.tmp / "f.txt").write_text("hi\n", encoding="utf-8")
        ctx3 = CommandContext(collect=True, password="secret-passphrase")
        rc, out = self._run(
            "sign", str(self.tmp / "f.txt"), "-k", str(self.tmp / "enc.pem"), context=ctx3
        )
        self.assertEqual(rc, 0, out)
        self.assertTrue((self.tmp / "f.txt.sig").is_file())

    def test_gui_password_required_message(self) -> None:
        (self.tmp / "f.txt").write_text("hi\n", encoding="utf-8")
        # 未加密密钥 + 无口令：正常
        self._run(
            "keygen", "--private", str(self.tmp / "k.pem"), "--public", str(self.tmp / "kpub.pem")
        )
        ctx = CommandContext(collect=True, interactive=False)
        rc, out = self._run(
            "sign", str(self.tmp / "f.txt"), "-k", str(self.tmp / "k.pem"), context=ctx
        )
        self.assertEqual(rc, 0, out)

    def test_audit_source_field(self) -> None:
        before = len(read_events(audit_path(), 10_000))
        self._run(
            "keygen", "--private", str(self.tmp / "s.pem"), "--public", str(self.tmp / "spub.pem")
        )
        lines = read_events(audit_path(), 10_000)[before:]
        self.assertTrue(lines)
        record = json.loads(lines[-1])
        self.assertEqual(record.get("source"), "cli")

        ctx = CommandContext(source="gui", collect=True)
        self._run("fingerprint", "-k", str(self.tmp / "spub.pem"), context=ctx)
        lines = read_events(audit_path(), 10_000)
        record = json.loads(lines[-1])
        self.assertEqual(record.get("source"), "gui")
        self.assertEqual(record.get("event"), "fingerprint")


if __name__ == "__main__":
    unittest.main()
