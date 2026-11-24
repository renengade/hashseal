"""失败审计：CLI/GUI 异常退出都必须留痕，且不重复。"""

from __future__ import annotations

import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import hashseal
from hashseal.audit import audit_path, read_events
from hashseal.result import CommandContext


def all_events() -> list[dict]:
    return [json.loads(line) for line in read_events(audit_path(), 100_000)]


def events_since(mark: int) -> list[dict]:
    return all_events()[mark:]


class FailureAuditTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="hashseal-fail-audit-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _run(self, *argv: str, ctx: CommandContext | None = None) -> int:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            try:
                return hashseal.main(list(argv), context=ctx)
            except SystemExit as exc:
                return int(exc.code or 0)

    def test_cli_die_writes_command_failed(self) -> None:
        mark = len(all_events())
        rc = self._run("verify", str(self.tmp / "missing.bin"))
        self.assertEqual(rc, 2)
        failed = [e for e in events_since(mark) if e.get("event") == "command_failed"]
        self.assertTrue(failed, "未找到 command_failed 事件")
        self.assertEqual(failed[-1]["source"], "cli")
        self.assertEqual(failed[-1]["command"], "verify")
        self.assertIn("不存在", failed[-1]["error"])

    def test_gui_source_recorded(self) -> None:
        mark = len(all_events())
        ctx = CommandContext(source="gui", collect=True, interactive=False)
        rc = self._run("verify", str(self.tmp / "missing.bin"), ctx=ctx)
        self.assertEqual(rc, 2)
        failed = [e for e in events_since(mark) if e.get("event") == "command_failed"]
        self.assertEqual(failed[-1]["source"], "gui")

    def test_no_duplicate_when_command_already_audited(self) -> None:
        # manifest 在空目录会先写 ok=False 审计，然后 die → 不应再补 command_failed
        empty = self.tmp / "empty"
        empty.mkdir()
        mark = len(all_events())
        rc = self._run("manifest", str(empty), "-o", str(self.tmp / "m.sha256"))
        self.assertEqual(rc, 2)
        events = events_since(mark)
        self.assertFalse(
            [e for e in events if e.get("event") == "command_failed"],
            "命令已自行审计失败时不应重复记录 command_failed",
        )

    def test_unexpected_exception_audited(self) -> None:
        from unittest import mock

        mark = len(all_events())
        with (
            mock.patch("hashseal.cli.load_config", side_effect=RuntimeError("boom")),
            self.assertRaises(RuntimeError),
        ):
            self._run("fingerprint")
        failed = [e for e in events_since(mark) if e.get("event") == "command_failed"]
        self.assertTrue(failed)
        self.assertEqual(failed[-1]["error"], "boom")


if __name__ == "__main__":
    unittest.main()
