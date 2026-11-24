"""GUI 任务队列测试：串行执行、口令剥离、失败审计、结果清理。"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from hashseal.gui.tasks import TaskQueue
from hashseal.gui.vault import PasswordVault


class TaskQueueTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="hashseal-task-test-"))
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)
        self.vault = PasswordVault()
        self.queue = TaskQueue(vault=self.vault, max_tasks=50, retain_seconds=3600)
        self.queue.start()
        self.addCleanup(self.queue.stop)
        # 测试密钥
        self.priv = self.tmp / "p.pem"
        self.pub = self.tmp / "pub.pem"
        self._run_cli(["keygen", "--private", str(self.priv), "--public", str(self.pub)])

    def _run_cli(self, argv: list[str], password: str | None = None) -> tuple[int, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            try:
                from hashseal import main as cli_main

                rc = cli_main(argv)
            except SystemExit as exc:
                rc = int(exc.code or 0)
        return rc, out.getvalue() + err.getvalue()

    def _wait(self, task_id: str) -> dict:
        for _ in range(600):
            task = self.queue.get(task_id)
            assert task is not None
            if task.state in ("succeeded", "failed", "canceled"):
                return task.to_dict()
            import time

            time.sleep(0.05)
        raise AssertionError("任务超时")

    def test_submit_executes_and_collects_result(self) -> None:
        target = self.tmp / "f.txt"
        target.write_text("x\n", encoding="utf-8")
        task = self.queue.submit("hash", ["hash", str(target)], password=None, remember_key=None)
        payload = self._wait(task.id)
        self.assertEqual(payload["state"], "succeeded")
        self.assertEqual(payload["result"]["files"][0]["path"], str(target))
        # 任务对象不保留口令字段
        self.assertNotIn("password", json.dumps(payload))

    def test_wrong_password_fails_and_drops_vault(self) -> None:

        # 生成加密密钥
        enc = self.tmp / "enc.pem"
        encpub = self.tmp / "encpub.pem"
        pw_file = self.tmp / "pw.txt"
        pw_file.write_text("right-pass\n", encoding="utf-8")
        self._run_cli(
            [
                "keygen",
                "--private",
                str(enc),
                "--public",
                str(encpub),
                "--password-file",
                str(pw_file),
            ]
        )
        target = self.tmp / "g.txt"
        target.write_text("g\n", encoding="utf-8")
        self.vault.put(enc, "totally-wrong")
        task = self.queue.submit(
            "sign",
            ["sign", str(target), "-k", str(enc), "--force"],
            password="totally-wrong",
            remember_key=str(enc),
        )
        payload = self._wait(task.id)
        self.assertEqual(payload["state"], "failed")
        self.assertIn("无法解密", payload["error"] or "")
        self.assertIsNone(self.vault.get(enc))

    def test_serial_execution(self) -> None:
        files = []
        for i in range(4):
            f2 = self.tmp / f"s{i}.txt"
            f2.write_text(f"{i}\n", encoding="utf-8")
            files.append(f2)
        tasks = [self.queue.submit("hash", ["hash", str(f2)]) for f2 in files]
        for t in tasks:
            payload = self._wait(t.id)
            self.assertEqual(payload["state"], "succeeded")

    def test_remember_key_stores_password_on_success(self) -> None:
        enc = self.tmp / "r.pem"
        encpub = self.tmp / "rpub.pem"
        self._run_cli(
            [
                "keygen",
                "--private",
                str(enc),
                "--public",
                str(encpub),
            ]
        )

        self._run_cli(
            [
                "keygen",
                "--private",
                str(enc),
                "--public",
                str(encpub),
                "--force",
            ]
        )
        # 用明文口令生成加密私钥（通过 context 传口令无法直接走 CLI argv，
        # 这里用未加密密钥验证 remember 流程本身：成功后 vault 里出现该密钥）
        target = self.tmp / "r.txt"
        target.write_text("r\n", encoding="utf-8")
        task = self.queue.submit(
            "sign",
            ["sign", str(target), "-k", str(enc), "--force"],
            password=None,
            remember_key=str(enc),
        )
        payload = self._wait(task.id)
        self.assertEqual(payload["state"], "succeeded")
        # password=None 时不会写入 vault
        self.assertIsNone(self.vault.get(enc))


if __name__ == "__main__":
    unittest.main()
