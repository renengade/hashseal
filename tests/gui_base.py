"""GUI 测试基座：启动内存中的本地服务，提供 HTTP 请求助手。"""

from __future__ import annotations

import json
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from hashseal.gui.server import GuiSettings, build

WAIT = 30.0


class GuiTestBase(unittest.TestCase):
    """启动一个真实服务（127.0.0.1 随机端口），roots 指向临时目录。"""

    RESTRICT_ROOTS = True  # 安全用例默认开启限制；系统根目录用例可覆盖

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="hashseal-gui-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.server, self.url, self.token = build(
            GuiSettings(
                port=0,
                open_browser=False,
                roots=[self.tmp],
                read_only=False,
                idle_timeout_minutes=0,
                vault_timeout_minutes=0,
                restrict_roots=self.RESTRICT_ROOTS,
            )
        )
        self.port = self.server.port
        self.base = f"http://127.0.0.1:{self.port}"
        thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05})
        thread.daemon = True
        thread.start()
        self.addCleanup(self._teardown)
        self._thread = thread

    def _teardown(self) -> None:
        self.server.shutdown()
        self.server.tasks.stop()
        self.server.server_close()
        self._thread.join(timeout=5)

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        body: dict | None = None,
        token: str | None = ...,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict]:
        url = self.base + path
        req_headers: dict[str, str] = {}
        if token is ...:
            token = self.token
        if token:
            req_headers["X-Hashseal-Token"] = token
        if headers:
            req_headers.update(headers)
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json")
        req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=WAIT) as resp:
                raw = resp.read()
                return resp.status, json.loads(raw.decode("utf-8")) if raw else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                payload = json.loads(raw.decode("utf-8")) if raw else {}
            except json.JSONDecodeError:
                payload = {"raw": raw.decode("utf-8", "replace")}
            return exc.code, payload

    def run_cmd(self, command: str, options: dict, *, wait_result: bool = True) -> tuple[int, dict]:
        status, payload = self.request(
            "/api/run", method="POST", body={"command": command, "options": options}
        )
        if status != 202 or not wait_result:
            return status, payload
        task_id = payload["task_id"]
        for _ in range(600):
            status, task = self.request(f"/api/tasks/{task_id}")
            if task.get("state") in ("succeeded", "failed", "canceled"):
                return status, task
            import time

            time.sleep(0.05)
        raise AssertionError(f"任务超时: {task_id}")

    def make_keypair(self, name: str = "key") -> tuple[Path, Path]:
        priv, pub = self.tmp / f"{name}_private.pem", self.tmp / f"{name}_public.pem"
        _status, task = self.run_cmd("keygen", {"private": str(priv), "public": str(pub)})
        self.assertEqual(task["state"], "succeeded", task)
        return priv, pub
