"""路径默认值预填测试：配置优先、启动目录锚定、越界不预填。"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path

from hashseal.gui.server import GuiSettings, build


class PathDefaultsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="hashseal-def-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        # 隔离用户配置
        self._old_cfg = os.environ.get("HASHSEAL_CONFIG")
        cfg_file = self.tmp / "config.toml"
        cfg_file.write_text(
            '[hashseal]\nkey = "mykey.pem"\npubkey = "mypub.pem"\n',
            encoding="utf-8",
        )
        os.environ["HASHSEAL_CONFIG"] = str(cfg_file)
        self.addCleanup(self._restore_cfg)
        # 配置里的相对路径按 CLI 语义锚定在启动目录（cwd）——本测试把 cwd 模拟为 tmp
        self._old_cwd = os.getcwd()
        os.chdir(self.tmp)
        self.addCleanup(os.chdir, self._old_cwd)

        self.server, self.url, self.token = build(
            GuiSettings(
                port=0,
                open_browser=False,
                roots=[self.tmp],
                idle_timeout_minutes=0,
                vault_timeout_minutes=0,
            )
        )
        self.base = f"http://127.0.0.1:{self.server.port}"
        thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05})
        thread.daemon = True
        thread.start()
        self.addCleanup(self._teardown)

    def _restore_cfg(self) -> None:
        if self._old_cfg is None:
            os.environ.pop("HASHSEAL_CONFIG", None)
        else:
            os.environ["HASHSEAL_CONFIG"] = self._old_cfg

    def _teardown(self) -> None:
        self.server.shutdown()
        self.server.tasks.stop()
        self.server.server_close()

    def _commands(self) -> dict[str, dict]:
        req = urllib.request.Request(
            self.base + "/api/commands", headers={"X-Hashseal-Token": self.token}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return {c["name"]: c for c in data["commands"]}

    def _field(self, command: dict, name: str) -> dict:
        return next(f for f in command["fields"] if f["name"] == name)

    def test_defaults_follow_config(self) -> None:
        commands = self._commands()
        keygen = commands["keygen"]
        self.assertEqual(self._field(keygen, "private")["default"], str(self.tmp / "mykey.pem"))
        self.assertEqual(self._field(keygen, "public")["default"], str(self.tmp / "mypub.pem"))
        sign = commands["sign"]
        self.assertEqual(self._field(sign, "key")["default"], str(self.tmp / "mykey.pem"))
        verify = commands["verify"]
        self.assertEqual(self._field(verify, "key")["default"], str(self.tmp / "mypub.pem"))

    def test_outside_root_default_omitted(self) -> None:
        # 把配置指向根外的路径 → 默认不预填（留空走 CLI 兜底）
        cfg_file = Path(os.environ["HASHSEAL_CONFIG"])
        cfg_file.write_text('[hashseal]\nkey = "/etc/outside_key.pem"\n', encoding="utf-8")
        commands = self._commands()
        self.assertEqual(self._field(commands["keygen"], "private")["default"], "")
        self.assertEqual(self._field(commands["sign"], "key")["default"], "")

    def test_fixed_name_defaults_anchored_to_cwd(self) -> None:
        commands = self._commands()
        def assert_default(field: dict, name: str) -> None:
            value = field["default"]
            self.assertEqual(os.path.basename(value), name)
            self.assertTrue(os.path.samefile(os.path.dirname(value), self.tmp), value)

        assert_default(self._field(commands["manifest"], "output"), "MANIFEST.sha256")
        assert_default(self._field(commands["sbom"], "output"), "sbom.cdx.json")
        assert_default(self._field(commands["attest"], "output"), "attestation.json")


if __name__ == "__main__":
    unittest.main()
