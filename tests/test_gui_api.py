"""GUI API 端到端测试：keygen→sign→verify 全流程、vault、审计 source、只读模式。"""

from __future__ import annotations

import json
import unittest

from gui_base import GuiTestBase

from hashseal.audit import audit_path, read_events


class LifecycleTest(GuiTestBase):
    def test_status_and_commands(self) -> None:
        status, payload = self.request("/api/status")
        self.assertEqual(status, 200)
        self.assertIn(str(self.tmp), payload["roots"])
        status, payload = self.request("/api/commands")
        self.assertEqual(status, 200)
        names = {c["name"] for c in payload["commands"]}
        self.assertIn("sign", names)
        self.assertIn("verify", names)

    def test_keygen_sign_verify_roundtrip(self) -> None:
        priv, pub = self.make_keypair()
        target = self.tmp / "app.py"
        target.write_text('print("hi")\n', encoding="utf-8")

        _status, task = self.run_cmd("sign", {"files": [str(target)], "key": str(priv)})
        self.assertEqual(task["state"], "succeeded", task)
        self.assertTrue((self.tmp / "app.py.sig").is_file())
        items = task["result"]["items"]
        self.assertEqual(items[0]["path"], str(target))
        self.assertIn("digest", items[0])

        _status, task = self.run_cmd("verify", {"file": str(target), "key": str(pub)})
        self.assertEqual(task["state"], "succeeded", task)
        self.assertTrue(task["result"]["ok"])
        self.assertTrue(task["result"]["signer_fingerprint"].startswith("SHA256:"))

    def test_verify_detects_tamper(self) -> None:
        priv, pub = self.make_keypair()
        target = self.tmp / "data.txt"
        target.write_text("hello\n", encoding="utf-8")
        _status, task = self.run_cmd("sign", {"files": [str(target)], "key": str(priv)})
        self.assertEqual(task["state"], "succeeded")
        target.write_text("hello!\n", encoding="utf-8")
        _status, task = self.run_cmd("verify", {"file": str(target), "key": str(pub)})
        self.assertEqual(task["state"], "failed")
        self.assertFalse(task["result"]["ok"])
        self.assertTrue(any("SHA-256 不同" in r for r in task["result"]["reasons"]))

    def test_directory_sign_verify(self) -> None:
        priv, pub = self.make_keypair()
        d = self.tmp / "pkg"
        d.mkdir()
        (d / "a.txt").write_text("A\n", encoding="utf-8")
        (d / "b.txt").write_text("B\n", encoding="utf-8")
        _status, task = self.run_cmd("sign", {"files": [str(d)], "key": str(priv)})
        self.assertEqual(task["state"], "succeeded", task)
        self.assertTrue((d / ".hashseal" / "MANIFEST.sha256.sig").is_file())

        _status, task = self.run_cmd("verify", {"file": str(d), "key": str(pub)})
        self.assertEqual(task["state"], "succeeded")
        self.assertTrue(task["result"]["ok"])
        self.assertEqual(task["result"]["files"]["checked"], 2)

        # 追加未列入文件 → 验证失败
        (d / "c.txt").write_text("C\n", encoding="utf-8")
        _status, task = self.run_cmd("verify", {"file": str(d), "key": str(pub)})
        self.assertEqual(task["state"], "failed")
        self.assertIn("c.txt", task["result"]["files"]["unlisted"])

    def test_hash_and_inspect(self) -> None:
        target = self.tmp / "t.bin"
        target.write_bytes(b"\x00" * 10)
        _status, task = self.run_cmd("hash", {"files": [str(target)]})
        self.assertEqual(task["state"], "succeeded")
        digest = task["result"]["files"][0]["digest"]
        self.assertEqual(len(digest), 64)

        priv, _pub = self.make_keypair()
        target.write_text("x\n", encoding="utf-8")
        self.run_cmd("sign", {"files": [str(target)], "key": str(priv)})
        _status, task = self.run_cmd("inspect", {"file": str(target) + ".sig"})
        self.assertEqual(task["state"], "succeeded")
        self.assertEqual(task["result"]["kind"], "sig")
        self.assertEqual(task["result"]["name"], "t.bin")

    def test_diff_manifests(self) -> None:
        d = self.tmp / "d"
        d.mkdir()
        (d / "a.txt").write_text("1\n", encoding="utf-8")
        _status, t1 = self.run_cmd(
            "manifest", {"paths": [str(d)], "output": str(self.tmp / "m1.sha256"), "base": str(d)}
        )
        self.assertEqual(t1["state"], "succeeded")
        (d / "b.txt").write_text("2\n", encoding="utf-8")
        self.run_cmd(
            "manifest", {"paths": [str(d)], "output": str(self.tmp / "m2.sha256"), "base": str(d)}
        )
        _status, task = self.run_cmd(
            "diff", {"left": str(self.tmp / "m1.sha256"), "right": str(self.tmp / "m2.sha256")}
        )
        self.assertEqual(task["state"], "failed")  # 有差异时 CLI rc=1
        self.assertIn("b.txt", task["result"]["added"])

    def test_config_init(self) -> None:
        out = self.tmp / "cfg.toml"
        _status, task = self.run_cmd("config-init", {"path": str(out)})
        self.assertEqual(task["state"], "succeeded")
        self.assertTrue(out.is_file())
        self.assertIn("[hashseal]", out.read_text(encoding="utf-8"))


class VaultTest(GuiTestBase):
    def test_unlock_wrong_and_right_password(self) -> None:
        priv, pub = self.make_keypair("enc")
        # 重新生成加密私钥
        _status, task = self.run_cmd(
            "keygen",
            {
                "private": str(priv),
                "public": str(pub),
                "password": "super-secret-pass",
                "force": True,
            },
        )
        self.assertEqual(task["state"], "succeeded")

        status, payload = self.request(
            "/api/vault/unlock",
            method="POST",
            body={"key": str(priv), "password": "wrong-pass"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "bad_password")

        status, payload = self.request(
            "/api/vault/unlock",
            method="POST",
            body={"key": str(priv), "password": "super-secret-pass"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(payload["fingerprint"].startswith("SHA256:"))

        status, payload = self.request("/api/vault")
        self.assertIn(str(priv), payload["keys"])

        # 记住的口令可直接签名
        target = self.tmp / "v.txt"
        target.write_text("v\n", encoding="utf-8")
        status, task = self.run_cmd("sign", {"files": [str(target)], "key": str(priv)})
        self.assertEqual(task["state"], "succeeded", task)

        # 锁定后需重新提供口令
        status, _ = self.request("/api/vault/lock", method="POST", body={})
        status, payload = self.request("/api/vault")
        self.assertEqual(payload["keys"], [])

    def test_sign_remember_stores_password(self) -> None:
        priv, pub = self.make_keypair("rm")
        _status, task = self.run_cmd(
            "keygen",
            {
                "private": str(priv),
                "public": str(pub),
                "password": "another-pass-123",
                "force": True,
            },
        )
        self.assertEqual(task["state"], "succeeded")

        target = self.tmp / "rm.txt"
        target.write_text("rm\n", encoding="utf-8")
        _status, task = self.run_cmd(
            "sign",
            {
                "files": [str(target)],
                "key": str(priv),
                "password": "another-pass-123",
                "remember": True,
            },
        )
        self.assertEqual(task["state"], "succeeded", task)
        _status, payload = self.request("/api/vault")
        self.assertIn(str(priv), payload["keys"])

    def test_wrong_password_fails_with_clear_error(self) -> None:
        priv, pub = self.make_keypair("wp")
        _status, task = self.run_cmd(
            "keygen",
            {"private": str(priv), "public": str(pub), "password": "right-pass-xyz", "force": True},
        )
        self.assertEqual(task["state"], "succeeded")
        target = self.tmp / "wp.txt"
        target.write_text("wp\n", encoding="utf-8")
        _status, task = self.run_cmd(
            "sign", {"files": [str(target)], "key": str(priv), "password": "bad-pass"}
        )
        self.assertEqual(task["state"], "failed")
        self.assertIn("无法解密", task["error"])
        # 失败任务对象中不残留口令
        self.assertNotIn("bad-pass", json.dumps(task))

    def test_password_never_in_task_or_argv(self) -> None:
        priv, pub = self.make_keypair("np")
        self.run_cmd(
            "keygen",
            {"private": str(priv), "public": str(pub), "password": "hidden-pass-9", "force": True},
        )
        target = self.tmp / "np.txt"
        target.write_text("np\n", encoding="utf-8")
        _status, task = self.run_cmd(
            "sign",
            {"files": [str(target)], "key": str(priv), "password": "hidden-pass-9"},
        )
        self.assertEqual(task["state"], "succeeded", task)
        dumped = json.dumps(task)
        self.assertNotIn("hidden-pass-9", dumped)


class AuditSourceTest(GuiTestBase):
    def test_gui_actions_audited_with_source(self) -> None:
        priv, _pub = self.make_keypair("aud")
        lines = read_events(audit_path(), 10_000)
        records = [json.loads(line) for line in lines]
        keygen_events = [
            r
            for r in records
            if r.get("event") == "keygen"
            and r.get("source") == "gui"
            and str(priv) in str(r.get("path", ""))
        ]
        self.assertTrue(keygen_events, records[-5:])


class ReadOnlyTest(GuiTestBase):
    def _read_only_server(self):
        from hashseal.gui.server import GuiSettings, build

        server, _url, token = build(
            GuiSettings(
                port=0,
                open_browser=False,
                roots=[self.tmp],
                read_only=True,
                idle_timeout_minutes=0,
                vault_timeout_minutes=0,
            )
        )
        self.addCleanup(server.server_close)
        self.addCleanup(server.tasks.stop)
        return server, token

    def test_read_only_blocks_mutating(self) -> None:
        import threading
        import urllib.request

        server, token = self._read_only_server()
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
        thread.daemon = True
        thread.start()
        self.addCleanup(server.shutdown)

        base = f"http://127.0.0.1:{server.port}"
        body = json.dumps({"command": "sign", "options": {}}).encode()
        req = urllib.request.Request(
            base + "/api/run",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "X-Hashseal-Token": token},
        )
        try:
            urllib.request.urlopen(req, timeout=10)
            self.fail("只读模式应拒绝 sign")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 403)
            payload = json.loads(exc.read().decode())
            self.assertEqual(payload["error"]["code"], "read_only")

        # 只读操作仍然可用
        req = urllib.request.Request(base + "/api/commands", headers={"X-Hashseal-Token": token})
        with urllib.request.urlopen(req, timeout=10) as resp:
            self.assertEqual(resp.status, 200)


if __name__ == "__main__":
    unittest.main()


class KeyInfoTest(GuiTestBase):
    def test_key_info_exists_and_remembered(self) -> None:
        import urllib.parse

        priv, pub = self.make_keypair("ki")
        # 未加密密钥
        status, payload = self.request(
            "/api/key-info?key=" + urllib.parse.quote(str(priv))
        )
        self.assertEqual(status, 200)
        self.assertTrue(payload["exists"])
        self.assertFalse(payload["encrypted"])
        self.assertFalse(payload["remembered"])

        # 不存在的路径 → exists False（而不是 404）
        status, payload = self.request(
            "/api/key-info?key=" + urllib.parse.quote(str(self.tmp / "nope.pem"))
        )
        self.assertEqual(status, 200)
        self.assertFalse(payload["exists"])

        # 加密密钥 + 解锁 → remembered True
        status, task = self.run_cmd(
            "keygen",
            {"private": str(priv), "public": str(pub),
             "password": "Str0ng#Pass", "force": True},
        )
        self.assertEqual(task["state"], "succeeded")
        status, payload = self.request(
            "/api/key-info?key=" + urllib.parse.quote(str(priv))
        )
        self.assertTrue(payload["encrypted"])
        self.assertFalse(payload["remembered"])
        status, _ = self.request(
            "/api/vault/unlock", method="POST",
            body={"key": str(priv), "password": "Str0ng#Pass"},
        )
        status, payload = self.request(
            "/api/key-info?key=" + urllib.parse.quote(str(priv))
        )
        self.assertTrue(payload["remembered"])
