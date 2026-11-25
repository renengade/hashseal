"""GUI 安全测试：鉴权、同源校验、路径 jail、请求体限制、静态资源与安全头。"""

from __future__ import annotations

import os
import unittest

from gui_base import GuiTestBase


class AuthTest(GuiTestBase):
    def test_missing_token_401(self) -> None:
        status, payload = self.request("/api/status", token="")
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"]["code"], "unauthorized")

    def test_wrong_token_401(self) -> None:
        status, _payload = self.request("/api/status", token="wrong-token")
        self.assertEqual(status, 401)

    def test_correct_token_ok(self) -> None:
        status, payload = self.request("/api/status")
        self.assertEqual(status, 200)
        self.assertTrue(payload["version"])

    def test_bad_host_403(self) -> None:
        status, payload = self.request("/api/status", headers={"Host": "evil.example"})
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "bad_host")

    def test_bad_origin_403(self) -> None:
        status, payload = self.request("/api/status", headers={"Origin": "http://evil.example"})
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "bad_origin")

    def test_good_origin_ok(self) -> None:
        origin = f"http://127.0.0.1:{self.port}"
        status, _p = self.request("/api/status", headers={"Origin": origin})
        self.assertEqual(status, 200)

    def test_post_requires_json_content_type(self) -> None:
        status, _payload = self.request(
            "/api/run",
            method="POST",
            body={"command": "keygen", "options": {}},
            headers={"Content-Type": "text/plain"},
        )
        self.assertEqual(status, 415)

    def test_transfer_encoding_rejected(self) -> None:
        status, _payload = self.request(
            "/api/run",
            method="POST",
            body={"command": "keygen", "options": {}},
            headers={"Transfer-Encoding": "chunked"},
        )
        self.assertEqual(status, 400)

    def test_oversized_body_413(self) -> None:
        import urllib.error
        import urllib.request

        req = urllib.request.Request(
            self.base + "/api/run",
            data=b"x" * (2 << 20),
            headers={
                "Content-Type": "application/json",
                "X-Hashseal-Token": self.token,
            },
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=30)
            self.fail("应该拒绝超大请求体")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 413)


class StaticTest(GuiTestBase):
    def _headers(self, path: str) -> dict[str, str]:
        import urllib.request

        req = urllib.request.Request(self.base + path)
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read()
            headers = {k.lower(): v for k, v in resp.headers.items()}
            self.assertEqual(resp.status, 200)
        self.assertTrue(body)
        return headers

    def test_index_served_without_token(self) -> None:
        headers = self._headers("/")
        self.assertIn("text/html", headers["content-type"])

    def test_security_headers(self) -> None:
        headers = self._headers("/")
        self.assertIn("default-src 'none'", headers["content-security-policy"])
        self.assertEqual(headers["x-content-type-options"], "nosniff")
        self.assertEqual(headers["referrer-policy"], "no-referrer")
        self.assertEqual(headers["x-frame-options"], "DENY")

    def test_static_allowlist(self) -> None:
        for path in ("/app.css", "/app.js", "/api.js", "/ui.js", "/favicon.svg"):
            self._headers(path)
        import urllib.error
        import urllib.request

        try:
            urllib.request.urlopen(self.base + "/secret.txt", timeout=30)
            self.fail("未知静态路径应 404")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 404)


class PathJailTest(GuiTestBase):
    def test_browse_outside_root_400(self) -> None:
        import urllib.parse

        outside = "/etc"
        status, payload = self.request("/api/browse?path=" + urllib.parse.quote(outside))
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "outside_root")

    def test_browse_traversal_rejected(self) -> None:
        import urllib.parse

        evil = str(self.tmp / ".." / ".." / "etc")
        status, payload = self.request("/api/browse?path=" + urllib.parse.quote(evil))
        # 视平台：既可能在 jail 检查被拒（400），也可能落在允许根内但不存在（404）
        self.assertIn(status, (400, 404), payload)
        self.assertIn(payload["error"]["code"], ("outside_root", "not_found"))

    def test_browse_inside_root_ok(self) -> None:
        import urllib.parse

        (self.tmp / "sub").mkdir()
        (self.tmp / "sub" / "a.txt").write_text("x", encoding="utf-8")
        status, payload = self.request("/api/browse?path=" + urllib.parse.quote(str(self.tmp)))
        self.assertEqual(status, 200)
        names = [e["name"] for e in payload["entries"]]
        self.assertIn("sub", names)

        # 父目录要么不可上溯（None），要么必须落在某个允许根内
        # （Windows 下 tmp 位于用户 home 内；用 realpath 消除 8.3 短路径差异）
        def canon(p: str) -> str:
            return os.path.normcase(os.path.realpath(str(p)).removeprefix("\\\\?\\"))

        if payload["parent"] is not None:
            parent = canon(payload["parent"])
            self.assertTrue(
                any(
                    parent == canon(r) or parent.startswith(canon(r) + os.sep)
                    for r in payload["roots"]
                ),
                payload,
            )

    def test_run_rejects_outside_paths(self) -> None:
        status, _task = self.run_cmd(
            "keygen",
            {"private": "/etc/hashseal_pwn.pem", "public": str(self.tmp / "p2pub.pem")},
            wait_result=False,
        )
        self.assertEqual(status, 400)
        self.assertEqual(_task["error"]["code"], "outside_root")

    def test_symlink_escape_not_navigable(self) -> None:
        import urllib.parse

        try:
            (self.tmp / "link").symlink_to("/etc")
        except (OSError, NotImplementedError):
            self.skipTest("本机不支持创建符号链接")
        status, payload = self.request("/api/browse?path=" + urllib.parse.quote(str(self.tmp)))
        self.assertEqual(status, 200)
        entry = next(e for e in payload["entries"] if e["name"] == "link")
        self.assertTrue(entry["symlink"])
        self.assertFalse(entry["navigable"])


class ApiValidationTest(GuiTestBase):
    def test_unknown_command_404(self) -> None:
        status, _payload = self.run_cmd("evil-cmd", {}, wait_result=False)
        self.assertEqual(status, 404)

    def test_unknown_option_400(self) -> None:
        status, _payload = self.run_cmd(
            "keygen", {"private": str(self.tmp / "x.pem"), "hax": "1"}, wait_result=False
        )
        self.assertEqual(status, 400)
        self.assertEqual(_payload["error"]["code"], "unknown_option")

    def test_missing_required_400(self) -> None:
        status, _payload = self.run_cmd("verify", {}, wait_result=False)
        self.assertEqual(status, 400)
        self.assertEqual(_payload["error"]["code"], "missing_option")


if __name__ == "__main__":
    unittest.main()


class SystemRootsTest(GuiTestBase):
    RESTRICT_ROOTS = False  # 默认放开：可浏览文件系统根 / 所有盘符

    def test_can_browse_system_root(self) -> None:
        import urllib.parse

        target = "C:\\" if os.name == "nt" else "/"
        status, payload = self.request("/api/browse?path=" + urllib.parse.quote(target))
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["entries"])
        # 系统根仍在 jail 内，但不出现在「根目录」列表里
        self.assertIn(target, payload["roots"])
        self.assertNotIn(target, payload["display_roots"])

    @unittest.skipIf(os.name == "nt", "POSIX 根目录 /")
    def test_can_browse_child_of_system_root(self) -> None:
        """回归：根 "/" 已带分隔符，拼接后不能变成 "//" 导致 /mnt 被判越界。"""
        import urllib.parse
        from pathlib import Path

        child = next(
            p for p in sorted(Path("/").iterdir()) if p.is_dir() and not p.name.startswith(".")
        )
        status, payload = self.request("/api/browse?path=" + urllib.parse.quote(str(child)))
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["entries"] or payload["path"])
