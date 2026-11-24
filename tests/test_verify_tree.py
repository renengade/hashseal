"""verify_tree 与 verify_entries+find_unlisted 的语义一致性测试。"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from hashseal.manifest import build_manifest, find_unlisted, verify_entries, verify_tree


class VerifyTreeParityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="hashseal-tree-test-"))
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)
        self.root = self.tmp / "pkg"
        self.root.mkdir()

    def _manifest(self) -> tuple[Path, list[tuple[str, str]]]:
        (self.root / "a.txt").write_text("A\n", encoding="utf-8")
        (self.root / "b.txt").write_text("B\n", encoding="utf-8")
        (self.root / ".env").write_text("SECRET=1\n", encoding="utf-8")
        (self.root / "c.txt").write_text("C\n", encoding="utf-8")  # 未列入
        manifest = self.tmp / "m.sha256"
        build_manifest([str(self.root)], manifest, self.root)
        entries = [
            ("f5df179a46f8ce999d35408fc9062e7b0b21d64fb28e78ea0f05201ffc464fa4", "b.txt"),
        ]
        return manifest, entries

    def test_parity_with_legacy_calls(self) -> None:
        _manifest, entries = self._manifest()
        # 旧路径：verify_entries + find_unlisted
        good, bad = verify_entries(self.root, entries, jobs=1)
        extras, skipped = find_unlisted(
            self.root, {rel for _, rel in entries}, excludes=(), follow_symlinks=False
        )
        # 新路径：verify_tree 单次遍历
        tree = verify_tree(self.root, entries, excludes=(), follow_symlinks=False, jobs=1)

        self.assertEqual(tree["checked"], len(entries))
        self.assertEqual(tree["ok_count"], len(good))
        self.assertEqual(tree["failed"], bad)
        self.assertEqual(tree["unlisted"], extras)
        self.assertEqual(tree["skipped"], skipped)
        # .env 命中 DEFAULT_EXCLUDES → skipped
        self.assertTrue(any("excluded" in s for s in tree["skipped"]))
        # c.txt 未列入
        self.assertIn("c.txt", tree["unlisted"])

    def test_missing_and_tamper(self) -> None:
        _manifest, entries = self._manifest()
        # 修改 b.txt 内容（失败）+ 删除后补一条不存在条目（缺失）
        (self.root / "b.txt").write_text("Tampered\n", encoding="utf-8")
        entries = entries + [
            ("0" * 64, "missing.txt"),
        ]
        tree = verify_tree(self.root, entries, follow_symlinks=False, jobs=1)
        reasons = {f["path"]: f["reason"] for f in tree["failed"]}
        self.assertEqual(reasons.get("b.txt"), "内容不一致")
        self.assertEqual(reasons.get("missing.txt"), "文件缺失")
        self.assertEqual(tree["ok_count"], len(entries) - len(tree["failed"]))
        # 失败项保持输入顺序
        failed_paths = [f["path"] for f in tree["failed"]]
        self.assertEqual(failed_paths, [e[1] for e in entries if e[1] in failed_paths])

    def test_check_unlisted_false_matches_verify_entries(self) -> None:
        _manifest, entries = self._manifest()
        good, bad = verify_entries(self.root, entries, jobs=1)
        tree = verify_tree(self.root, entries, check_unlisted=False, jobs=1)
        self.assertEqual(tree["ok_count"], len(good))
        self.assertEqual(tree["failed"], bad)
        self.assertEqual(tree["unlisted"], [])
        self.assertEqual(tree["skipped"], [])

    def test_symlink_skip_and_fallback_hash(self) -> None:
        _manifest, entries = self._manifest()
        # a.txt 未列入清单；做软链接指向根外 → skipped（不跟随）
        (self.root / "d.txt").write_text("D\n", encoding="utf-8")
        try:
            os.symlink(self.tmp / "outside.txt", self.root / "e.txt")
        except (OSError, NotImplementedError):
            self.skipTest("本机不支持创建符号链接")
        (self.tmp / "outside.txt").write_text("OUT\n", encoding="utf-8")
        entries = entries + [("a" * 64, "d.txt"), ("b" * 64, "really_missing.txt")]
        tree = verify_tree(self.root, entries, follow_symlinks=False, jobs=1)
        self.assertTrue(any("symlink" in s for s in tree["skipped"]))
        reasons = {f["path"]: f["reason"] for f in tree["failed"]}
        self.assertEqual(reasons.get("d.txt"), "内容不一致")  # 文件存在但哈希不符
        self.assertEqual(reasons.get("really_missing.txt"), "文件缺失")


if __name__ == "__main__":
    unittest.main()
