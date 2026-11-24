"""bundle 解包防护：zip bomb 上限（条目数 / 解压后大小）。"""

from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from hashseal.bundle import BundleError, unpack_bundle


class BundleLimitTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="hashseal-bomb-"))
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)
        self.bundle = self.tmp / "b.zip"

    def _make_zip(self, entries: int, payload: bytes = b"x") -> None:
        with zipfile.ZipFile(self.bundle, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("hashseal-bundle.json", "{}")
            for i in range(entries):
                zf.writestr(f"f{i}.bin", payload)

    def test_entry_count_limit(self) -> None:
        self._make_zip(entries=5)
        with self.assertRaises(BundleError) as ctx:
            unpack_bundle(self.bundle, self.tmp / "out", max_entries=3)
        self.assertIn("条目数超限", str(ctx.exception))

    def test_total_bytes_limit(self) -> None:
        self._make_zip(entries=2, payload=b"x" * 1000)
        with self.assertRaises(BundleError) as ctx:
            unpack_bundle(self.bundle, self.tmp / "out", max_bytes=100)
        self.assertIn("解压后大小超限", str(ctx.exception))

    def test_within_limits_ok(self) -> None:
        self._make_zip(entries=2, payload=b"x" * 10)
        meta = unpack_bundle(self.bundle, self.tmp / "out", max_bytes=1 << 20, max_entries=10)
        self.assertIsInstance(meta, dict)
        self.assertTrue((self.tmp / "out" / "f0.bin").is_file())


if __name__ == "__main__":
    unittest.main()
