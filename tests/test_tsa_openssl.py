"""无 openssl 时的 TSA 证书链行为：明确报错 / 明确 skipped。"""

from __future__ import annotations

import hashlib
import unittest
from pathlib import Path
from unittest import mock

from hashseal.tsa import OPENSSL_MISSING_HINT, TimestampError, check_token, openssl_available

FIXTURES = Path(__file__).resolve().parent / "fixtures"
TOKEN = FIXTURES / "app.py.sig.tsr"
DATA = FIXTURES / "app.py.sig"
CA = FIXTURES / "freetsa_ca.pem"


@unittest.skipUnless(TOKEN.is_file() and DATA.is_file(), "缺少 TSA 测试夹具")
class TsaOpensslTest(unittest.TestCase):
    def _digest(self) -> bytes:
        return hashlib.sha256(DATA.read_bytes()).digest()

    def test_strict_chain_without_openssl_has_clear_error(self) -> None:
        with (
            mock.patch("hashseal.tsa._openssl_chain", return_value="unavailable（未找到 openssl）"),
            self.assertRaises(TimestampError) as ctx,
        ):
            check_token(
                TOKEN.read_bytes(),
                self._digest(),
                data_path=DATA,
                ca_pem=CA.read_bytes(),
                ca_label="test-ca",
                chain_required=True,
            )
        self.assertIn("未安装 openssl", str(ctx.exception))
        self.assertIn("--allow-unverified-chain", str(ctx.exception))

    def test_non_strict_chain_without_openssl_skips_with_note(self) -> None:
        with mock.patch("hashseal.tsa._openssl_chain", return_value="unavailable（未找到 openssl）"):
            info = check_token(
                TOKEN.read_bytes(),
                self._digest(),
                data_path=DATA,
                ca_pem=CA.read_bytes(),
                ca_label="test-ca",
                chain_required=False,
            )
        self.assertEqual(info["ok"], True)
        self.assertIn("未安装 openssl", info["chain"])

    def test_openssl_available_is_bool(self) -> None:
        self.assertIsInstance(openssl_available(), bool)
        self.assertIn("openssl", OPENSSL_MISSING_HINT)


if __name__ == "__main__":
    unittest.main()
