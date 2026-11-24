"""安装脚本静态检查：sh 语法 + ps1 语法（PS 不可用时跳过）。"""

from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class InstallScriptTest(unittest.TestCase):
    def test_install_sh_syntax(self) -> None:
        sh = shutil.which("dash") or shutil.which("sh")
        assert sh
        result = subprocess.run([sh, "-n", str(ROOT / "install.sh")], check=False, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_install_ps1_no_bom_and_crlf(self) -> None:
        # `irm | iex` 会把 BOM 当作首行命令导致报错 → 文件必须无 BOM；
        # 落盘运行（PS5.1）需 `Get-Content -Encoding UTF8 | iex`（脚本头部已注明）。
        raw = (ROOT / "install.ps1").read_bytes()
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"), "install.ps1 不能带 UTF-8 BOM")
        text = raw.decode("utf-8")
        self.assertIn("\r\n", text, "install.ps1 应使用 CRLF")

    def test_install_ps1_powershell_syntax(self) -> None:
        exe = shutil.which("pwsh") or shutil.which("powershell")
        if exe is None:
            candidate = Path("/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
            exe = str(candidate) if candidate.exists() else None
        if exe is None:
            self.skipTest("本机无 PowerShell，跳过语法检查")
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "install.ps1"
            dest.write_bytes((ROOT / "install.ps1").read_bytes())
            win_path = subprocess.run(
                ["wslpath", "-w", str(dest)], check=False, capture_output=True, text=True
            )
            if win_path.returncode != 0:
                self.skipTest("wslpath 不可用（非 WSL 环境）")
            cmd = (
                "try { $t = Get-Content -Raw -Encoding UTF8 -LiteralPath "
                f"'{win_path.stdout.strip()}'"
                "; [void][scriptblock]::Create($t); 'OK' } catch { Write-Error $_.Exception.Message; exit 1 }"
            )
            result = subprocess.run([exe, "-NoProfile", "-Command", cmd], check=False, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout.decode() + result.stderr.decode())


if __name__ == "__main__":
    unittest.main()
