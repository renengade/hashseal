"""Node DOM 垫片：全部 GUI 表单与典型结果渲染回归（防空白页类问题）。"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from hashseal.gui.commands import specs_for_frontend

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "src" / "hashseal" / "gui" / "static"
SHIM = Path(__file__).resolve().parent / "gui_dom_shim.mjs"
NODE = shutil.which("node")


@unittest.skipUnless(NODE, "需要 node 运行 GUI 表单渲染回归")
class GuiJsFormTest(unittest.TestCase):
    def test_all_forms_and_results_render(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hashseal-forms-") as tmp:
            work = Path(tmp)
            for name in ("ui.js", "api.js"):
                shutil.copy2(STATIC / name, work / name)
            shutil.copy2(SHIM, work / "check.mjs")
            (work / "package.json").write_text('{"type":"module"}\n', encoding="utf-8")
            specs = specs_for_frontend(openssl=True)
            specs_path = work / "specs.json"
            specs_path.write_text(
                json.dumps(specs, ensure_ascii=False), encoding="utf-8"
            )
            result = subprocess.run(
                [NODE, str(work / "check.mjs"), str(specs_path)],
                check=False,
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.assertEqual(
                result.returncode,
                0,
                (result.stdout or "") + (result.stderr or ""),
            )
            self.assertIn("OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
