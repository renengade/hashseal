"""GUI 前端 api 契约：app/ui 里调用的每个 api.X 都必须在 api.js 中定义。"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "src" / "hashseal" / "gui" / "static"


def _api_methods() -> set[str]:
    source = (STATIC / "api.js").read_text(encoding="utf-8")
    block = source.split("export const api = {", 1)[1].split("\n};", 1)[0]
    return set(re.findall(r"^\s{2}([A-Za-z_]\w*)\s*:", block, re.MULTILINE))


class GuiApiContractTest(unittest.TestCase):
    def test_every_called_method_exists(self) -> None:
        defined = _api_methods()
        self.assertIn("tasks", defined)  # 概览「最近操作」依赖
        called: dict[str, set[str]] = {}
        for name in ("app.js", "ui.js"):
            text = (STATIC / name).read_text(encoding="utf-8")
            used = set(re.findall(r"\bapi\.([A-Za-z_]\w*)\s*\(", text))
            called[name] = used
        missing = {name: sorted(used - defined) for name, used in called.items() if used - defined}
        self.assertFalse(missing, f"api.js 缺少方法: {missing}")


if __name__ == "__main__":
    unittest.main()
