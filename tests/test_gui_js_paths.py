"""Windows/POSIX 路径工具单测（Node 直接加载 ui.js 的导出函数）。"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "src" / "hashseal" / "gui" / "static"
NODE = shutil.which("node")

SCRIPT = r'''
import { basename, joinPath, dirname, splitPathParts, pathSep } from "./ui.js";

const eq = (actual, expected, label) => {
  if (actual !== expected) {
    console.error(`FAIL ${label}: ${JSON.stringify(actual)} != ${JSON.stringify(expected)}`);
    process.exit(1);
  }
};
const deep = (actual, expected, label) => {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    console.error(`FAIL ${label}: ${JSON.stringify(actual)} != ${JSON.stringify(expected)}`);
    process.exit(1);
  }
};

eq(basename("C:\\Users\\me\\key.pem"), "key.pem", "basename win");
eq(basename("/home/me/key.pem"), "key.pem", "basename posix");
eq(basename("C:\\Users\\me\\"), "me", "basename trailing sep");
eq(joinPath("C:\\Users\\me", "a.zip"), "C:\\Users\\me\\a.zip", "joinPath win");
eq(joinPath("C:/Users/me", "a.zip"), "C:/Users/me/a.zip", "joinPath win fwd");
eq(joinPath("C:\\Users\\me\\", "a.zip"), "C:\\Users\\me\\a.zip", "joinPath trailing");
eq(joinPath("/home/me", "a.zip"), "/home/me/a.zip", "joinPath posix");
eq(dirname("C:\\Users\\me\\key.pem"), "C:\\Users\\me", "dirname win");
eq(dirname("C:\\key.pem"), "C:\\", "dirname drive root");
eq(dirname("/a/b/c"), "/a/b", "dirname posix");
eq(dirname("\\\\server\\share\\dir\\f.txt"), "\\\\server\\share\\dir", "dirname unc");
eq(pathSep("C:\\x"), "\\", "pathSep win");
eq(pathSep("/x"), "/", "pathSep posix");
deep(splitPathParts("C:\\Users\\me"), { prefix: "C:", restParts: ["Users", "me"] }, "split win");
deep(splitPathParts("\\\\server\\share\\dir"), { prefix: "\\\\server\\share", restParts: ["dir"] }, "split unc");
deep(splitPathParts("/a/b"), { prefix: "", restParts: ["a", "b"] }, "split posix");
console.log("OK");
'''


@unittest.skipUnless(NODE, "需要 node 运行 JS 路径单测")
class GuiJsPathTest(unittest.TestCase):
    def test_windows_and_posix_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hashseal-js-") as tmp:
            work = Path(tmp)
            for name in ("ui.js", "api.js"):
                shutil.copy2(STATIC / name, work / name)
            (work / "package.json").write_text('{"type":"module"}\n', encoding="utf-8")
            (work / "check.mjs").write_text(SCRIPT, encoding="utf-8")
            result = subprocess.run(
                [NODE, str(work / "check.mjs")],
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(
                result.returncode,
                0,
                (result.stdout or "") + (result.stderr or ""),
            )
            self.assertIn("OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
