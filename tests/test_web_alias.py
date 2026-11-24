"""hashseal web 别名 = gui 子命令。"""

from __future__ import annotations

import unittest

from hashseal.cli import build_parser, cmd_gui


class WebAliasTest(unittest.TestCase):
    def test_web_alias_maps_to_gui(self) -> None:
        for argv in (["web", "--no-browser"], ["gui", "--no-browser"]):
            with self.subTest(argv=argv):
                args = build_parser().parse_args(argv)
                self.assertIs(args.func, cmd_gui)
                self.assertTrue(args.no_browser)

    def test_alias_default_port_zero(self) -> None:
        args = build_parser().parse_args(["web"])
        self.assertEqual(args.port, 0)
        self.assertFalse(args.read_only)


if __name__ == "__main__":
    unittest.main()
