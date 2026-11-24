"""GUI 表单字段与 CLI parser 的一致性（防止 GUI 传入不存在的参数）。"""

from __future__ import annotations

import argparse
import unittest

from hashseal.cli import build_parser
from hashseal.gui.commands import COMMANDS


def _subparsers() -> argparse._SubParsersAction:
    parser = build_parser()
    return next(
        action
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    )


class GuiSpecParityTest(unittest.TestCase):
    def test_all_gui_commands_exist_in_cli(self) -> None:
        choices = _subparsers().choices
        for name in COMMANDS:
            with self.subTest(command=name):
                self.assertIn(name, choices)

    def test_every_field_flag_is_accepted_by_cli(self) -> None:
        subs = _subparsers()
        for name, command in COMMANDS.items():
            parser = subs.choices[name]
            options = {
                opt for action in parser._actions for opt in action.option_strings
            }
            for field in command.fields:
                if field.gui_only or field.type in ("password", "args"):
                    continue
                if field.name in command.positional:
                    continue
                flag = "--" + (field.flag or field.name.replace("_", "-"))
                with self.subTest(command=name, field=field.name, flag=flag):
                    self.assertIn(flag, options)

    def test_positional_fields_are_accepted(self) -> None:
        subs = _subparsers()
        for name, command in COMMANDS.items():
            parser = subs.choices[name]
            positionals = {
                action.dest for action in parser._actions if not action.option_strings
            }
            for field_name in command.positional:
                with self.subTest(command=name, field=field_name):
                    self.assertIn(field_name, positionals)

    def test_no_stale_gui_jobs_on_hash(self) -> None:
        # 回归：hash 的 CLI 没有 --jobs，GUI 曾错误暴露该字段
        names = {f.name for f in COMMANDS["hash"].fields}
        self.assertNotIn("jobs", names)


if __name__ == "__main__":
    unittest.main()
