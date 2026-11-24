"""命令执行上下文：CLI 与 GUI 共用的结构化结果 / 警告 / 进度 / 取消通道。

CLI 正常运行时创建默认上下文（不收集结果，行为与历史版本完全一致）；
GUI 通过 ``cli.main(argv, context=ctx)`` 注入收集上下文，
命令函数把结构化结果写进 ``ctx.result``，GUI 无需解析人类输出。
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

ProgressFn = Callable[[str, int, int], None]
WarnSink = Callable[[str], None]


@dataclass
class CommandContext:
    """一次命令执行的上下文。"""

    source: str = "cli"
    password: str | None = None
    interactive: bool = True
    collect: bool = False
    result: dict[str, Any] | None = None
    warnings: list[str] = field(default_factory=list)
    error: str | None = None
    error_code: int = 2
    progress: ProgressFn | None = None
    cancel: threading.Event | None = None
    audited_failure: bool = False  # 命令已自行写入失败审计（避免重复）

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    def set_result(self, payload: dict[str, Any]) -> None:
        if self.collect:
            self.result = payload

    def set_progress(self, stage: str, done: int, total: int) -> None:
        if self.progress is None:
            return
        self.progress(stage, done, total)

    def cancelled(self) -> bool:
        return bool(self.cancel is not None and self.cancel.is_set())


_CTX: ContextVar[CommandContext | None] = ContextVar("hashseal_command_ctx", default=None)
_WARN_SINK: ContextVar[WarnSink | None] = ContextVar("hashseal_warn_sink", default=None)


def current() -> CommandContext | None:
    return _CTX.get()


def warn_sink() -> WarnSink | None:
    return _WARN_SINK.get()


def activate(ctx: CommandContext) -> tuple[Any, Any]:
    """在当前线程/任务上下文绑定 ctx，返回可传给 deactivate 的令牌。"""
    token_ctx = _CTX.set(ctx)
    token_sink = _WARN_SINK.set(ctx.warn if ctx.collect else None)
    return token_ctx, token_sink


def deactivate(tokens: tuple[Any, Any]) -> None:
    _WARN_SINK.reset(tokens[1])
    _CTX.reset(tokens[0])
