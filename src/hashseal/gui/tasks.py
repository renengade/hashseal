"""GUI 任务队列：单工作线程串行执行 CLI 命令。

串行化的目的：
- 重定向 stdout/stderr 只发生在工作线程，不会与 HTTP 日志互相污染；
- 避免 GUI 并发写 .sig / 审计日志；
- 私钥口令只在任务对象里短暂存在，执行前剥离。
"""

from __future__ import annotations

import io
import threading
import uuid
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .. import cli
from ..result import CommandContext

MAX_OUTPUT_CHARS = 16_000
TERMINAL_STATES = ("succeeded", "failed", "canceled")


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class Task:
    id: str
    command: str
    argv: list[str]
    state: str = "queued"  # queued | running | succeeded | failed | canceled
    rc: int | None = None
    created: str = field(default_factory=_now)
    started: str | None = None
    finished: str | None = None
    progress: dict[str, Any] | None = None
    result: dict[str, Any] | None = None
    warnings: list[str] = field(default_factory=list)
    error: str | None = None
    output: str = ""
    cancel_requested: bool = False
    cancelable: bool = False
    password: str | None = None
    remember_key: str | None = None
    cancel_event: threading.Event = field(default_factory=threading.Event)

    def to_dict(self, *, include_argv: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id,
            "command": self.command,
            "state": self.state,
            "rc": self.rc,
            "created": self.created,
            "started": self.started,
            "finished": self.finished,
            "progress": self.progress,
            "result": self.result,
            "warnings": self.warnings,
            "error": self.error,
            "output": self.output,
            "cancelable": self.cancelable,
            "cancel_requested": self.cancel_requested,
        }
        if include_argv:
            payload["argv"] = self.argv
        return payload


class TaskQueue:
    """FIFO 队列 + 单工作线程；任务结果保留有限份，过期清理。"""

    def __init__(
        self,
        *,
        vault: Any | None = None,
        config: dict | None = None,
        max_tasks: int = 100,
        retain_seconds: int = 3600,
    ) -> None:
        self.vault = vault
        self.config = config or {}
        self.max_tasks = max_tasks
        self.retain_seconds = retain_seconds
        self._cond = threading.Condition()
        self._queue: list[Task] = []
        self._tasks: dict[str, Task] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ---- 生命周期 ------------------------------------------------------- #
    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._worker_loop, name="hashseal-gui-tasks", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        with self._cond:
            self._cond.notify_all()
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def busy(self) -> bool:
        with self._cond:
            return any(t.state in ("queued", "running") for t in self._tasks.values())

    # ---- 提交 / 查询 ---------------------------------------------------- #
    def submit(
        self,
        command: str,
        argv: list[str],
        *,
        password: str | None = None,
        remember_key: str | None = None,
        cancelable: bool = False,
    ) -> Task:
        task = Task(
            id="t_" + uuid.uuid4().hex[:12],
            command=command,
            argv=list(argv),
            password=password,
            remember_key=remember_key,
            cancelable=cancelable,
        )
        with self._cond:
            self._tasks[task.id] = task
            self._queue.append(task)
            self._prune_locked()
            self._cond.notify_all()
        return task

    def get(self, task_id: str) -> Task | None:
        with self._cond:
            return self._tasks.get(task_id)

    def list(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._cond:
            tasks = sorted(self._tasks.values(), key=lambda t: t.created, reverse=True)
        return [t.to_dict(include_argv=False) for t in tasks[: max(0, limit)]]

    def cancel(self, task_id: str) -> bool:
        task = self.get(task_id)
        if task is None:
            return False
        if task.state in ("queued", "running"):
            task.cancel_requested = True
            task.cancel_event.set()
            return True
        return False

    def _prune_locked(self) -> None:
        now = datetime.now(timezone.utc)
        for task_id in list(self._tasks):
            task = self._tasks[task_id]
            if task.state not in TERMINAL_STATES:
                continue
            finished = task.finished or task.created
            try:
                age = (now - datetime.fromisoformat(finished)).total_seconds()
            except ValueError:
                age = 0
            expired = age > self.retain_seconds
            if (expired or len(self._tasks) > self.max_tasks) and task.state in TERMINAL_STATES:
                del self._tasks[task_id]

    # ---- 工作线程 -------------------------------------------------------- #
    def _worker_loop(self) -> None:
        while not self._stop.is_set():
            with self._cond:
                while not self._queue and not self._stop.is_set():
                    self._cond.wait(timeout=0.5)
                if self._stop.is_set():
                    return
                task = self._queue.pop(0)
            self._run_one(task)

    def _run_one(self, task: Task) -> None:
        task.state = "running"
        task.started = _now()
        password = task.password
        task.password = None  # 任务对象里永远不留口令

        ctx = CommandContext(
            source="gui",
            password=password,
            interactive=False,
            collect=True,
            progress=lambda stage, done, total: self._set_progress(task, stage, done, total),
            cancel=task.cancel_event,
        )
        out, err = io.StringIO(), io.StringIO()
        try:
            with redirect_stdout(out), redirect_stderr(err):
                try:
                    rc = cli.main(task.argv, context=ctx)
                except SystemExit as exc:  # die() / argparse
                    rc = int(exc.code or 0)
            task.rc = rc
            task.result = ctx.result
            task.warnings = ctx.warnings
            task.error = ctx.error
            if ctx.cancelled():
                task.state = "canceled"
            elif rc == 0:
                task.state = "succeeded"
            else:
                task.state = "failed"
        except BaseException as exc:  # noqa: BLE001 - 兜底：绝不让工作线程死亡
            task.state = "failed"
            task.rc = task.rc if task.rc is not None else 1
            task.error = str(exc) or exc.__class__.__name__
        combined = out.getvalue() + err.getvalue()
        task.output = combined[-MAX_OUTPUT_CHARS:]
        task.finished = _now()

        # 口令善后：成功且要求记住 → 存入 vault；解密失败 → 丢弃旧口令
        if self.vault is not None and task.remember_key:
            if task.state == "succeeded" and password:
                self.vault.put(task.remember_key, password)
            elif task.state == "failed" and task.error and "无法解密" in task.error:
                self.vault.drop(task.remember_key)

        # 失败审计统一由 cli.main 的 command_failed 记录（含 CLI/GUI），此处不重复

    @staticmethod
    def _set_progress(task: Task, stage: str, done: int, total: int) -> None:
        task.progress = {"stage": stage, "done": done, "total": total}
