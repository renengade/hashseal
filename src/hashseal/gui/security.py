"""GUI 安全原语：token、同源校验、路径 jail（RootSet）、请求体限制。"""

from __future__ import annotations

import hmac
import os
import secrets
from pathlib import Path


class ApiError(Exception):
    """带 HTTP 语义的 API 错误；handler 捕获后转成 JSON 响应。"""

    def __init__(self, status: int, code: str, message: str, hint: str | None = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.hint = hint

    def to_dict(self) -> dict:
        err: dict[str, str] = {"code": self.code, "message": self.message}
        if self.hint:
            err["hint"] = self.hint
        return {"error": err}


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_ok(expected: str, got: str | None) -> bool:
    if not got:
        return False
    return hmac.compare_digest(expected, got)


def allowed_hosts(port: int) -> tuple[str, ...]:
    return (f"127.0.0.1:{port}", f"localhost:{port}")


def allowed_origins(port: int) -> tuple[str, ...]:
    return (f"http://127.0.0.1:{port}", f"http://localhost:{port}")


class RootSet:
    """允许 GUI 读写的根目录集合；所有路径必须落在其中之一。"""

    def __init__(self, roots: list[Path]):
        display: list[str] = []
        normed: list[str] = []
        for root in roots:
            resolved = root.expanduser().resolve()
            if str(resolved) not in display:
                display.append(str(resolved))
                normed.append(os.path.normcase(str(resolved)))
        self.display = display
        self._norm = normed

    def contains(self, path: Path) -> bool:
        try:
            resolved = os.path.normcase(str(path.expanduser().resolve()))
        except OSError:
            return False
        for root in self._norm:
            if resolved == root or resolved.startswith(root + os.sep):
                return True
        return False

    def require_inside(self, raw: str, *, label: str = "路径") -> Path:
        if not raw:
            raise ApiError(400, "invalid_path", f"{label}不能为空")
        if "\x00" in raw:
            raise ApiError(400, "invalid_path", f"{label}包含非法字符")
        p = Path(raw).expanduser()
        if not self.contains(p):
            raise ApiError(
                400,
                "outside_root",
                f"{label}不在允许的根目录内: {raw}",
                hint="启动时用 --root <目录> 添加该目录",
            )
        return p

    def require_readable(self, raw: str, *, label: str = "路径") -> Path:
        p = self.require_inside(raw, label=label)
        if not p.exists():
            raise ApiError(404, "not_found", f"{label}不存在: {raw}")
        return p

    def require_writable(self, raw: str, *, label: str = "输出路径") -> Path:
        p = self.require_inside(raw, label=label)
        parent = p if p.is_dir() else p.parent
        if not parent.is_dir():
            raise ApiError(400, "invalid_path", f"{label}的父目录不存在: {parent}")
        return p


def check_str(value: object, *, label: str, max_len: int = 4096) -> str:
    if not isinstance(value, str):
        raise ApiError(400, "bad_request", f"{label}必须是字符串")
    if "\x00" in value or "\n" in value or "\r" in value:
        raise ApiError(400, "bad_request", f"{label}包含非法字符")
    if len(value) > max_len:
        raise ApiError(400, "bad_request", f"{label}超过 {max_len} 字符上限")
    return value
