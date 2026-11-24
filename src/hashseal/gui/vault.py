"""口令内存保管（Vault）：私钥口令只存在于进程内存，绝不落盘、不进日志。"""

from __future__ import annotations

import threading
from pathlib import Path

from ..core import load_private, public_fingerprint


class PasswordVault:
    """按“私钥绝对路径 → 口令”保存；锁定/进程退出即清空。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, str] = {}

    @staticmethod
    def _key(path: Path | str) -> str:
        return str(Path(path).expanduser().resolve())

    def get(self, key_path: Path | str) -> str | None:
        with self._lock:
            return self._entries.get(self._key(key_path))

    def put(self, key_path: Path | str, password: str) -> None:
        with self._lock:
            self._entries[self._key(key_path)] = password

    def drop(self, key_path: Path | str) -> None:
        with self._lock:
            self._entries.pop(self._key(key_path), None)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def keys(self) -> list[str]:
        with self._lock:
            return list(self._entries)

    def unlock(self, key_path: Path | str, password: str) -> str:
        """校验口令可以解密后保存；返回公钥指纹。失败抛 SystemExit。"""
        path = Path(key_path).expanduser()
        key = load_private(path, password)
        fingerprint = public_fingerprint(key.public_key())
        self.put(path, password)
        return fingerprint
