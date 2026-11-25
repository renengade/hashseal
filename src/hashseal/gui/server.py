"""hashseal gui 服务：仅绑定 127.0.0.1 的本地 Web 服务。

安全模型：
- 每次启动生成 32 字节随机 token，前端通过 URL fragment 携带，
  所有 /api/* 请求必须带 X-Hashseal-Token 头；
- Host / Origin / Sec-Fetch-Site 三重同源校验（防 DNS rebinding 与 CSRF）；
- 所有路径必须位于 RootSet 内（防路径穿越）；
- 静态资源白名单 + 严格 CSP，无外链、无内联脚本。
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import threading
import time
import webbrowser
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .. import __version__
from ..audit import audit_path, read_events
from ..config import config_path, load_config
from ..core import die, is_encrypted_key
from ..tsa import openssl_available
from . import commands as gui_commands
from .security import (
    ApiError,
    RootSet,
    allowed_hosts,
    allowed_origins,
    new_token,
    token_ok,
)
from .tasks import TaskQueue
from .vault import PasswordVault

MAX_BODY = 1 << 20  # 1 MiB
MAX_AUDIT_LINES = 500
STATIC_DIR = Path(__file__).with_name("static")

STATIC_FILES: dict[str, tuple[str, str]] = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/api.js": ("api.js", "text/javascript; charset=utf-8"),
    "/ui.js": ("ui.js", "text/javascript; charset=utf-8"),
    "/theme.js": ("theme.js", "text/javascript; charset=utf-8"),
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
}

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)


@dataclass
class GuiSettings:
    port: int = 0
    open_browser: bool = True
    roots: list[Path] = field(default_factory=list)
    read_only: bool = False
    idle_timeout_minutes: float = 30.0
    vault_timeout_minutes: float = 0.0
    config: dict = field(default_factory=dict)
    restrict_roots: bool = False  # 默认放开整机文件系统（token 保护）；True 则仅 roots


class GuiServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        addr: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        *,
        settings: GuiSettings,
        roots: RootSet,
        token: str,
        tasks: TaskQueue,
        vault: PasswordVault,
    ) -> None:
        self.settings = settings
        self.roots = roots
        self.token = token
        self.tasks = tasks
        self.vault = vault
        super().__init__(addr, handler)
        self.port = self.server_address[1]
        self.log_stream = sys.stderr
        self.started_at = time.monotonic()
        self.last_activity = time.monotonic()
        self.shutdown_event = threading.Event()
        self._auth_failures: list[float] = []
        self._auth_lock = threading.Lock()

    def note_auth_failure(self) -> bool:
        """记录鉴权失败；1 分钟内超过阈值返回 True（应限流）。"""
        now = time.monotonic()
        with self._auth_lock:
            self._auth_failures = [t for t in self._auth_failures if now - t < 60]
            self._auth_failures.append(now)
            return len(self._auth_failures) > 30


class GuiHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "hashseal"
    sys_version = ""
    timeout = 30

    # ---- 日志 ------------------------------------------------------------- #
    def log_message(self, fmt: str, *args: object) -> None:
        stream = getattr(self.server, "log_stream", sys.stderr)
        print(f"[gui] {fmt % args}", file=stream)

    def log_request(self, code: object = "-", size: object = "-") -> None:
        path = urlsplit(self.path).path
        self.log_message('%s "%s" %s', self.command, path, str(code))

    def version_string(self) -> str:
        return self.server_version

    # ---- 入口 ------------------------------------------------------------- #
    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")

    def do_HEAD(self) -> None:
        # 静态资源支持 HEAD；API 不需要
        url = urlsplit(self.path)
        if url.path in STATIC_FILES and self.command == "HEAD":
            try:
                name, _ctype = STATIC_FILES[url.path]
                data = (STATIC_DIR / name).read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", _ctype)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self._security_headers()
                self.end_headers()
            except ApiError as exc:
                self._send_json(exc.to_dict(), exc.status)
            except OSError:
                self._send_json({"error": {"code": "not_found", "message": "静态资源不存在"}}, 404)
            return
        self.send_error(405, "Method Not Allowed")

    def _handle(self, method: str) -> None:
        try:
            url = urlsplit(self.path)
            if url.path == "/api" or url.path.startswith("/api/"):
                self._route_api(method, parse_qs(url.query))
            elif method == "GET":
                self._serve_static(url.path)
            else:
                raise ApiError(405, "method_not_allowed", "不支持的请求方法")
        except ApiError as exc:
            self._send_json(exc.to_dict(), exc.status)
        except BrokenPipeError:
            pass
        except Exception as exc:  # noqa: BLE001 - 兜底：意外错误不回传堆栈
            print(f"[gui] 内部错误: {exc!r}", file=getattr(self.server, "log_stream", sys.stderr))
            self._send_json(
                {"error": {"code": "internal", "message": "内部错误，详情见服务端日志"}}, 500
            )

    # ---- 安全门 ----------------------------------------------------------- #
    def _api_guard(self, method: str) -> None:
        server: GuiServer = self.server  # type: ignore[assignment]
        port = server.port
        host = self.headers.get("Host", "")
        if host not in allowed_hosts(port):
            raise ApiError(403, "bad_host", "Host 不合法（已拒绝，防 DNS rebinding）")
        origin = self.headers.get("Origin")
        if origin and origin not in allowed_origins(port):
            raise ApiError(403, "bad_origin", "Origin 不合法")
        fetch_site = self.headers.get("Sec-Fetch-Site")
        if fetch_site and fetch_site not in ("same-origin", "none"):
            raise ApiError(403, "bad_origin", "跨站请求被拒绝")
        if not token_ok(server.token, self.headers.get("X-Hashseal-Token")):
            if server.note_auth_failure():
                raise ApiError(429, "rate_limited", "鉴权失败过于频繁，请稍后重试")
            raise ApiError(401, "unauthorized", "会话无效，请使用终端中显示的地址重新打开")
        if method == "POST":
            ctype = self.headers.get("Content-Type", "")
            if not ctype.lower().startswith("application/json"):
                raise ApiError(415, "unsupported_media_type", "POST 必须是 application/json")

    # ---- API 路由 --------------------------------------------------------- #
    def _route_api(self, method: str, query: dict[str, list[str]]) -> None:
        self._check_idle()
        self.server.last_activity = time.monotonic()  # type: ignore[attr-defined]
        self._api_guard(method)

        server: GuiServer = self.server  # type: ignore[assignment]
        path = urlsplit(self.path).path
        cfg = load_config()

        if method == "GET":
            if path == "/api/status":
                return self._send_json(self._status_payload())
            if path == "/api/commands":
                return self._send_json(
                    {
                        "sections": gui_commands.SECTIONS,
                        "section_commands": gui_commands.SECTION_COMMANDS,
                        "commands": gui_commands.specs_for_frontend(
                            config=cfg,
                            cwd=Path.cwd(),
                            roots=server.roots,
                            openssl=openssl_available(),
                        ),
                    }
                )
            if path == "/api/config":
                return self._send_json({"path": str(config_path()), "config": cfg})
            if path == "/api/browse":
                return self._api_browse(query)
            if path == "/api/audit":
                return self._api_audit(query)
            if path == "/api/key-info":
                return self._api_key_info(query)
            if path == "/api/vault":
                return self._send_json({"keys": server.vault.keys()})
            if path == "/api/tasks":
                return self._send_json({"tasks": server.tasks.list(50)})
            if path == "/api/ping":
                return self._send_json({"ok": True, "version": __version__})
            if path.startswith("/api/tasks/"):
                task = server.tasks.get(path[len("/api/tasks/") :])
                if task is None:
                    raise ApiError(404, "not_found", "任务不存在或已过期")
                return self._send_json(task.to_dict())
            raise ApiError(404, "not_found", "接口不存在")

        # POST
        body = self._read_json()
        if path == "/api/run":
            return self._api_run(body)
        if path == "/api/vault/unlock":
            return self._api_vault_unlock(body)
        if path == "/api/vault/lock":
            key = body.get("key")
            if key:
                server.vault.drop(str(key))
            else:
                server.vault.clear()
            return self._send_json({"ok": True, "keys": server.vault.keys()})
        if path.startswith("/api/tasks/") and path.endswith("/cancel"):
            task_id = path[len("/api/tasks/") : -len("/cancel")]
            ok = server.tasks.cancel(task_id)
            return self._send_json({"ok": ok})
        if path == "/api/shutdown":
            if server.tasks.busy():
                raise ApiError(409, "busy", "有任务正在运行，请等待完成后再退出")
            self._send_json({"ok": True})
            threading.Thread(target=server.shutdown, daemon=True).start()
            return
        raise ApiError(404, "not_found", "接口不存在")

    # ---- 具体端点 ---------------------------------------------------------- #
    def _status_payload(self) -> dict:
        server: GuiServer = self.server  # type: ignore[assignment]
        cfg = load_config()
        return {
            "version": __version__,
            "python": platform.python_version(),
            "platform": platform.system().lower(),
            "openssl": openssl_available(),
            "read_only": server.settings.read_only,
            "roots": server.roots.display,
            "config_path": str(config_path()),
            "audit_path": str(audit_path()),
            "vault": {"keys": server.vault.keys()},
            "restrict_roots": server.settings.restrict_roots,
            "idle_timeout_minutes": server.settings.idle_timeout_minutes,
            "vault_timeout_minutes": server.settings.vault_timeout_minutes,
            "config": cfg,
        }

    def _api_run(self, body: dict) -> None:
        server: GuiServer = self.server  # type: ignore[assignment]
        command_name = body.get("command")
        if not isinstance(command_name, str):
            raise ApiError(400, "bad_request", "缺少 command")
        command = gui_commands.get(command_name)
        if server.settings.read_only and command.mutating:
            raise ApiError(
                403,
                "read_only",
                "只读模式：该操作已被禁用",
                hint="以 hashseal gui（不带 --read-only）启动可解除",
            )
        if not isinstance(body.get("options"), dict):
            raise ApiError(400, "bad_request", "options 必须是对象")
        config = load_config()
        prepared = gui_commands.prepare(command, body["options"], server.roots, config)
        if not prepared.password:
            # vault 已记住该私钥的口令 → 自动取用；失败时同样会被丢弃
            key_path = gui_commands.key_path_for(command.name, body["options"], config)
            if key_path:
                stored = server.vault.get(key_path)
                if stored:
                    prepared.password = stored
                    prepared.remember_key = key_path
        task = server.tasks.submit(
            command.name,
            prepared.argv,
            password=prepared.password,
            remember_key=prepared.remember_key,
            cancelable=command.cancelable,
        )
        self._send_json({"task_id": task.id}, 202)

    def _api_vault_unlock(self, body: dict) -> None:
        server: GuiServer = self.server  # type: ignore[assignment]
        raw = body.get("key")
        password = body.get("password")
        if not isinstance(raw, str) or not isinstance(password, str):
            raise ApiError(400, "bad_request", "需要 key 与 password")
        key_path = server.roots.require_readable(raw, label="私钥路径")
        try:
            fingerprint = server.vault.unlock(key_path, password)
        except SystemExit:
            raise ApiError(400, "bad_password", "无法解密私钥（口令错误或文件损坏）") from None
        self._send_json({"ok": True, "key": str(key_path), "fingerprint": fingerprint})

    def _api_audit(self, query: dict[str, list[str]]) -> None:
        try:
            lines_param = int((query.get("lines") or ["100"])[0])
        except ValueError:
            lines_param = 100
        lines_param = max(1, min(lines_param, MAX_AUDIT_LINES))
        events = read_events(audit_path(), lines_param)
        parsed = []
        for line in reversed(events):  # 新的在前
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                record = {"raw": line}
            parsed.append(record)
        self._send_json({"path": str(audit_path()), "events": parsed})

    def _api_key_info(self, query: dict[str, list[str]]) -> None:
        """私钥状态校验：是否存在、是否加密、口令是否已记住。"""
        server: GuiServer = self.server  # type: ignore[assignment]
        raw = (query.get("key") or [""])[0]
        key_path = server.roots.require_inside(raw, label="私钥路径")
        if not key_path.exists():
            return self._send_json(
                {
                    "key": str(key_path),
                    "exists": False,
                    "encrypted": False,
                    "remembered": False,
                }
            )
        self._send_json(
            {
                "key": str(key_path),
                "exists": True,
                "encrypted": is_encrypted_key(key_path),
                "remembered": server.vault.get(key_path) is not None,
            }
        )

    def _shortcuts(self) -> list[dict]:
        server: GuiServer = self.server  # type: ignore[assignment]
        home = Path.home()
        candidates = (
            ("主目录", home),
            ("桌面", home / "Desktop"),
            ("下载", home / "Downloads"),
            ("文档", home / "Documents"),
        )
        out: list[dict] = []
        seen: set[str] = set()
        for label, path in candidates:
            try:
                if not path.is_dir():
                    continue
                resolved = str(path.resolve())
            except OSError:
                continue
            if not server.roots.contains(Path(resolved)) or resolved in seen:
                continue
            seen.add(resolved)
            out.append({"label": label, "path": resolved})
        mnt = Path("/mnt")
        if _is_wsl() and mnt.is_dir() and server.roots.contains(mnt):
            out.append({"label": "Windows 磁盘", "path": "/mnt"})
        if os.name == "nt":
            for drive in _system_roots():
                resolved = str(drive)
                if resolved in seen or not server.roots.contains(drive):
                    continue
                seen.add(resolved)
                out.append({"label": resolved.rstrip("\\/") + " 盘", "path": resolved})
        return out

    def _api_browse(self, query: dict[str, list[str]]) -> None:
        server: GuiServer = self.server  # type: ignore[assignment]
        roots = server.roots
        raw = (query.get("path") or [""])[0]
        hidden = (query.get("hidden") or ["0"])[0] in ("1", "true")
        visible_roots = (
            roots.display
            if server.settings.restrict_roots
            else [r for r in roots.display if not _is_system_root_path(r)]
        )
        if not raw:
            return self._send_json(
                {
                    "path": None,
                    "parent": None,
                    "roots": roots.display,
                    "display_roots": visible_roots,
                    "shortcuts": self._shortcuts(),
                    "entries": [],
                }
            )
        target = roots.require_inside(raw, label="路径")
        if not target.exists():
            raise ApiError(404, "not_found", f"路径不存在: {raw}")
        if not target.is_dir():
            raise ApiError(400, "not_a_directory", f"不是目录: {raw}")
        try:
            children = sorted(target.iterdir(), key=lambda c: (not c.is_dir(), c.name.lower()))
        except OSError as exc:
            raise ApiError(403, "forbidden", f"无法读取目录: {exc}") from exc
        entries = []
        for child in children:
            name = child.name
            if not hidden and name.startswith("."):
                continue
            try:
                st = child.lstat()
                is_dir = child.is_dir()
            except OSError:
                continue
            entries.append(
                {
                    "name": name,
                    "path": str(child),
                    "kind": "dir" if is_dir else "file",
                    "symlink": child.is_symlink(),
                    "size": 0 if is_dir else st.st_size,
                    "mtime": st.st_mtime,
                    "navigable": is_dir and roots.contains(child),
                }
            )
        parent = target.parent
        self._send_json(
            {
                "path": str(target),
                "parent": str(parent) if roots.contains(parent) else None,
                "roots": roots.display,
                "display_roots": visible_roots,
                "shortcuts": self._shortcuts(),
                "entries": entries,
            }
        )

    # ---- 工具方法 ---------------------------------------------------------- #
    def _read_json(self) -> dict:
        if self.headers.get("Transfer-Encoding"):
            raise ApiError(400, "bad_request", "不支持 Transfer-Encoding")
        length = self.headers.get("Content-Length")
        if length is None:
            raise ApiError(411, "length_required", "缺少 Content-Length")
        try:
            n = int(length)
        except ValueError:
            raise ApiError(400, "bad_request", "Content-Length 无效") from None
        if n < 0 or n > MAX_BODY:
            # 超限：小体积先排干请求体再回 413（否则客户端写被重置、读不到响应）；
            # 巨大声明直接断开。
            if n <= (8 << 20):
                remaining = n
                while remaining > 0:
                    chunk = self.rfile.read(min(65536, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
            else:
                self.close_connection = True
            raise ApiError(413, "too_large", f"请求体超过 {MAX_BODY} 字节上限")
        raw = b""
        while len(raw) < n:
            chunk = self.rfile.read(n - len(raw))
            if not chunk:
                break
            raw += chunk
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ApiError(400, "bad_request", "JSON 解析失败") from None
        if not isinstance(data, dict):
            raise ApiError(400, "bad_request", "请求体必须是 JSON 对象")
        return data

    def _check_idle(self) -> None:
        server: GuiServer = self.server  # type: ignore[assignment]
        settings = server.settings
        idle_seconds = time.monotonic() - server.last_activity
        if server.tasks.busy():
            return
        idle_exceeded = (
            settings.idle_timeout_minutes > 0
            and idle_seconds > settings.idle_timeout_minutes * 60
            and not server.shutdown_event.is_set()
        )
        if idle_exceeded:
            server.shutdown_event.set()
            threading.Thread(target=server.shutdown, daemon=True).start()
        if (
            settings.vault_timeout_minutes > 0
            and idle_seconds > settings.vault_timeout_minutes * 60
        ):
            server.vault.clear()

    def _serve_static(self, path: str) -> None:
        entry = STATIC_FILES.get(path)
        if entry is None:
            raise ApiError(404, "not_found", "静态资源不存在")
        name, ctype = entry
        data = (STATIC_DIR / name).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self._security_headers()
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, payload: dict, status: int = 200) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self._security_headers()
        self.end_headers()
        self.wfile.write(data)

    def _security_headers(self) -> None:
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")


# --------------------------------------------------------------------------- #
# 启动
# --------------------------------------------------------------------------- #


def _default_roots(extra: list[Path]) -> list[Path]:
    roots: list[Path] = [Path.home()]
    cwd = Path.cwd()
    if cwd not in roots:
        roots.append(cwd)
    for root in extra:
        if root not in roots:
            roots.append(root)
    return roots


def _is_system_root_path(path: str) -> bool:
    """是否为文件系统根（POSIX "/" 或 Windows 盘符根）。"""
    if os.name == "nt":
        stripped = path.rstrip("\\/")
        return len(stripped) == 2 and stripped[1] == ":" and stripped[0].isalpha()
    return path == "/"


def _system_roots() -> list[Path]:
    """系统级浏览入口：POSIX 为 /，Windows 为所有存在的盘符。"""
    roots: list[Path] = []
    if os.name == "nt":
        import string

        for letter in string.ascii_uppercase:
            drive = Path(f"{letter}:\\")
            try:
                if drive.exists():
                    roots.append(drive)
            except OSError:
                continue
    else:
        roots.append(Path("/"))
    return roots


def _is_wsl() -> bool:
    if os.environ.get("WSL_DISTRO_NAME"):
        return True
    try:
        return "microsoft" in platform.release().lower()
    except (AttributeError, OSError):  # pragma: no cover
        return False


def _open_browser(url: str) -> None:
    """WSL 下优先用 cmd.exe start（explorer.exe 对带 #fragment 的 URL 会打开文件管理器）。"""
    opened = False
    if _is_wsl():
        candidates: list[tuple[str, tuple[str, ...]]] = []
        wslview = shutil.which("wslview")
        if wslview:
            candidates.append(("wslview", (wslview, url)))
        cmd = shutil.which("cmd.exe") or "/mnt/c/Windows/System32/cmd.exe"
        if cmd and Path(cmd).exists():
            candidates.append(("cmd", (cmd, "/c", "start", "", url)))
        explorer = shutil.which("explorer.exe") or "/mnt/c/Windows/explorer.exe"
        if explorer and Path(explorer).exists():
            candidates.append(("explorer", (explorer, url)))
        for name, argv in candidates:
            try:
                subprocess.Popen(
                    argv,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                opened = True
                break
            except OSError:
                continue
    if not opened:
        try:
            opened = webbrowser.open(url)
        except webbrowser.Error:  # pragma: no cover
            opened = False
    if not opened:
        print("[gui] 无法自动打开浏览器，请手动复制上面的地址", flush=True)


def build(
    settings: GuiSettings,
) -> tuple[GuiServer, str, str]:
    """创建服务器（不进入主循环），返回 (server, url, token)。供 serve/测试复用。"""
    token = new_token()
    root_list = _default_roots(list(settings.roots))
    if not settings.restrict_roots:
        for system_root in _system_roots():
            if system_root not in root_list:
                root_list.append(system_root)
    roots = RootSet(root_list)
    vault = PasswordVault()
    tasks = TaskQueue(vault=vault, config=settings.config)
    try:
        server = GuiServer(
            ("127.0.0.1", settings.port),
            GuiHandler,
            settings=settings,
            roots=roots,
            token=token,
            tasks=tasks,
            vault=vault,
        )
    except OSError as exc:
        die(f"无法绑定 127.0.0.1:{settings.port}: {exc}")
    tasks.start()
    url = f"http://127.0.0.1:{server.port}/#token={token}"
    return server, url, token


def _idle_monitor(server: GuiServer) -> None:
    while not server.shutdown_event.is_set():
        time.sleep(15)
        settings = server.settings
        idle = time.monotonic() - server.last_activity
        if server.tasks.busy():
            continue
        if settings.idle_timeout_minutes > 0 and idle > settings.idle_timeout_minutes * 60:
            server.shutdown_event.set()
            threading.Thread(target=server.shutdown, daemon=True).start()
            return
        if settings.vault_timeout_minutes > 0 and idle > settings.vault_timeout_minutes * 60:
            server.vault.clear()


def serve(settings: GuiSettings) -> int:
    server, url, _token = build(settings)
    print("hashseal GUI 已启动（仅本机）", flush=True)
    print(f"  地址: {url}", flush=True)
    print(f"  根目录: {', '.join(server.roots.display)}", flush=True)
    missing = [r for r in server.roots.display if not Path(r).exists()]
    if missing:
        print(f"  警告: 以下根目录不存在，浏览时不可进入: {', '.join(missing)}", flush=True)
    if settings.read_only:
        print("  模式: 只读（签名/生成/解包等写操作已禁用）", flush=True)
    print("  按 Ctrl+C 停止", flush=True)
    if settings.open_browser:
        threading.Thread(target=_open_browser, args=(url,), daemon=True).start()
    threading.Thread(target=_idle_monitor, args=(server,), daemon=True).start()
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.tasks.stop()
        server.server_close()
    print("[gui] 已退出", flush=True)
    return 0
