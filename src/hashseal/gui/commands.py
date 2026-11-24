"""GUI 命令白名单：字段 schema、类型校验与 argv 构造。

GUI 不接受任意 argv：每个命令声明可用的字段，服务端校验后
拼装成 CLI 参数，再调用 cli.main()。前端按同一份 spec 渲染表单。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from ..config import config_path
from ..core import DEFAULT_PRIVATE, DEFAULT_PUBLIC, MANIFEST_NAME
from .security import ApiError, RootSet, check_str

# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Field:
    name: str
    type: str  # path|paths|str|int|float|bool|enum|list|password|args
    flag: str | None = None  # CLI 选项名；None = 位置参数
    label: str = ""
    help: str = ""
    required: bool = False
    advanced: bool = False
    direction: str = "in"  # in|out|any
    options: tuple[str, ...] = ()
    min: float | None = None
    max: float | None = None
    danger: bool = False
    placeholder: str = ""
    gui_only: bool = False  # 不进入 argv（password/remember）
    inline: bool = False  # 横排展示、不折叠进高级选项
    default: bool | None = None  # bool 字段预置开关值


@dataclass(frozen=True)
class Command:
    name: str
    cli: str
    section: str
    title: str
    desc: str
    mutating: bool
    fields: tuple[Field, ...]
    positional: tuple[str, ...] = ()
    cancelable: bool = False


@dataclass
class Prepared:
    argv: list[str]
    password: str | None = None
    remember_key: str | None = None


def _f(**kwargs: object) -> Field:
    return Field(**kwargs)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# 命令注册表
# --------------------------------------------------------------------------- #

_COMMAND_LIST: list[Command] = [
    Command(
        name="verify",
        cli="verify",
        section="verify",
        title="验证签名",
        desc="用可信公钥核对文件或目录是否被改过、是谁签的、时间戳是否有效",
        mutating=False,
        cancelable=False,
        positional=("file",),
        fields=(
            _f(
                name="file",
                type="path",
                label="文件或目录",
                required=True,
                help="单文件或已签名目录",
            ),
            _f(
                name="key",
                type="path",
                flag="key",
                label="公钥",
                direction="in",
                help="验证用的公钥 PEM；默认读配置或 hashseal_public.pem",
            ),
            _f(
                name="sig",
                type="path",
                flag="sig",
                label="签名文件",
                direction="in",
                advanced=True,
                help="默认与目标同名 + .sig",
            ),
            _f(
                name="tsr",
                type="path",
                flag="tsr",
                label="时间戳令牌",
                direction="in",
                advanced=True,
            ),
            _f(name="ts_only", type="bool", flag="ts-only", label="只校验时间戳", advanced=True),
            _f(
                name="name",
                type="str",
                flag="name",
                label="原文件名",
                advanced=True,
                help="文件被改名时指定签名时的名称",
            ),
            _f(
                name="expect_fingerprint",
                type="str",
                flag="expect-fingerprint",
                label="期望公钥指纹",
                advanced=True,
                placeholder="SHA256:…",
            ),
            _f(
                name="allow_unlisted",
                type="bool",
                flag="allow-unlisted",
                label="允许未列入清单的文件",
                advanced=True,
            ),
            _f(name="exclude", type="list", flag="exclude", label="排除（glob）", advanced=True),
            _f(
                name="follow_symlinks",
                type="bool",
                flag="follow-symlinks",
                label="跟随符号链接",
                advanced=True,
            ),
            _f(
                name="jobs",
                type="int",
                flag="jobs",
                label="并行线程数",
                advanced=True,
                min=1,
                max=64,
            ),
            _f(
                name="tsa_ca",
                type="path",
                flag="tsa-ca",
                label="TSA 信任根",
                direction="in",
                advanced=True,
            ),
            _f(
                name="allow_unverified_chain",
                type="bool",
                flag="allow-unverified-chain",
                label="允许未通过证书链校验",
                advanced=True,
                danger=True,
            ),
        ),
    ),
    Command(
        name="status",
        cli="status",
        section="verify",
        title="快速检查",
        desc="只核对签名与目录完整性，不请求 TSA、不联网",
        mutating=False,
        positional=("file",),
        fields=(
            _f(name="file", type="path", label="文件或目录", required=True),
            _f(name="key", type="path", flag="key", label="公钥", direction="in"),
            _f(
                name="sig", type="path", flag="sig", label="签名文件", direction="in", advanced=True
            ),
            _f(
                name="allow_unlisted",
                type="bool",
                flag="allow-unlisted",
                label="允许未列入清单的文件",
                advanced=True,
            ),
            _f(name="exclude", type="list", flag="exclude", label="排除（glob）", advanced=True),
            _f(
                name="follow_symlinks",
                type="bool",
                flag="follow-symlinks",
                label="跟随符号链接",
                advanced=True,
            ),
            _f(
                name="jobs",
                type="int",
                flag="jobs",
                label="并行线程数",
                advanced=True,
                min=1,
                max=64,
            ),
        ),
    ),
    Command(
        name="sign",
        cli="sign",
        section="sign",
        title="签名",
        desc="为文件/目录生成 .sig 分离签名，可选 RFC 3161 可信时间戳",
        mutating=True,
        cancelable=True,
        positional=("files",),
        fields=(
            _f(
                name="files",
                type="paths",
                label="文件或目录",
                required=True,
                help="可多选；目录会自动生成并签名清单",
            ),
            _f(
                name="key",
                type="path",
                flag="key",
                label="私钥",
                direction="in",
                help="默认读配置或 hashseal_private.pem",
            ),
            _f(
                name="password",
                type="password",
                label="私钥口令",
                gui_only=True,
                help="私钥已加密时必填；可选记住到退出",
            ),
            _f(
                name="remember",
                type="bool",
                label="记住口令直到退出",
                gui_only=True,
                default=True,
            ),
            _f(
                name="signer",
                type="str",
                flag="signer",
                label="署名",
                placeholder="姓名 <email>",
                help="纳入签名，防止冒用",
                inline=True,
            ),
            _f(
                name="timestamp",
                type="bool",
                flag="timestamp",
                label="申请可信时间戳",
                default=True,
            ),
            _f(name="force", type="bool", flag="force", label="覆盖已有签名", inline=True),
            _f(
                name="sig",
                type="path",
                flag="sig",
                label="签名输出路径",
                direction="out",
                inline=True,
                help="仅单文件/单目录可用",
            ),
            _f(
                name="tsr",
                type="path",
                flag="tsr",
                label="时间戳输出路径",
                direction="out",
                inline=True,
            ),
            _f(
                name="tsa",
                type="str",
                flag="tsa",
                label="TSA 地址",
                advanced=True,
                placeholder="默认 DigiCert → Sectigo → freetsa",
            ),
            _f(
                name="tsa_ca",
                type="path",
                flag="tsa-ca",
                label="TSA 信任根",
                direction="in",
                advanced=True,
            ),
            _f(
                name="timeout",
                type="float",
                flag="timeout",
                label="TSA 超时秒数",
                advanced=True,
                min=1,
                max=300,
            ),
            _f(
                name="retry",
                type="int",
                flag="retry",
                label="TSA 重试次数",
                advanced=True,
                min=0,
                max=10,
            ),
            _f(name="exclude", type="list", flag="exclude", label="排除（glob）", advanced=True),
            _f(
                name="jobs",
                type="int",
                flag="jobs",
                label="并行线程数",
                advanced=True,
                min=1,
                max=64,
            ),
            _f(
                name="follow_symlinks",
                type="bool",
                flag="follow-symlinks",
                label="跟随符号链接",
                advanced=True,
            ),
            _f(
                name="allow_unverified_chain",
                type="bool",
                flag="allow-unverified-chain",
                label="允许未通过证书链校验",
                advanced=True,
                danger=True,
            ),
        ),
    ),
    Command(
        name="keygen",
        cli="keygen",
        section="keys",
        title="生成密钥对",
        desc="生成 Ed25519 私钥/公钥；只做一次，公钥可公开分发",
        mutating=True,
        fields=(
            _f(name="private", type="path", flag="private", label="私钥输出路径", direction="out"),
            _f(name="public", type="path", flag="public", label="公钥输出路径", direction="out"),
            _f(
                name="password",
                type="password",
                label="私钥口令",
                gui_only=True,
                placeholder="≥8 位，含大小写字母/数字/特殊字符至少 3 种",
                help="留空不加密（不推荐）",
            ),
            _f(
                name="remember",
                type="bool",
                label="记住口令直到退出",
                gui_only=True,
                inline=True,
                default=True,
            ),
            _f(
                name="force",
                type="bool",
                flag="force",
                label="覆盖已有密钥",
                inline=True,
            ),
        ),
    ),
    Command(
        name="fingerprint",
        cli="fingerprint",
        section="keys",
        title="查看公钥指纹",
        desc="打印指纹，供电话/当面核对，防中间人",
        mutating=False,
        fields=(
            _f(
                name="key",
                type="path",
                flag="key",
                label="公钥 PEM",
                direction="in",
                help="默认读配置或 hashseal_public.pem",
            ),
        ),
    ),
    Command(
        name="manifest",
        cli="manifest",
        section="dirs",
        title="生成清单",
        desc="为一组文件生成 sha256sum 兼容的 MANIFEST.sha256",
        mutating=True,
        cancelable=False,
        positional=("paths",),
        fields=(
            _f(name="paths", type="paths", label="文件或目录", required=True),
            _f(
                name="output",
                type="path",
                flag="output",
                label="清单输出路径",
                direction="out",
                help="默认 MANIFEST.sha256",
                advanced=True,
            ),
            _f(
                name="base",
                type="path",
                flag="base",
                label="基准目录",
                direction="in",
                advanced=True,
                help="记录相对路径的基准",
            ),
            _f(name="exclude", type="list", flag="exclude", label="排除（glob）", advanced=True),
            _f(
                name="follow_symlinks",
                type="bool",
                flag="follow-symlinks",
                label="跟随符号链接",
                advanced=True,
            ),
            _f(
                name="jobs",
                type="int",
                flag="jobs",
                label="并行线程数",
                advanced=True,
                min=1,
                max=64,
            ),
        ),
    ),
    Command(
        name="diff",
        cli="diff",
        section="dirs",
        title="对比清单",
        desc="对比两份清单，找出新增/删除/变化",
        mutating=False,
        positional=("left", "right"),
        fields=(
            _f(name="left", type="path", label="旧清单", direction="in", required=True),
            _f(name="right", type="path", label="新清单", direction="in", required=True),
        ),
    ),
    Command(
        name="bundle",
        cli="bundle",
        section="dirs",
        title="打包 bundle",
        desc="把已签名目录打包为可分发 zip（内置公钥与校验）",
        mutating=True,
        positional=("dir",),
        fields=(
            _f(name="dir", type="path", label="已签名目录", direction="in", required=True),
            _f(
                name="output",
                type="path",
                flag="output",
                label="输出 zip",
                direction="out",
                required=True,
            ),
            _f(
                name="key",
                type="path",
                flag="key",
                label="公钥",
                direction="in",
                help="打包时校验用的公钥；默认读配置",
            ),
            _f(
                name="allow_unlisted",
                type="bool",
                flag="allow-unlisted",
                label="允许未列入清单的文件",
                advanced=True,
            ),
            _f(
                name="compress",
                type="enum",
                flag="compress",
                label="压缩方式",
                options=("stored", "deflate"),
                advanced=True,
            ),
            _f(
                name="jobs",
                type="int",
                flag="jobs",
                label="并行线程数",
                advanced=True,
                min=1,
                max=64,
            ),
        ),
    ),
    Command(
        name="unpack",
        cli="unpack",
        section="dirs",
        title="解包 bundle",
        desc="解包 zip 并校验签名与文件完整性",
        mutating=True,
        positional=("bundle",),
        fields=(
            _f(name="bundle", type="path", label="bundle 文件", direction="in", required=True),
            _f(
                name="dest",
                type="path",
                flag="dest",
                label="目标目录",
                direction="out",
                required=True,
            ),
            _f(name="key", type="path", flag="key", label="公钥", direction="in"),
            _f(name="force", type="bool", flag="force", label="允许非空目标目录", advanced=True),
            _f(
                name="no_verify",
                type="bool",
                flag="no-verify",
                label="跳过校验",
                advanced=True,
                danger=True,
            ),
            _f(
                name="trust_embedded_key",
                type="bool",
                flag="trust-embedded-key",
                label="信任 bundle 内置公钥",
                advanced=True,
                danger=True,
            ),
        ),
    ),
    Command(
        name="sbom",
        cli="sbom",
        section="dirs",
        title="生成 SBOM",
        desc="从已签名清单生成 CycloneDX SBOM",
        mutating=True,
        positional=("dir",),
        fields=(
            _f(name="dir", type="path", label="已签名目录", direction="in", required=True),
            _f(
                name="output",
                type="path",
                flag="output",
                label="输出文件",
                direction="out",
                advanced=True,
            ),
            _f(
                name="deps",
                type="bool",
                flag="deps",
                label="解析依赖组件",
                help="从 uv.lock / requirements.txt 读取",
                advanced=True,
            ),
            _f(
                name="lock",
                type="path",
                flag="lock",
                label="依赖清单路径",
                direction="in",
                advanced=True,
            ),
        ),
    ),
    Command(
        name="timestamp",
        cli="timestamp",
        section="stamps",
        title="申请时间戳",
        desc="向 TSA 申请 RFC 3161 可信时间戳（.tsr）",
        mutating=True,
        positional=("file",),
        fields=(
            _f(name="file", type="path", label="文件或目录", direction="in", required=True),
            _f(
                name="out",
                type="path",
                flag="out",
                label="令牌输出路径",
                direction="out",
                advanced=True,
            ),
            _f(name="tsa", type="str", flag="tsa", label="TSA 地址", advanced=True),
            _f(
                name="tsa_ca",
                type="path",
                flag="tsa-ca",
                label="TSA 信任根",
                direction="in",
                advanced=True,
            ),
            _f(
                name="timeout",
                type="float",
                flag="timeout",
                label="超时秒数",
                advanced=True,
                min=1,
                max=300,
            ),
            _f(
                name="retry",
                type="int",
                flag="retry",
                label="重试次数",
                advanced=True,
                min=0,
                max=10,
            ),
            _f(name="force", type="bool", flag="force", label="覆盖已有令牌", advanced=True),
            _f(
                name="allow_unverified_chain",
                type="bool",
                flag="allow-unverified-chain",
                label="允许未通过证书链校验",
                advanced=True,
                danger=True,
            ),
        ),
    ),
    Command(
        name="renew",
        cli="renew",
        section="stamps",
        title="续期时间戳",
        desc="只续期时间戳，不重签内容",
        mutating=True,
        positional=("file",),
        fields=(
            _f(name="file", type="path", label=".sig / 文件 / 目录", direction="in", required=True),
            _f(name="tsa", type="str", flag="tsa", label="TSA 地址", advanced=True),
            _f(
                name="tsa_ca",
                type="path",
                flag="tsa-ca",
                label="TSA 信任根",
                direction="in",
                advanced=True,
            ),
            _f(
                name="timeout",
                type="float",
                flag="timeout",
                label="超时秒数",
                advanced=True,
                min=1,
                max=300,
            ),
            _f(
                name="retry",
                type="int",
                flag="retry",
                label="重试次数",
                advanced=True,
                min=0,
                max=10,
            ),
            _f(name="force", type="bool", flag="force", label="覆盖已有令牌", advanced=True),
            _f(
                name="allow_unverified_chain",
                type="bool",
                flag="allow-unverified-chain",
                label="允许未通过证书链校验",
                advanced=True,
                danger=True,
            ),
        ),
    ),
    Command(
        name="attest",
        cli="attest",
        section="stamps",
        title="生成证明",
        desc="生成 in-toto DSSE 证明（软件供应链场景）",
        mutating=True,
        positional=("dir",),
        fields=(
            _f(name="dir", type="path", label="已签名目录", direction="in", required=True),
            _f(
                name="output",
                type="path",
                flag="output",
                label="证明输出路径",
                direction="out",
                advanced=True,
            ),
            _f(name="key", type="path", flag="key", label="私钥", direction="in"),
            _f(name="password", type="password", label="私钥口令", gui_only=True),
            _f(name="remember", type="bool", label="记住口令直到退出", gui_only=True),
            _f(
                name="predicate_type",
                type="str",
                flag="predicate-type",
                label="predicate 类型 URI",
                advanced=True,
            ),
        ),
    ),
    Command(
        name="attest-verify",
        cli="attest-verify",
        section="stamps",
        title="验证证明",
        desc="验证 in-toto DSSE 证明的签名与内容",
        mutating=False,
        positional=("file",),
        fields=(
            _f(name="file", type="path", label="证明 JSON", direction="in", required=True),
            _f(name="key", type="path", flag="key", label="公钥", direction="in"),
        ),
    ),
    Command(
        name="hash",
        cli="hash",
        section="tools",
        title="计算 SHA-256",
        desc="输出 sha256sum 兼容校验和，可用于抽查比对",
        mutating=False,
        cancelable=True,
        positional=("files",),
        fields=(
            _f(name="files", type="paths", label="文件或目录", required=True),
            _f(name="verbose", type="bool", flag="verbose", label="显示文件大小", advanced=True),
            _f(name="exclude", type="list", flag="exclude", label="排除（glob）", advanced=True),
            _f(
                name="follow_symlinks",
                type="bool",
                flag="follow-symlinks",
                label="跟随符号链接",
                advanced=True,
            ),
        ),
    ),
    Command(
        name="inspect",
        cli="inspect",
        section="tools",
        title="查看元数据",
        desc="查看 .sig / .tsr 内的名称、摘要、时间等元数据",
        mutating=False,
        positional=("file",),
        fields=(
            _f(name="file", type="path", label=".sig 或 .tsr 文件", direction="in", required=True),
        ),
    ),
    Command(
        name="ots",
        cli="ots",
        section="tools",
        title="OpenTimestamps",
        desc="透传 ots 客户端（需系统安装 opentimestamps-client）",
        mutating=True,
        fields=(
            _f(
                name="args",
                type="args",
                label="ots 参数",
                help="如：stamp file.txt（空格分隔）",
                required=True,
            ),
        ),
    ),
    Command(
        name="config-init",
        cli="config-init",
        section="settings",
        title="生成配置模板",
        desc="生成 TOML 配置文件模板",
        mutating=True,
        positional=("path",),
        fields=(
            _f(
                name="path",
                type="path",
                label="配置输出路径",
                direction="out",
                help="默认 ~/.config/hashseal/config.toml",
            ),
            _f(name="force", type="bool", flag="force", label="覆盖已有配置", advanced=True),
        ),
    ),
]

COMMANDS: dict[str, Command] = {c.name: c for c in _COMMAND_LIST}

SECTIONS: list[dict[str, str]] = [
    {"id": "keys", "label": "密钥", "desc": "生成密钥对、核对公钥指纹、口令保管"},
    {"id": "sign", "label": "签名", "desc": "为文件/目录生成签名与时间戳"},
    {"id": "verify", "label": "验证", "desc": "核对签名、时间戳与目录完整性"},
    {"id": "stamps", "label": "时间戳与证明", "desc": "RFC 3161 时间戳与 in-toto 证明"},
    {"id": "dirs", "label": "目录与分发", "desc": "清单、对比、打包、解包、SBOM"},
    {"id": "tools", "label": "工具", "desc": "哈希、元数据、OpenTimestamps"},
    {"id": "settings", "label": "设置", "desc": "配置、模板与只读信息"},
]

SECTION_COMMANDS: dict[str, list[str]] = {}
for _c in _COMMAND_LIST:
    SECTION_COMMANDS.setdefault(_c.section, []).append(_c.name)


# --------------------------------------------------------------------------- #
# 校验与 argv 构造
# --------------------------------------------------------------------------- #


def _validate_field(f: Field, value: object, roots: RootSet) -> object:
    label = f.label or f.name
    if f.type == "path":
        raw = check_str(value, label=label, max_len=4096)
        if f.direction == "out":
            return str(roots.require_writable(raw, label=label))
        return str(roots.require_inside(raw, label=label))
    if f.type == "paths":
        if not isinstance(value, list) or not value:
            raise ApiError(400, "bad_request", f"{label}至少选择一项")
        out = []
        for item in value:
            raw = check_str(item, label=label, max_len=4096)
            out.append(str(roots.require_inside(raw, label=label)))
        return out
    if f.type == "str":
        return check_str(value, label=label)
    if f.type == "password":
        if not isinstance(value, str):
            raise ApiError(400, "bad_request", f"{label}必须是字符串")
        if "\x00" in value or len(value) > 1024:
            raise ApiError(400, "bad_request", f"{label}包含非法字符或超长")
        return value
    if f.type in ("int", "float"):
        if isinstance(value, bool) or not isinstance(value, (int, float, str)):
            raise ApiError(400, "bad_request", f"{label}必须是数字")
        try:
            num = float(str(value))
        except ValueError:
            raise ApiError(400, "bad_request", f"{label}必须是数字") from None
        if f.type == "int":
            if not float(num).is_integer():
                raise ApiError(400, "bad_request", f"{label}必须是整数")
            num = int(num)
        if f.min is not None and num < f.min:
            raise ApiError(400, "bad_request", f"{label}不能小于 {f.min}")
        if f.max is not None and num > f.max:
            raise ApiError(400, "bad_request", f"{label}不能大于 {f.max}")
        return num
    if f.type == "bool":
        if not isinstance(value, bool):
            raise ApiError(400, "bad_request", f"{label}必须是布尔值")
        return value
    if f.type == "enum":
        raw = check_str(value, label=label)
        if raw not in f.options:
            raise ApiError(400, "bad_request", f"{label}必须是 {', '.join(f.options)} 之一")
        return raw
    if f.type == "list":
        if not isinstance(value, list):
            raise ApiError(400, "bad_request", f"{label}必须是数组")
        return [check_str(v, label=label, max_len=512) for v in value]
    if f.type == "args":
        if isinstance(value, str):
            value = value.split()
        if not isinstance(value, list) or not value:
            raise ApiError(400, "bad_request", f"{label}不能为空")
        if len(value) > 64:
            raise ApiError(400, "bad_request", f"{label}最多 64 个参数")
        return [check_str(v, label=label, max_len=2048) for v in value]
    raise ApiError(400, "bad_request", f"未知字段类型: {f.type}")


def _key_target(command: Command, normalized: dict[str, object], config: dict) -> str | None:
    """remember 口令归属的私钥路径（sign/attest/keygen 有意义）。"""
    if command.name in ("sign", "attest"):
        raw = normalized.get("key") or config.get("key") or DEFAULT_PRIVATE
    elif command.name == "keygen":
        raw = normalized.get("private") or config.get("key") or DEFAULT_PRIVATE
    else:
        return None
    return str(Path(os.path.expanduser(str(raw))))


def key_path_for(command_name: str, options: dict, config: dict) -> str | None:
    """为 vault 自动取口令解析私钥路径（接受未规范化的 options）。"""
    if command_name in ("sign", "attest"):
        raw = options.get("key") or config.get("key") or DEFAULT_PRIVATE
    elif command_name == "keygen":
        raw = options.get("private") or config.get("key") or DEFAULT_PRIVATE
    else:
        return None
    return str(Path(os.path.expanduser(str(raw))))


def prepare(command: Command, options: dict, roots: RootSet, config: dict) -> Prepared:
    unknown = set(options) - {f.name for f in command.fields}
    if unknown:
        raise ApiError(400, "unknown_option", f"不支持的选项: {', '.join(sorted(unknown))}")
    normalized: dict[str, object] = {}
    for f in command.fields:
        value = options.get(f.name)
        if value is None or value == "" or value is False:
            if f.required and not f.gui_only:
                raise ApiError(400, "missing_option", f"缺少必填项: {f.label or f.name}")
            continue
        if f.gui_only:
            normalized[f.name] = value
            continue
        normalized[f.name] = _validate_field(f, value, roots)

    # 预检：--sig / --tsr 仅单目标
    if command.name == "sign":
        files = normalized.get("files")
        file_count = len(files) if isinstance(files, list) else 0
        if file_count > 1 and (normalized.get("sig") or normalized.get("tsr")):
            raise ApiError(400, "invalid_option", "--sig / --tsr 只能用于单文件或单个目录")

    argv = [command.cli]
    for name in command.positional:
        value = normalized.get(name)
        if value is None:
            continue
        if isinstance(value, list):
            argv.extend(str(v) for v in value)
        else:
            argv.append(str(value))
    for f in command.fields:
        if f.name in command.positional or f.gui_only:
            continue
        value = normalized.get(f.name)
        if value is None or value is False or value == "":
            continue
        flag = "--" + (f.flag or f.name.replace("_", "-"))
        if f.type == "bool":
            argv.append(flag)
        elif isinstance(value, list) and f.type in ("list", "args"):
            for item in value:
                argv.extend([flag, str(item)] if f.type == "list" else [str(item)])
        else:
            argv.extend([flag, str(value)])

    raw_password = normalized.get("password")
    password = str(raw_password) if raw_password else None
    remember = bool(normalized.get("remember"))
    remember_key = _key_target(command, normalized, config) if (remember and password) else None
    return Prepared(argv=argv, password=password, remember_key=remember_key)


def _path_default(
    command: Command,
    field_name: str,
    config: dict,
    cwd: Path,
    roots: RootSet,
) -> str:
    """路径选项的默认值：与 CLI 的解析规则一致（配置优先 → 固定名 → 启动目录）。

    预填仅是"透明化"：留空时 CLI 会解析出同样的默认值。若默认路径
    不在允许根目录内则不预填，避免前端提交被 jail 拒绝。
    """
    cfg_key = config.get("key")
    cfg_pub = config.get("pubkey")
    raw: object = None
    if field_name == "private" and command.name == "keygen":
        raw = cfg_key or DEFAULT_PRIVATE
    elif field_name == "public" and command.name == "keygen":
        raw = cfg_pub or DEFAULT_PUBLIC
    elif field_name == "key" and command.name in ("sign", "attest"):
        raw = cfg_key or DEFAULT_PRIVATE
    elif field_name == "key" and command.name in (
        "verify",
        "status",
        "fingerprint",
        "bundle",
        "unpack",
        "attest-verify",
    ):
        raw = cfg_pub or DEFAULT_PUBLIC
    elif field_name == "output" and command.name == "manifest":
        raw = MANIFEST_NAME
    elif field_name == "output" and command.name == "sbom":
        raw = "sbom.cdx.json"
    elif field_name == "output" and command.name == "attest":
        raw = "attestation.json"
    elif field_name == "path" and command.name == "config-init":
        raw = str(config_path())
    if raw is None or raw == "":
        return ""
    path = Path(os.path.expanduser(str(raw)))
    if not path.is_absolute():
        path = cwd / path
    if not roots.contains(path):
        return ""
    return str(path)


def specs_for_frontend(
    config: dict | None = None,
    cwd: Path | None = None,
    roots: RootSet | None = None,
    *,
    openssl: bool = True,
) -> list[dict]:
    """输出给前端渲染表单；不含任何敏感内容。"""
    config = config or {}
    cwd = cwd or Path.cwd()
    out: list[dict] = []
    for command in _COMMAND_LIST:
        fields = []
        for f in command.fields:
            default: object = ""
            if f.type == "path" and roots is not None:
                default = _path_default(command, f.name, config, cwd, roots)
            elif f.type == "bool" and f.default is not None:
                default = f.default
                if command.name == "sign" and f.name == "timestamp" and not openssl:
                    default = False  # 无 openssl 时链校验不可用，默认不申请时间戳
            fields.append(
                {
                    "name": f.name,
                    "default": default,
                    "type": f.type,
                    "label": f.label or f.name,
                    "help": f.help,
                    "required": f.required,
                    "advanced": f.advanced,
                    "direction": f.direction,
                    "options": list(f.options),
                    "min": f.min,
                    "max": f.max,
                    "danger": f.danger,
                    "placeholder": f.placeholder,
                    "inline": f.inline,
                }
            )
        out.append(
            {
                "name": command.name,
                "section": command.section,
                "title": command.title,
                "desc": command.desc,
                "mutating": command.mutating,
                "cancelable": command.cancelable,
                "fields": fields,
            }
        )
    return out


def get(name: str) -> Command:
    command = COMMANDS.get(name)
    if command is None:
        raise ApiError(404, "unknown_command", f"未知命令: {name}")
    return command
