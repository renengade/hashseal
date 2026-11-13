#!/bin/sh
# hashseal installer（POSIX sh，兼容 dash / ash / bash）
#
#   curl -fsSL https://raw.githubusercontent.com/renengade/hashseal/main/install.sh | sh
#
# 安装到 uv 的独立工具环境（不污染系统 Python），并链接 hashseal 到 PATH。
# 可用环境变量覆盖：
#   HASHSEAL_REF=v0.2.0   指定 tag/分支（生产环境建议锁定 tag）
#   HASHSEAL_REPO=owner/repo
#   HASHSEAL_URL=<url>    直接指定源码包地址
set -eu

REPO="${HASHSEAL_REPO:-renengade/hashseal}"
REF="${HASHSEAL_REF:-main}"
URL="${HASHSEAL_URL:-https://github.com/$REPO/archive/$REF.tar.gz}"
MARKER="hashseal installer"

say() { printf '%s\n' "$*"; }
die() { printf '错误: %s\n' "$*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || die "需要 curl"
command -v tar  >/dev/null 2>&1 || die "需要 tar"

# 1) 确保有 uv
if ! command -v uv >/dev/null 2>&1; then
    say "未找到 uv，正在安装（https://astral.sh/uv）..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
    export PATH
fi
command -v uv >/dev/null 2>&1 || die "uv 安装失败，请手动安装后重试"

# 2) 下载源码包
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

say "下载 $URL"
curl -fsSL "$URL" -o "$TMP/src.tar.gz" || die "下载失败（检查仓库/分支，或设置 HASHSEAL_REF）"

if [ -n "${HASHSEAL_SHA256:-}" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$TMP/src.tar.gz" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$TMP/src.tar.gz" | awk '{print $1}')"
    else
        die "需要 sha256sum 或 shasum 才能校验 HASHSEAL_SHA256"
    fi
    [ "$actual" = "$HASHSEAL_SHA256" ] || die "SHA-256 校验失败（期望 $HASHSEAL_SHA256，实际 $actual）"
    say "SHA-256 校验通过"
fi

# 3) 解包并安装到独立环境
tar -xzf "$TMP/src.tar.gz" -C "$TMP" || die "解压失败"
SRC="$(find "$TMP" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
[ -n "$SRC" ] || die "源码包结构异常"

say "安装 hashseal ..."
uv tool install --force "$SRC" || die "uv tool install 失败"

# 4) 确保可执行文件在 PATH 上
BIN_DIR="$(uv tool dir --bin 2>/dev/null || printf '%s' "$HOME/.local/bin")"
say ""
if command -v hashseal >/dev/null 2>&1; then
    say "✅ 安装完成: $(command -v hashseal)"
    hashseal --version || true
else
    say "✅ 已安装，但 $BIN_DIR 不在 PATH 中。"
    RC=""
    case "${SHELL:-}" in
        */zsh)  RC="$HOME/.zshrc" ;;
        */bash) RC="$HOME/.bashrc" ;;
    esac
    if [ -n "$RC" ] && ! grep -qs "$MARKER" "$RC"; then
        printf '\n# added by %s\nexport PATH="%s:$PATH"\n' "$MARKER" "$BIN_DIR" >> "$RC"
        say "已写入 $RC，请重开终端后运行：hashseal --version"
    else
        say "请执行：export PATH=\"$BIN_DIR:\$PATH\""
    fi
fi

say ""
say "升级: 重新执行本脚本"
say "卸载: uv tool uninstall hashseal"
