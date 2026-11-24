# 安装

## 一行安装

Linux / macOS / WSL：

```bash
curl -fsSL https://github.com/renengade/hashseal/releases/latest/download/install.sh | sh
```

Windows（无 WSL，PowerShell 5.1+）：

```powershell
irm https://github.com/renengade/hashseal/releases/latest/download/install.ps1 | iex
```

脚本会解析最新 release，并把 hashseal 安装到 uv 的独立工具环境（不污染系统 Python）。
Windows 上会自动写入用户 PATH，重开终端生效。

> 安装脚本本身也随 Release 资产分发，走 `github.com` 而非 `raw.githubusercontent.com`，
> 后者在部分网络下不可达。

## 锁定版本

```bash
curl -fsSL https://github.com/renengade/hashseal/releases/latest/download/install.sh \
  | HASHSEAL_REF=v0.10.4 sh
```

```powershell
$env:HASHSEAL_REF = "v0.10.4"
irm https://github.com/renengade/hashseal/releases/latest/download/install.ps1 | iex
```

## SHA-256 校验

Release 页有 `SHA256SUMS`（含 wheel、sdist、安装脚本）：

```bash
curl -fsSL .../install.sh | HASHSEAL_SHA256=<源码包对应的 sha256> sh
```

```powershell
$env:HASHSEAL_SHA256 = "<源码包对应的 sha256>"
irm https://github.com/renengade/hashseal/releases/latest/download/install.ps1 | iex
```

## 其他方式

```bash
uv tool install git+https://github.com/renengade/hashseal
pipx install git+https://github.com/renengade/hashseal
pip install hashseal-0.10.4-py3-none-any.whl   # 直接装 Release 中的 wheel
```

## 国内网络 / 镜像

```bash
export UV_INSTALLER_GITHUB_BASE_URL=https://gh-proxy.com/https://github.com
export UV_DEFAULT_INDEX=https://pypi.tuna.tsinghua.edu.cn/simple
export HASHSEAL_URL=https://gh-proxy.com/https://github.com/renengade/hashseal/archive/main.tar.gz
curl -fsSL https://gh-proxy.com/https://github.com/renengade/hashseal/releases/latest/download/install.sh | sh
```

## 升级与卸载

```bash
# Linux/macOS/WSL
curl -fsSL .../install.sh | sh
# Windows
irm .../install.ps1 | iex

uv tool uninstall hashseal
```

WSL 与 Windows 是**两套独立安装**（各自的密钥、配置、审计目录），升级也需要分别执行。
用 `hashseal --version` 确认版本。

## Windows 与 TSA 证书链

时间戳的证书链校验依赖系统 `openssl`。Windows 默认不带：

- `sign --timestamp`、`timestamp`、`renew` 会给出可执行提示（不会静默通过）；
- 验证时间戳（`verify --tsr`）严格模式同样失败并提示安装；
- 安装：`winget install ShiningLight.OpenSSL.Light`，或使用 Git for Windows 自带的 openssl 并加入 PATH；
- 明确接受风险时可加 `--allow-unverified-chain`（只跳过链校验，令牌内容/签名/摘要仍校验）。

Windows 原生安装对 `D:\` 本地盘的大文件哈希比 WSL `/mnt/*`（9P）快 4–5 倍。

## Docker

镜像用于 CI/服务器中的**验证**场景（GUI 面向桌面，容器内不建议使用）：

```bash
docker run --rm -v "$PWD:/work" ghcr.io/renengade/hashseal verify /work/file
```
