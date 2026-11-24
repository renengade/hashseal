# 安装

## 一行安装

```bash
curl -fsSL https://raw.githubusercontent.com/renengade/hashseal/main/install.sh | sh
```

默认安装最新 release（GitHub API 解析 latest tag）。

## 锁定版本

```bash
curl -fsSL .../install.sh | HASHSEAL_REF=v0.9.0 sh
```

## SHA-256 校验

```bash
HASHSEAL_SHA256=<Release 页 SHA256SUMS 中的值> curl ... | sh
```

## 其他方式

```bash
uv tool install git+https://github.com/renengade/hashseal
pipx install git+https://github.com/renengade/hashseal
```

## 国内网络 / 镜像

```bash
export UV_INSTALLER_GITHUB_BASE_URL=https://gh-proxy.com/https://github.com
export UV_DEFAULT_INDEX=https://pypi.tuna.tsinghua.edu.cn/simple
export HASHSEAL_URL=https://gh-proxy.com/https://github.com/renengade/hashseal/archive/main.tar.gz
curl -fsSL https://gh-proxy.com/https://raw.githubusercontent.com/renengade/hashseal/main/install.sh | sh
```

## 升级与卸载

```bash
curl -fsSL .../install.sh | sh          # 升级
uv tool uninstall hashseal              # 卸载
```


## Windows（无 WSL，PowerShell 一键安装）

```powershell
irm https://github.com/renengade/hashseal/releases/latest/download/install.ps1 | iex
```

- 需要 PowerShell 5.1+（Windows 10/11 自带）与 `tar.exe`（Win10 1803+ 自带）；
- 未装 uv 会自动安装；hashseal 会写入用户 PATH（重开终端生效）；
- 锁定版本 / 校验哈希：

```powershell
$env:HASHSEAL_REF = "v0.10.0"; $env:HASHSEAL_SHA256 = "<SHA256SUMS 中的值>"; irm https://github.com/renengade/hashseal/releases/latest/download/install.ps1 | iex
```

- 升级：重新执行；卸载：`uv tool uninstall hashseal`；
- Windows 原生安装对 `D:\` 等本地盘的大文件哈希比 WSL `/mnt/*`（9P）快 4–5 倍。
