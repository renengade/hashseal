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
