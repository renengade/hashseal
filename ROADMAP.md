# Roadmap

## 0.4.0（已完成）

- P0：未列入清单文件检测、清单路径逃逸防护、v2 签名者绑定、版本单一来源、测试回仓 + CI。
- P1：私钥口令加密、`--expect-fingerprint`、敏感文件默认排除、TSA 重试、拒绝弱摘要、原子写入、符号链接策略、目录 JSON。
- 工程：`src/` 布局拆分（core / manifest / tsa / cli）、pytest、ruff、GitHub Actions、pre-commit。
- 体验：`diff`、`inspect`、`--allow-unlisted`、`--exclude`。

## 0.5.0（已完成，并入 0.6.0）

- `bundle` / `unpack`：文件 + `.sig` + `.tsr` + 公钥一键打包与验证。
- `renew`：只续期时间戳，不重签。
- `status`：快速检查，不请求 TSA。
- 配置系统：`~/.config/hashseal/config.toml`（默认 TSA/CA/key/exclude）。
- 审计日志（JSON Lines）与细分退出码。

## 0.6.0（已完成）

- 发布到 PyPI（Trusted Publishing，workflow 已就绪，需配置仓库变量）。
- SBOM（SPDX / CycloneDX）生成与签名。
- GitHub Action / pre-commit 验证示例。
- Docker 镜像（ghcr.io），用于 CI 内验证。
- 发布产物校验和 + 签名，`install.sh` 安装前验证。

## 0.7.0（已完成）

- in-toto DSSE 证明、SBOM 依赖组件、审计 syslog/轮转、交互式口令、文档站与威胁模型。

## 后续

- 多签名 / 门限签名（2-of-3 发布审批）。
- KMS / HSM / PKCS#11 私钥后端。
- 多 TSA 交叉见证与时间戳续期（LTV，RFC 4998）。
- 单文件 zipapp / WASM 只读验证器。
- Homebrew / Scoop / winget 分发。
- 完整文档站与威胁模型。
