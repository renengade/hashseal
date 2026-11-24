# Roadmap

## 已完成

### 0.4.0

- P0：未列入清单文件检测、清单路径逃逸防护、v2 签名者绑定、版本单一来源、测试回仓 + CI。
- P1：私钥口令加密、`--expect-fingerprint`、敏感文件默认排除、TSA 重试、拒绝弱摘要、原子写入、符号链接策略、目录 JSON。
- 工程：`src/` 布局拆分（core / manifest / tsa / cli）、pytest、ruff、GitHub Actions、pre-commit。
- 体验：`diff`、`inspect`、`--allow-unlisted`、`--exclude`。

### 0.5.0 / 0.6.0

- `bundle` / `unpack`、`renew`、`status`、配置系统、审计日志。
- SBOM（CycloneDX）、GitHub Action、Docker、发布校验和。

### 0.7.0

- in-toto DSSE 证明、SBOM 依赖组件、审计 syslog/轮转、文档站与威胁模型。

### 0.8.0

- `.hashseal/` 默认元数据目录（兼容旧布局）。
- TSA 默认 HTTP + 多端点回退；`--tsa` 支持多个地址。
- 审计日志强制开启；空口令文件拒绝。

### 0.9.0

- mypy 类型检查 + CI；SLSA provenance；私钥 KDF 600k；审计全命令覆盖。

### 0.10.x

- **本地 Web GUI（`hashseal gui` / `web`）**：零依赖、仅 127.0.0.1、
  token/同源校验、路径 jail、只读模式、口令内存保管、单线程任务队列。
- 结构化命令结果（CLI/GUI 共用内核）；审计 `source` 与 `command_failed`。
- 目录校验单次遍历 + 流式聚合；哈希读路径调优（32 MiB readinto）。
- **Windows 官方支持**：`install.ps1`、Windows CI（3.12/3.13）、无 openssl 明确降级。
- bundle 解包上限（zip bomb 防护）；跨平台测试修复（macOS 路径、Windows 夹具字节）。
- 签名格式保持 `hashseal/2`；GUI 默认开启时间戳与口令记忆。

## 后续（按需）

- 签名格式 v3：`created`/`comment` 纳入签名，keyid 快速错配提示。
- `key-passwd`（更换私钥口令）、`key-recover`（从私钥重建公钥）、stdin 签名。
- `cli.py` 服务层拆分（当前 1.7k 行；GUI 已复用同一内核）。
- mypy 全量（tsa.py ASN.1 动态类型）、针对解析器的 fuzz/属性测试。
- CodeQL 代码扫描、依赖漏洞审计。
- 审计日志哈希链（需外部锚点才有实际意义）。
- KDF 升级 scrypt/Argon2id（新密钥，旧格式继续可读）。
- 多签名 / 门限签名（2-of-3 发布审批）。
- KMS / HSM / PKCS#11 私钥后端。
- 多 TSA 交叉见证与 LTV（RFC 4998）。
- 单文件 zipapp / WASM 只读验证器。
- Homebrew / Scoop / winget 分发。
