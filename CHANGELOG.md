# Changelog

## Unreleased

### Added

- `hashseal web` 子命令（= `gui` 别名）。
- Windows PowerShell 一键安装（`install.ps1`，无需 WSL；行为与环境变量与 install.sh 一致）。

### Changed

- `sha256_file` 读路径调优：unbuffered + `readinto` 复用 32 MiB 缓冲（NVMe 实测快约 10%）。
- 目录校验改为 `verify_tree` 单次遍历（清单校验 + 未列入收集合并），只保留失败项与计数，
  大目录内存占用从全量通过列表降为 KB 级；`verify_entries` / `find_unlisted` 保留为兼容 API。

## 0.10.0

### Added

- **本地 Web GUI**：`hashseal gui` 启动仅绑定 `127.0.0.1` 的零依赖 Web 界面，浏览器完成全部 CLI 功能（验证/签名/密钥/清单/bundle/时间戳/证明/SBOM/审计/配置）。
- GUI 安全模型：随机 token（URL fragment 携带）、Host/Origin/Sec-Fetch-Site 同源校验、严格 CSP、路径 jail（`--root` 白名单）、只读模式、空闲自动退出。
- 口令内存保管（vault）：私钥口令只存进程内存，可一键锁定；任务对象/审计/日志永不包含口令。
- 命令上下文（`result.py`）：CLI 与 GUI 共用同一套业务代码；GUI 通过结构化结果渲染，无需解析人类输出。
- 审计事件新增 `source` 字段（`cli` / `gui`）。
- `verify` / `status` / `_check_timestamp_only` 的失败原因结构化输出（`reasons`）；目录校验列表封顶 1000 条并标记 `truncated`。
- 静态资源（HTML/CSS/JS）随 wheel 分发，无外链、无构建步骤。

### Fixed

- `verify` 文件模式未写审计日志的遗漏（现在所有 verify 路径都会审计）。

## 0.9.0

### Added

- mypy 类型检查进 CI（`ruff` + `mypy` + `pytest` 三阶段）。
- Release workflow 加入 `actions/attest-build-provenance`（keyless SLSA 证明）。
- 私钥 KDF 迭代从 2048 提升到 600,000（PBKDF2-HMAC-SHA256 + AES-256-CBC）。
- 审计日志覆盖所有命令（keygen/fingerprint/hash/manifest/diff/inspect/ots）。
- `config` 命令显示完整配置键。
- 文档：符号链接逃逸拒绝、显式排除文件不受 exclude 影响、TSA 回退语义。

### Fixed

- `_pub_path` / `_key_path` / `_tsa_ca` / `_audit` 类型签名。
- `_verify_file` 消除 `args` 传递歧义。

## 0.8.2

### Fixed

- 所有路径参数支持 `~` 展开（`-k`、`--sig`、`--tsr`、`-o`、`--tsa-ca`、`--password-file` 等）。
- `bundle --include-pubkey` 内置公钥改名为 `hashseal-public.pem`，
  避免与载荷中同名 `public.pem` 冲突（此前 zip 内会出现重复条目）。
- `unpack` 改为流式复制，修复大文件解包内存占用问题。
- `inspect .tsr` 移除从不出现的 `chain` 字段。

### Added

- `bundle --compress stored|deflate`：默认 `stored`（不压缩），256MB 数据 6.6s → 1.9s；
- `bundle` 默认内置公钥（`hashseal-public.pem`），接收方无需单独获取；
- `-j/--jobs` 并行哈希：`sign` / `manifest` / `verify` / `status` / `bundle`；
- `unpack` 使用 1 MiB 缓冲流式复制。

## 0.8.1

### Changed

- 所有人工展示时间统一为“本地时间 + UTC”，例如
  `2026-11-14 09:55:23 +0800（UTC 2026-11-14 01:55:23）`：
  `inspect`、`verify`、`audit`、`sbom`、`bundle`。
- 机器可读字段（JSON `ts` / `gen_time` / CycloneDX `timestamp`）保持 RFC3339 不变。
- 审计日志记录操作者 `user` / `uid` / `hostname` / `ip`，SSH 场景记录 `ssh_client`，
  `sudo` 场景记录 `sudo_user`。
- 审计日志按天/大小滚动，默认保留 90 天（`audit_retention_days`），过期归档自动删除；
  `audit` 命令会读取活跃文件与归档。

## 0.8.0

### Changed

- 目录签名默认把元数据放进 `.hashseal/`（清单、签名、时间戳），源文件保持干净；
  `verify DIR` 自动查找 `.hashseal/`，并兼容旧版根目录布局。
- 默认 TSA 改回 `http://timestamp.digicert.com`，失败自动回退
  `http://timestamp.sectigo.com`、`https://freetsa.org/tsr`；
  `--tsa` / `HASHSEAL_TSA` 支持逗号分隔多个地址。

### Security

- 审计日志强制开启：移除 `--no-audit`、`HASHSEAL_NO_AUDIT` 和配置开关；
  syslog 不可用时回退本地文件，写入失败会告警。
- 空口令文件被拒绝，避免静默生成未加密私钥。

## 0.7.0

### Added

- in-toto Statement + DSSE：`attest` / `attest-verify`。
- SBOM `--deps` / `--lock`：追加 `uv.lock` / `requirements.txt` 组件（name/version/purl）。
- 审计 sink：`file` / `syslog` / `both`，按大小轮转（默认 10 MiB × 5）。
- 交互式私钥口令提示（有 TTY 时）。
- mkdocs-material 文档站与 GitHub Pages workflow（威胁模型、审计、证明）。

## 0.6.0

### Added

- `status`：快速检查签名，不请求 TSA。
- `renew`：只续期时间戳，不重签。
- `bundle` / `unpack`：已签名目录打包为 zip，解包后自动校验。
- `sbom`：从已签名清单生成 CycloneDX SBOM。
- 配置文件 `~/.config/hashseal/config.toml` 与 `config` 命令。
- JSON Lines 审计日志与 `audit` 命令。
- `Dockerfile`、GitHub Action (`action.yml`)、发布产物 `SHA256SUMS`。
- `install.sh` 支持 `HASHSEAL_SHA256` 校验下载包。

## 0.4.1

### Fixed

- 移除测试文件多余的 shebang，修复 CI lint 失败。
- Release workflow 的 PyPI 发布改为显式开关（`PUBLISH_TO_PYPI=true`），避免未配置时误发布。

## 0.4.0

### Changed

- 重构为 `src/hashseal/` 包（core / manifest / tsa / cli），测试回到发布仓。
- 签名格式升级为 `hashseal/2`：`signer` 纳入签名；继续只读兼容 `hashseal/1`、`fileproof/1`。
- 默认 TSA 改为 `https://timestamp.digicert.com`。
- 版本号改为从包元数据读取，避免多处维护。

### Fixed

- `verify DIR` 现在能发现“目录中存在但未列入清单”的文件。
- 清单路径逃逸（`..`、绝对路径、重复条目）被拒绝。
- 私钥支持口令加密；`--password-file` / `HASHSEAL_KEY_PASSWORD`。
- TSA 请求支持重试；弱摘要算法（SHA-1/MD5）被拒绝。
- `.sig` / `.tsr` / 清单改为原子写入。
- 目录遍历默认跳过符号链接，可用 `--follow-symlinks` 开启。

### Added

- `--expect-fingerprint`、`--exclude`、`--allow-unlisted`、`--retry`。
- `hashseal diff`、`hashseal inspect`。
- 目录 `verify --json`。
- GitHub Actions CI / Release、pre-commit、本变更日志。
