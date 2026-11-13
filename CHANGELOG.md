# Changelog

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
