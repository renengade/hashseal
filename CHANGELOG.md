# Changelog

## 0.10.10

### Changed

- 主启动命令改为 **`hashseal web`**（`hashseal gui` 保留为兼容别名）。
- GUI 导航简化：「目录与分发」→「分发」，「时间戳与证明」→「时间戳」。
- 文件浏览默认放开整机：WSL/Linux 可浏览 `/`，Windows 列出所有盘符；
  `--restrict-roots` 可收紧为「主目录 + 当前目录 + --root」白名单。
- 修复设置页「配置说明」链接（指向「审计与配置」文档页）。

### Docs

- 说明「TSA 是 HTTP，为何仍需本机 OpenSSL」：HTTP 是传输，OpenSSL 用于本地证书链校验。
- 同步 web 命令、导航名称、根目录策略与演示命令。

## 0.10.9

### Changed

- **撤销 Windows 安装器自动安装 OpenSSL**：企业环境可能将 OpenSSL 列入软件黑名单；
  安装器改为仅检测并提示（普通签名/验证不需要，仅时间戳链校验需要）。
  可用 WSL 侧或按公司政策手动安装。

### Fixed

- Windows 升级前自动停止运行中的 hashseal 进程，避免 `uv tool install --force`
  因文件锁（`uv\tools\hashseal\Scripts` 拒绝访问）半失败；安装后校验 `hashseal.exe` 存在。

## 0.10.8

### Added

- Windows 安装器自动处理 OpenSSL（仅时间戳证书链校验需要）：
  已安装则加入 PATH（含 Git for Windows 自带），否则尝试
  `winget install ShiningLight.OpenSSL.Light`；失败不阻塞 hashseal 安装。
  跳过：`$env:HASHSEAL_NO_OPENSSL='1'`。
- Linux/WSL 安装脚本在缺少 openssl 时给出提示（不自动安装）。
- 文档同步：OpenSSL 的必要性（仅时间戳）与安装器行为。

## 0.10.7

### Fixed（GUI）

- 修复签名/时间戳页提示条中的图标渲染为黑色大三角：为 `.note-bar` 内 SVG
  补充尺寸与描边样式。
- OpenSSL 提示文案明确「仅影响时间戳证书链校验，普通签名/验证不需要」；
  文档 FAQ 同步。

## 0.10.6

### Added（GUI · P1/P2）

- 路径选择器新增「主目录 / 桌面 / 下载 / 文档」快捷入口（仅限 `--root` 内）。
- bundle/unpack 输出路径智能建议（`<目录>.zip`、同级 `<名字>/`；手动修改后不再覆盖）。
- 设置页诊断信息：平台、OpenSSL、版本、配置/审计路径、根目录，一键复制。
- 审计页对 `command_failed` 等事件显示 ❌ 与错误摘要。
- 解包命令说明标注上限（8 GiB / 10 万条目）。
- **Node DOM 表单回归测试入仓并进 CI**：18 个命令表单 + 典型结果渲染，
  防止「整页空白」类渲染崩溃再次发生。

## 0.10.5

### Fixed（GUI · P0）

- Windows 路径工具：选择器的 basename/joinPath/面包屑/初始目录全部兼容 `C:\`、`C:/` 与 UNC，
  修复「浏览…」丢失当前目录、保存模式文件名错误、面包屑错乱。
- 移除 GUI `hash` 表单中不存在的 `--jobs` 字段（提交会报参数错误）。
- 无 OpenSSL 时：`/api/status` 暴露 `openssl/platform`；签名默认关闭时间戳并页面提示；
  TSA 相关页面常驻说明。
- 签名成功但时间戳失败时，界面显示「签名已生成，时间戳未完成」并引导续期，不再只报“执行失败”。

### Added

- GUI 字段 ↔ CLI parser 一致性测试（防止表单暴露不存在的参数）。
- Node 路径工具单测（Windows/POSIX/UNC）。

## 0.10.4

### Added

- Windows 纳入 CI 矩阵（3.12/3.13）：官方 Windows 安装路径从此有真实测试覆盖。

### Fixed

- bundle 解包防护：条目数（默认 10 万）与解压后总大小（默认 8 GiB）上限，拒绝 zip bomb。
- 失败审计补全：所有命令（CLI 与 GUI）异常退出都会写入 `command_failed`
  （含 command/error/exit_code），且不会与命令自身的失败审计重复。
- 无 openssl 环境（典型为 Windows 原生安装）：TSA 证书链严格模式给出可执行的
  安装指引（winget/Git for Windows），非严格模式明确标记「证书链未校验」；
  `sign --timestamp` 提前警告。文档补充 Windows OpenSSL 说明。

## 0.10.3

### Added

- URL 深链：`#token=…&next=/页面` 可直达指定页面（支持/排查场景）。

### Changed

- 生成密钥对的口令复杂性要求改为**输入框 placeholder 展示**（`≥8 位，含大小写字母/数字/特殊字符至少 3 种`），
  不再单独占一行；输入不合规实时红边 + 提交拦截；帮助行简化为「留空不加密（不推荐）」。

## 0.10.2

### Fixed

- 修复密钥页（生成密钥对）渲染崩溃导致整页空白：确认口令块曾使 `keygenPwBlock` 脱离 DOM，
  触发 `parentNode` 为 null 的异常；顺带修复口令框出现两个复制按钮的问题。
- 表单/页面渲染异常改为**可见的红色错误卡**（含堆栈），不再静默空白。

## 0.10.1

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
