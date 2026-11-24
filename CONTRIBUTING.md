# Contributing

## 开发环境

```bash
uv sync
uv run hashseal --version
uv run hashseal web --no-browser     # GUI 本地调试
```

## 提交前检查

```bash
uv run ruff check .
uv run mypy src/hashseal --ignore-missing-imports --exclude ".*tsa\.py.*|.*sbom\.py.*"
uv run pytest -q
uv run --group docs mkdocs build --strict
```

CI 在 **Ubuntu / macOS / Windows** 上运行（Windows 覆盖 3.12/3.13）。

## 平台策略

- GUI/CLI 的代码保持**跨平台**（同一套 Python/JS，不做运行时平台分支限制）；
- **Windows 是主要目标与主验证平台**：新功能优先在 Windows 上验证，
  安装入口为 `install.ps1`；
- CI 必须同时覆盖 Linux / macOS / Windows；任何 Windows 专属修复不得破坏
  其它平台（路径、换行、openssl、syslog 等易错点已有对应测试）。

## 约定

- 保持 CLI 行为向后兼容；破坏性变更需要更新 CHANGELOG。
- 安全相关修复必须附回归测试。
- 新增签名字段时必须保留对旧格式的只读兼容。
- 提交信息使用祈使句，例如 `fix: reject manifest path traversal`。
- 测试夹具（`.sig` / `.tsr` / `.pem`）对字节敏感，已在 `.gitattributes`
  标记为二进制，请勿改为文本或让编辑器改行尾。
- GUI 静态资源无构建步骤；改完 JS/CSS 直接刷新页面（服务端 `no-store`）。
- 表单/页面渲染必须有错误兜底（异常显示错误卡，不允许静默空白）。

## 发布

- 版本号在 `pyproject.toml`，tag 必须为 `v<version>`；Release workflow 会校验并拒绝不一致。
- 推送 `v*` tag 触发：发布前测试 → 构建 wheel/sdist → SHA256SUMS →
  SLSA provenance → GitHub Release（附 `install.sh` / `install.ps1`）。
- CHANGELOG 的 `## <version>` 段会自动作为 Release 说明。
- PyPI 发布需要先配置 Trusted Publishing，并在仓库变量中设置 `PUBLISH_TO_PYPI=true`。
- 发版后请同步升级 WSL 与 Windows 两端安装（互不影响）。
