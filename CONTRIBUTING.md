# Contributing

## 开发环境

```bash
uv sync
uv run hashseal --help
```

## 提交前检查

```bash
uv run ruff check .
uv run pytest -q
```

## 约定

- 保持 CLI 行为向后兼容；破坏性变更需要更新 CHANGELOG。
- 安全相关修复必须附回归测试。
- 新增签名字段时必须保留对旧格式的只读兼容。
- 提交信息使用祈使句，例如 `fix: reject manifest path traversal`。
