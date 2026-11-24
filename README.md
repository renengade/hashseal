# hashseal

> 用 **SHA-256 + Ed25519 + RFC 3161** 证明文件"没被改过、是谁发的、什么时候发的"。

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey)
[![CI](https://github.com/renengade/hashseal/actions/workflows/ci.yml/badge.svg)](https://github.com/renengade/hashseal/actions/workflows/ci.yml)
[![Docs](https://github.com/renengade/hashseal/actions/workflows/docs.yml/badge.svg)](https://renengade.github.io/hashseal/)

**完整文档**：<https://renengade.github.io/hashseal/>

---

## 安装

```bash
curl -fsSL https://raw.githubusercontent.com/renengade/hashseal/main/install.sh | sh
```

默认安装最新 release。锁定版本 / 镜像 / 升级：[docs/install.md](https://renengade.github.io/hashseal/install)

## 60 秒上手

```bash
# 1. 生成密钥
hashseal keygen

# 2. 签名
hashseal sign app.py --signer "A <a@example.com>"

# 3. 验证
hashseal verify app.py

# 整个目录（含时间戳）
hashseal sign dist/ --timestamp
hashseal verify dist/

# 不喜欢命令行？启动本地 Web 界面
hashseal gui
```

## 命令速查

| 命令 | 用途 |
| --- | --- |
| `gui` | 本地 Web 界面（浏览器操作，与 CLI 同功能） |
| `keygen` | 生成密钥对 |
| `sign` | 签名文件/目录，可选时间戳 |
| `verify` | 验证签名/时间戳/目录完整性 |
| `status` | 快速检查（不联网） |
| `bundle` / `unpack` | 打包/解包已签名目录 |
| `hash` | SHA-256 校验和 |
| `manifest` | 生成文件清单 |
| `timestamp` / `renew` | 申请/续期时间戳 |
| `diff` | 对比两份清单 |
| `inspect` | 查看 `.sig` / `.tsr` 元数据 |
| `sbom` | 生成 CycloneDX SBOM |
| `attest` / `attest-verify` | in-toto DSSE 证明 |
| `config` / `audit` | 配置 / 审计日志 |
| `ots` | OpenTimestamps（可选） |
| `fingerprint` | 打印公钥指纹 |

详细选项与示例：[docs/commands.md](https://renengade.github.io/hashseal/commands)

## 能力层级

| 层级 | 手段 | 能证明 |
| --- | --- | --- |
| L1 | SHA-256 | 内容未变 |
| **L2** | **Ed25519 签名** | **内容未变 + 来自谁** |
| **L3** | **+ RFC 3161** | **+ 什么时候签的** |

## 安全边界

- 签名证明"谁签的"，不证明"内容是对的"；
- 脚本无法自证清白，需外部可信启动器；
- 公钥指纹必须通过**独立信道**核对；
- 哈希一致 ≠ 运行行为一致。

更多：[威胁模型](https://renengade.github.io/hashseal/threat-model)

## 开发

```bash
uv sync
uv run pytest -q
uv run ruff check .
uv run --group docs mkdocs serve
```

## License

MIT
