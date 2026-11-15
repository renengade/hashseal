# hashseal

用 **SHA-256 + Ed25519 + RFC 3161** 证明文件"没被改过、是谁发的、什么时候发的"。

## 安装

```bash
curl -fsSL https://raw.githubusercontent.com/renengade/hashseal/main/install.sh | sh
```

默认安装最新 release；生产环境建议锁定版本并校验 SHA-256。

## 60 秒上手

```bash
hashseal keygen
hashseal sign app.py
hashseal verify app.py

hashseal sign dist/ --timestamp
hashseal verify dist/
```

## 文档

- [安装](install.md) — 版本锁定、镜像、卸载
- [核心概念](concepts.md) — 三件产物、信任链、清单原理
- [命令详解](commands.md) — 全部命令与选项
- [时间戳](timestamps.md) — TSA、回退链、LTV
- [证明与 SBOM](attest.md) — in-toto DSSE、CycloneDX
- [审计与配置](audit.md) — 配置文件、审计日志
- [性能](performance.md) — 基准与优化
- [威胁模型](threat-model.md) — 资产、信任边界、残余风险
- [常见问题](faq.md)
