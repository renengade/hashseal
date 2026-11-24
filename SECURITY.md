# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.10.x | ✅ |
| < 0.10 | ❌ |

## Reporting a vulnerability

请通过 GitHub Security Advisories 私密报告，或发邮件到 1145986820@qq.com。
请不要在公开 Issue 中披露未修复的漏洞细节。

## Scope

- 签名 / 验证逻辑（Ed25519、RFC 3161、清单与 bundle）
- 签名与密钥格式的解析（外部输入）
- 私钥处理、口令加密与内存保管
- 本地 Web GUI（token/同源校验、路径 jail、CSP、只读模式）
- 安装脚本与发布产物（SHA256SUMS、SLSA provenance）

## 发布产物校验

```bash
gh release download v0.10.4 -R renengade/hashseal
sha256sum -c SHA256SUMS
gh attestation verify hashseal-0.10.4-py3-none-any.whl -R renengade/hashseal
```

## 明确不在范围

- 本机同权限恶意程序、浏览器扩展（见 GUI 信任边界）
- 被完全控制的主机上的私钥与审计日志
- 单一 TSA 的可用性/可信度
