# 命令详解

全局选项：

```
hashseal -V          # 版本
hashseal --no-audit  # 本次不写审计日志（不推荐）
```

退出码：`0` 通过 / `1` 失败 / `2` 用法或 IO 错误。

---

## keygen

生成 Ed25519 密钥对。

```
hashseal keygen [--private PATH] [--public PATH] [--password-file PATH] [--force]
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--private` | `hashseal_private.pem` | 私钥输出路径 |
| `--public` | `hashseal_public.pem` | 公钥输出路径 |
| `--password-file` | — | 口令文件；给出则私钥加密存储 |
| `--force` | — | 覆盖已存在的密钥文件 |

```bash
hashseal keygen
hashseal keygen --password-file key.pass
```

---

## fingerprint

打印公钥指纹 `SHA256:...`。

```
hashseal fingerprint [PUBLIC] [-k PATH]
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `PUBLIC`（位置参数） | — | 公钥 PEM 文件 |
| `-k, --key` | — | 公钥 PEM（等价于位置参数） |

---

## hash

计算 SHA-256，输出与 `sha256sum` 兼容。

```
hashseal hash FILE|DIR... [-v] [--exclude GLOB] [--follow-symlinks]
```

| 参数 | 说明 |
| --- | --- |
| `-v, --verbose` | 额外显示文件大小 |
| `--exclude GLOB` | 目录遍历时排除（可重复） |
| `--follow-symlinks` | 跟随符号链接（默认跳过） |

---

## manifest

生成 `MANIFEST.sha256` 清单。

```
hashseal manifest PATH... [-o OUT] [--base DIR] [--exclude GLOB] [--follow-symlinks] [-j N]
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-o, --output` | `MANIFEST.sha256` | 输出路径 |
| `--base` | — | 记录相对路径的基准目录 |
| `--exclude` | — | 排除 glob（可重复） |
| `--follow-symlinks` | 跳过 | 跟随符号链接 |
| `-j, --jobs` | `min(4, CPU)` | 并行哈希线程数 |

---

## sign

签名文件或目录，可选时间戳。

```
hashseal sign FILE|DIR... [-k KEY] [--password-file PATH] [--signer TEXT]
               [--name NAME] [--sig PATH] [--timestamp] [--tsa URL]
               [--tsa-ca PEM] [--timeout SEC] [--retry N] [--tsr PATH]
               [--exclude GLOB] [-j N] [--follow-symlinks] [--force]
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-k, --key` | `hashseal_private.pem` | 私钥路径 |
| `--password-file` | — | 口令文件（加密私钥时必需） |
| `--sig` | `<文件>.sig` | 签名输出路径 |
| `--signer` | 空 | 署名备注；v2 起纳入签名 |
| `--name` | 实际文件名 | 签名时记录的文件名 |
| `--timestamp` | 关 | 签名后立即申请时间戳 |
| `--tsa` | DigiCert→Sectigo→freetsa | TSA 地址，可逗号分隔 |
| `--tsa-ca` | 内置 + 系统 CA | 时间戳信任根 |
| `--timeout` | `30` | TSA 网络超时（秒） |
| `--retry` | `2` | TSA 失败重试次数 |
| `--tsr` | `<签名>.tsr` | 时间戳输出路径 |
| `--exclude` | — | 目录排除 glob |
| `-j, --jobs` | `min(4, CPU)` | 并行哈希线程数 |
| `--follow-symlinks` | 跳过 | 跟随符号链接 |
| `--force` | — | 覆盖已存在的 `.sig` / `.tsr` |

目录输入：不接受 `--sig` / `--name`；产物写入 `.hashseal/`。

---

## verify

验证文件或目录。

```
hashseal verify FILE|DIR [--sig PATH] [-k KEY] [--name NAME] [--tsr TOKEN]
              [--ts-only] [--tsa-ca PEM] [--expect-fingerprint FP]
              [--allow-unlisted] [--exclude GLOB] [--follow-symlinks] [-j N] [--json]
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--sig` | `<文件>.sig` | 签名文件路径 |
| `-k, --key` | `hashseal_public.pem` | 公钥 PEM |
| `--name` | 实际文件名 | 改名时指定签名中记录的原名 |
| `--tsr` | 目录自动探测 | 时间戳令牌 |
| `--ts-only` | 关 | 只验时间戳，不要求 `.sig` |
| `--tsa-ca` | 内置 + 系统 CA | 时间戳信任根 |
| `--expect-fingerprint` | — | 公钥指纹必须匹配 |
| `--allow-unlisted` | 关 | 允许未列入清单的文件 |
| `--exclude` | — | 目录排除 glob |
| `--follow-symlinks` | 跳过 | 跟随符号链接 |
| `-j, --jobs` | `min(4, CPU)` | 并行校验线程数 |
| `--json` | 关 | 输出 JSON 结果 |

退出码：`0` 通过 / `1` 失败 / `2` 用法或 IO 错误。

---

## timestamp

申请 RFC 3161 可信时间戳。

```
hashseal timestamp FILE|DIR [-o PATH] [--tsa URL] [--tsa-ca PEM] [--timeout SEC] [--retry N] [--force] [--json]
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-o, --out` | `<目标>.tsr` | 令牌输出路径 |
| `--tsa` | `http://timestamp.digicert.com` | TSA 地址 |
| `--tsa-ca` | 内置 + 系统 CA | 信任根 |
| `--timeout` | `30` | 网络超时（秒） |
| `--retry` | `2` | 失败重试次数 |
| `--force` | — | 覆盖已存在的 `.tsr` |
| `--json` | 关 | 机器可读输出 |

目录自动定位 `.hashseal/MANIFEST.sha256.sig`。

---

## renew

只续期时间戳，不重签。

```
hashseal renew FILE|DIR [--tsa URL] [--tsa-ca PEM] [--timeout SEC] [--retry N] [--force]
```

参数同 `timestamp`；`FILE` 可以是 `.sig` 文件、普通文件或目录。

---

## status

快速检查签名，不请求 TSA。

```
hashseal status FILE|DIR [--sig PATH] [-k KEY] [--json]
              [--allow-unlisted] [--exclude GLOB] [--follow-symlinks] [-j N]
```

退出码与 `verify` 相同。

---

## diff

对比两份清单。

```
hashseal diff LEFT RIGHT [--json]
```

有差异退出码 `1`，无差异 `0`。

---

## inspect

查看 `.sig` / `.tsr` 元数据。

```
hashseal inspect FILE [--json]
```

- `.sig`：格式、名称、摘要、签名者、本地时间；
- `.tsr`：TSA、签发时间、序列号、策略。

不做密码学验证，仅解析元数据。

---

## bundle

打包已签名目录。

```
hashseal bundle DIR -o ZIP [-k KEY] [--include-pubkey] [--compress MODE] [-j N] [--allow-unlisted]
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-o, --output` | 必填 | 输出 zip 路径 |
| `-k, --key` | `hashseal_public.pem` | 公钥 PEM |
| `--include-pubkey` | 关 | 内置 `hashseal-public.pem` 到 zip |
| `--compress` | `stored` | `stored`=不压缩（最快）；`deflate`=减小体积 |
| `-j, --jobs` | `min(4, CPU)` | 并行校验线程数 |
| `--allow-unlisted` | 关 | 允许未列入清单的文件 |

---

## unpack

解包并校验。

```
hashseal unpack ZIP -d DIR [-k KEY] [--force] [--no-verify]
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-d, --dest` | 必填 | 解包目标目录 |
| `-k, --key` | 内置公钥 | 公钥 PEM |
| `--force` | — | 覆盖非空目标目录 |
| `--no-verify` | — | 跳过校验 |

---

## sbom

从已签名清单生成 CycloneDX SBOM。

```
hashseal sbom DIR [-o PATH] [--deps] [--lock PATH]
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-o, --output` | `sbom.cdx.json` | 输出路径 |
| `--deps` | 关 | 解析依赖加入组件 |
| `--lock` | `DIR/uv.lock` | 依赖清单路径 |

---

## attest

生成 in-toto DSSE 证明。

```
hashseal attest DIR [-o PATH] [-k KEY] [--password-file PATH] [--predicate-type URI]
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-o, --output` | `attestation.json` | 输出路径 |
| `-k, --key` | `hashseal_private.pem` | 私钥路径 |
| `--password-file` | — | 口令文件 |
| `--predicate-type` | `https://hashseal.dev/attestation/v1` | 证明类型 URI |

---

## attest-verify

```
hashseal attest-verify FILE [-k KEY] [--json]
```

| 参数 | 说明 |
| --- | --- |
| `-k, --key` | 公钥 PEM |
| `--json` | 输出 JSON 摘要 |

---

## config

```
hashseal config [--json]
```

显示配置路径与生效配置。配置文件 `~/.config/hashseal/config.toml`。

---

## audit

```
hashseal audit [-n N] [--json]
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-n, --lines` | `20` | 显示最近 N 条 |
| `--json` | 关 | 输出原始 JSON Lines |

---

## ots

透传 OpenTimestamps 客户端。

```
hashseal ots stamp|verify|upgrade FILE ...
```

需 `uv tool install opentimestamps-client`。
