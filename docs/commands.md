# 命令详解

全局选项：

```
hashseal -V / --version      # 版本
```

> 审计日志始终开启，没有关闭开关（`--no-audit` 已移除）。

退出码：`0` 通过 / `1` 验证失败 / `2` 用法或 IO 错误。

---

## gui / web

启动本地 Web 界面（`web` 是 `gui` 的别名）。完整说明见 [GUI 界面](gui.md)。

```
hashseal gui [--port N] [--no-browser] [--root PATH ...] [--read-only]
             [--idle-timeout MIN] [--vault-timeout MIN]
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--port` | 随机空闲端口 | 固定端口 |
| `--no-browser` | 自动打开 | 只打印地址 |
| `--root` | 主目录 + 当前目录 | 允许访问的根目录（可多次） |
| `--read-only` | 关 | 禁用签名/生成/解包等写操作 |
| `--idle-timeout` | `30` | 闲置自动退出分钟数（0 = 不退出） |
| `--vault-timeout` | `0` | 口令闲置锁定分钟数（0 = 记住到退出） |

服务只绑定 `127.0.0.1`，每次启动生成随机 token（地址 `#token=…`）。

---

## keygen

生成 Ed25519 密钥对。

```
hashseal keygen [--private PATH] [--public PATH] [--password-file PATH] [--force]
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--private` | 配置 `key` 或 `hashseal_private.pem` | 私钥输出 |
| `--public` | 配置 `pubkey` 或 `hashseal_public.pem` | 公钥输出 |
| `--password-file` | — | 口令文件；给出则私钥加密 |
| `--force` | — | 覆盖已存在文件 |

- 口令短于 8 字符会**警告**；GUI 中强制执行「≥8 位 + 至少 3 种字符类型」；
- 私钥加密使用 PBES2（PBKDF2-HMAC-SHA256 60 万次 + AES-256-CBC）。

---

## fingerprint

打印公钥指纹 `SHA256:...`。

```
hashseal fingerprint [PUBLIC] [-k PATH]
```

---

## hash

计算 SHA-256，输出与 `sha256sum` 兼容。

```
hashseal hash FILE|DIR... [-v] [--exclude GLOB] [--follow-symlinks]
```

---

## manifest

生成 `MANIFEST.sha256` 清单。

```
hashseal manifest PATH... [-o OUT] [--base DIR] [--exclude GLOB] [--follow-symlinks] [-j N]
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-o, --output` | `MANIFEST.sha256` | 输出路径 |
| `--base` | 自动推导 | 记录相对路径的基准目录 |
| `-j, --jobs` | `min(4, CPU)` | 并行哈希线程数 |

---

## sign

签名文件或目录，可选时间戳。

```
hashseal sign FILE|DIR... [-k KEY] [--password-file PATH] [--signer TEXT]
               [--name NAME] [--sig PATH] [--timestamp] [--tsa URL]
               [--tsa-ca PEM] [--timeout SEC] [--retry N] [--tsr PATH]
               [--exclude GLOB] [-j N] [--follow-symlinks] [--force]
               [--allow-unverified-chain]
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-k, --key` | 配置 `key` 或 `hashseal_private.pem` | 私钥 |
| `--password-file` | — | 口令文件（加密私钥时） |
| `--signer` | 空 | 署名；`hashseal/2` 起纳入签名 |
| `--name` | 实际文件名 | 签名时记录的文件名 |
| `--sig` | `<文件>.sig` | 签名输出（仅单目标） |
| `--timestamp` | 关 | 签名后申请 RFC 3161 时间戳（GUI 默认开） |
| `--tsa` / `--tsa-ca` | DigiCert→Sectigo→freetsa / 内置+系统 CA | TSA 与信任根 |
| `--timeout` / `--retry` | `30` / `2` | TSA 超时与重试 |
| `--tsr` | `<签名>.tsr` | 时间戳输出 |
| `--exclude` | — | 目录排除 glob |
| `-j, --jobs` | `min(4, CPU)` | 并行哈希线程数 |
| `--follow-symlinks` | 跳过 | 跟随符号链接 |
| `--force` | — | 覆盖已有 `.sig` / `.tsr` |
| `--allow-unverified-chain` | 关 | 跳过 TSA 证书链校验（降低安全性） |

目录输入：不接受 `--sig` / `--name`，产物写入 `.hashseal/`。

签名记录为 `hashseal/2` JSON；`name/size/digest/signer` 参与签名，
`created` 是**未签名的声明时间**（可信时间以 `.tsr` 为准）。

---

## verify

验证文件或目录。

```
hashseal verify FILE|DIR [--sig PATH] [-k KEY] [--name NAME] [--tsr TOKEN]
              [--ts-only] [--tsa-ca PEM] [--expect-fingerprint FP]
              [--allow-unlisted] [--exclude GLOB] [--follow-symlinks] [-j N]
              [--json] [--allow-unverified-chain]
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-k, --key`（别名 `-p, --pubkey`） | 配置 `pubkey` 或 `hashseal_public.pem` | 公钥 |
| `--sig` | `<文件>.sig` | 签名文件 |
| `--name` | 实际文件名 | 改名时指定签名中的原名 |
| `--tsr` | 目录自动探测 `<sig>.tsr` | 时间戳令牌 |
| `--ts-only` | 关 | 只验时间戳 |
| `--tsa-ca` | 内置 + 系统 CA | 信任根 |
| `--expect-fingerprint` | — | 指纹必须匹配 |
| `--allow-unlisted` | 关 | 允许未列入清单的文件 |
| `--exclude` | — | 目录排除 glob |
| `--follow-symlinks` | 跳过 | 跟随符号链接 |
| `-j, --jobs` | `min(4, CPU)` | 并行校验线程数 |
| `--json` | 关 | 机器可读输出 |
| `--allow-unverified-chain` | 关 | 跳过 TSA 证书链校验 |

### `--json` 结构

文件：

```json
{
  "target": "/path/file",
  "kind": "file",
  "ok": true,
  "signature_valid": true,
  "signer_signed": true,
  "metadata_valid": true,
  "digest": "…",
  "size": 123,
  "name": "file",
  "expected": {"name": "file", "size": 123, "digest": "…", "signer": "", "created": "…"},
  "signer_fingerprint": "SHA256:…",
  "timestamp": {"ok": true, "gen_time": "…", "tsa": "…", "chain": "ok"},
  "reasons": []
}
```

目录额外包含 `manifest`（清单签名信息）与 `files`：
`checked / ok / failed / unlisted / skipped`，失败与未列入列表各上限 1000 条，
超出时附 `failed_truncated: true` / `unlisted_truncated: true`。

目录校验为**单次遍历**（清单校验 + 未列入收集合并），内存仅保留失败项与计数。

---

## status

快速检查签名与目录完整性，不请求 TSA、不联网。

```
hashseal status FILE|DIR [--sig PATH] [-k KEY] [--json]
              [--allow-unlisted] [--exclude GLOB] [--follow-symlinks] [-j N]
```

---

## timestamp

申请 RFC 3161 可信时间戳；目录自动定位 `.hashseal/MANIFEST.sha256.sig`。

```
hashseal timestamp FILE|DIR [-o PATH] [--tsa URL] [--tsa-ca PEM]
                  [--timeout SEC] [--retry N] [--force] [--json]
                  [--allow-unverified-chain]
```

---

## renew

只续期时间戳，不重签。参数同 `timestamp`；`FILE` 可以是 `.sig`、普通文件或目录。

---

## diff

对比两份清单。

```
hashseal diff LEFT RIGHT [--json]
```

有差异退出码 `1`。JSON：`{left, right, ok, added[], removed[], changed[]}`。

---

## inspect

查看 `.sig` / `.tsr` 元数据（不做密码学验证）。

```
hashseal inspect FILE [--json]
```

---

## bundle

把已签名目录打包为可分发 zip（**始终内置公钥** `hashseal-public.pem`）。

```
hashseal bundle DIR -o ZIP [-k KEY] [--allow-unlisted] [--compress stored|deflate] [-j N]
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-o, --output` | 必填 | 输出 zip |
| `-k, --key` | 配置 `pubkey` | 打包前校验用的公钥 |
| `--compress` | `stored` | `stored` 最快；`deflate` 减小体积 |
| `--allow-unlisted` | 关 | 允许未列入清单的文件 |

---

## unpack

解包并校验。

```
hashseal unpack ZIP -d DIR [-k KEY] [--force] [--no-verify] [--trust-embedded-key]
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-d, --dest` | 必填 | 解包目标目录 |
| `-k, --key` | 配置 `pubkey` / `hashseal_public.pem` | 可信公钥（内置公钥仅在显式 `--trust-embedded-key` 时使用） |
| `--force` | — | 覆盖非空目标目录 |
| `--no-verify` | — | 跳过校验（危险） |
| `--trust-embedded-key` | — | 接受 bundle 内置公钥（危险） |

防护：拒绝 `..`/绝对路径/符号链接条目；条目数默认上限 **10 万**，
解压后总大小默认上限 **8 GiB**（超出即拒绝，防 zip bomb）。

---

## sbom

从已签名清单生成 CycloneDX 1.5 SBOM。

```
hashseal sbom DIR [-o PATH] [--deps] [--lock PATH]
```

---

## attest / attest-verify

生成 / 验证 in-toto DSSE 证明。

```
hashseal attest DIR [-o PATH] [-k KEY] [--password-file PATH] [--predicate-type URI]
hashseal attest-verify FILE [-k KEY] [--json]
```

`attest` 默认输出到**启动目录**的 `attestation.json`；它是独立附件，
不参与 `verify`/bundle，可安全删除或改路径。详见 [证明与 SBOM](attest.md)。

---

## config / config-init

```
hashseal config [--json]                 # 显示配置路径与生效配置
hashseal config-init [PATH] [--force]    # 生成 TOML 模板（默认 ~/.config/hashseal/config.toml）
```

> Windows 配置中的路径请用正斜杠（`C:/Users/...`）或 TOML 单引号字符串；
> 双引号里的 `\` 会被当作转义，hashseal 会明确提示。

---

## audit

```
hashseal audit [-n N] [--json]
```

按天或 10 MiB 滚动，默认保留 90 天。事件包含 `source`（`cli` / `gui`）；
命令异常退出会记录 `command_failed`。详见 [审计与配置](audit.md)。

---

## ots

透传 OpenTimestamps 客户端（需系统安装 `opentimestamps-client`）：

```
hashseal ots stamp|verify|upgrade FILE ...
```
