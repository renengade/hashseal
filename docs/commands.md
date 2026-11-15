# 命令详解

## keygen

```
hashseal keygen [--private PATH] [--public PATH] [--password-file PATH] [--force]
```

| 选项 | 默认值 | 说明 |
| --- | --- | --- |
| `--private` | `hashseal_private.pem` | 私钥输出路径 |
| `--public` | `hashseal_public.pem` | 公钥输出路径 |
| `--password-file` | — | 私钥口令文件；给出则私钥加密存储 |
| `--force` | — | 允许覆盖 |

## fingerprint

```
hashseal fingerprint [PUBLIC] [-k PATH]
```

打印 `SHA256:...` 形式的公钥指纹。

## hash

```
hashseal hash FILE|DIR... [-v] [--exclude GLOB] [--follow-symlinks] [-j N]
```

输出与 `sha256sum` 逐字节兼容。

## manifest

```
hashseal manifest PATH... [-o OUT] [--base DIR] [--exclude GLOB] [--follow-symlinks] [-j N]
```

## sign

```
hashseal sign FILE|DIR... [-k KEY] [--signer TEXT] [--name NAME]
               [--timestamp] [--tsa URL] [--tsa-ca PEM] [--timeout SEC] [--retry N]
               [--sig PATH] [--tsr PATH] [--password-file PATH]
               [--exclude GLOB] [--follow-symlinks] [--force]
```

- **单文件** → `<文件>.sig`；
- **目录** → `.hashseal/MANIFEST.sha256` + `.sig` + `.tsr`；
- **重复签名**必须 `--force`；
- 时间戳失败不丢签名。

## verify

```
hashseal verify FILE|DIR [--sig PATH] [-k KEY] [--name NAME]
              [--tsr TOKEN] [--ts-only] [--tsa-ca PEM] [--json]
              [--expect-fingerprint SHA256:...] [--allow-unlisted]
              [--exclude GLOB] [--follow-symlinks]
```

退出码：`0` 通过 / `1` 失败 / `2` 用法或 IO 错误。

## timestamp

```
hashseal timestamp FILE|DIR [-o PATH] [--tsa URL] [--tsa-ca PEM] [--timeout SEC] [--retry N] [--force] [--json]
```

目录自动定位 `.hashseal/MANIFEST.sha256.sig`。

## status / renew / diff / inspect / bundle / unpack / sbom

```bash
hashseal status FILE|DIR [-k KEY] [--json]
hashseal renew FILE|DIR [--tsa URL] [--force]
hashseal diff LEFT RIGHT [--json]
hashseal inspect FILE [--json]
hashseal bundle DIR -o ZIP [-k KEY] [--include-pubkey] [--compress MODE] [-j N]
hashseal unpack ZIP -d DIR [-k KEY] [--force] [--no-verify]
hashseal sbom DIR [-o sbom.cdx.json] [--deps] [--lock PATH]
```

## config / audit

```bash
hashseal config [--json]
hashseal audit [-n N] [--json]
```

## ots

```bash
hashseal ots stamp|verify|upgrade FILE ...
```

需 `uv tool install opentimestamps-client`。
