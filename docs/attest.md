# 证明与 SBOM

## in-toto DSSE 证明

`hashseal attest` 从**已签名清单**生成 in-toto Statement，并用 Ed25519 做 DSSE 封装：

```bash
hashseal sign dist/
hashseal attest dist -o attestation.json
hashseal attest-verify attestation.json -k hashseal_public.pem
```

Statement 包含：

- `subject`：清单中每个文件的 SHA-256；
- `predicateType`：`https://hashseal.dev/attestation/v1`；
- `predicate`：工具版本、清单哈希、签名格式/签名者、时间戳是否存在及其哈希。

DSSE 签名覆盖 `PAE(payloadType, payload)`，可用标准 in-toto 工具链校验。

### 输出位置

- 默认写到**启动目录**的 `attestation.json`（`-o` 可改）；
- GUI：「时间戳」页 → 生成证明 → 高级选项可改输出路径；
- 它是独立附件，**不参与 `verify` / bundle**，可安全删除或移走；
- 用于向 CI/下游声明「这批产物是谁、何时、基于什么内容发布」。

## SBOM

```bash
hashseal sbom dist                 # 默认输出 dist.cdx.json（与 dist/ 同级）
hashseal sbom dist --deps
```

- 默认生成文件级 CycloneDX 1.5；
- 默认输出与已签名目录同级，不放进 `dist/`（避免未列入），也不依赖当前目录；
- `--deps` 解析 `uv.lock` 或 `requirements.txt`，追加 `library` 组件（name/version/purl）；
- `--lock PATH` 指定依赖清单。

SBOM 本身是数据，需要可信时再签名：

```bash
hashseal sign dist.cdx.json --timestamp
```

分发建议：`bundle` **不会自动包含** SBOM。需要随交付物提供时，单独签名后与
bundle 一起分发（`dist.zip` + `dist.cdx.json` + `.sig`）；若必须纳入清单，
先把 SBOM 放进目录再重新 `sign`/`bundle`。

## GUI 中的证明页

「时间戳」页同时提供：时间戳申请/续期、生成证明、验证证明。
表单默认只显示目录与私钥；输出路径、predicate 类型在高级选项中。
