# 证明与 SBOM

## in-toto DSSE 证明

`hashseal attest` 从已签名清单生成 in-toto Statement，并用 Ed25519 做 DSSE 封装：

```bash
hashseal sign dist/
hashseal attest dist -o attestation.json
hashseal attest-verify attestation.json -p hashseal_public.pem
```

Statement 包含：

- `subject`：清单中每个文件的 SHA-256；
- `predicateType`：`https://hashseal.dev/attestation/v1`；
- `predicate`：工具版本、清单哈希、签名格式/签名者、时间戳是否存在及其哈希。

DSSE 签名覆盖 `PAE(payloadType, payload)`，可用标准 in-toto 工具链校验。

## SBOM

```bash
hashseal sbom dist -o sbom.cdx.json
hashseal sbom dist -o sbom.cdx.json --deps
```

- 默认生成文件级 CycloneDX 1.5；
- `--deps` 解析 `uv.lock` 或 `requirements.txt`，追加 `library` 组件（name/version/purl）；
- `--lock PATH` 指定依赖清单。

SBOM 本身是数据，需要可信时再签名：

```bash
hashseal sign sbom.cdx.json --timestamp
```
