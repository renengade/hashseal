# 测试夹具（离线可复现）

| 文件 | 说明 |
| --- | --- |
| `app.py` | 被签名 / 被时间戳的示例文件（内容固定） |
| `app.py.sig` | 对 `app.py` 的 Ed25519 分离签名（格式版本 `fileproof/1`，见下） |
| `app.py.sig.tsr` | freetsa.org 对 `app.py.sig` 的 RFC 3161 令牌（完整 TimeStampResp，ECDSA） |
| `app.py.sig.digicert.tsr` | DigiCert 对同一 `.sig` 的令牌（RSA + 通用 rsaEncryption OID，回归测试用） |
| `public.pem` | 签名公钥（对应私钥生成后即销毁，未入库） |
| `freetsa_ca.pem` | freetsa 根证书，用于 `--tsa-ca` 校验证书链 |

## 为什么签名格式是 `fileproof/1`

这套夹具生成于项目还叫 `fileproof` 的时候。改名 `hashseal` 后，hashseal **仍能读取旧格式**
（只读兼容，新签名一律写 `hashseal/1`），所以夹具无需重签、测试保持离线可复现。

如果将来要重新生成（需要联网访问 TSA）：

```bash
hashseal keygen --private /tmp/fixture_priv.pem --public public.pem
hashseal sign app.py -k /tmp/fixture_priv.pem --signer "hashseal test fixture"
hashseal timestamp app.py.sig --tsa-ca freetsa_ca.pem
rm /tmp/fixture_priv.pem
```

## 有效期

freetsa 令牌时间 2026-11-11 09:58:53 UTC，受 freetsa TSA 证书约束（至 2040 年）；
DigiCert 令牌时间 2026-11-11 14:47:58 UTC，用系统 CA 库验链。
`freetsa_ca.pem` 来源：<https://freetsa.org/files/cacert.pem>。

## 用途

单元测试在不联网的前提下验证「签名 → 时间戳 → 联合校验」全链路，
以及篡改令牌、错数据、错根证书等失败路径。令牌绑定的是这份 `app.py.sig` 的精确字节，
不能用于任何其他文件。
