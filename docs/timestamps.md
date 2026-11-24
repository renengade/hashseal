# 时间戳

## 默认 TSA 与信任根

- 默认 TSA：`http://timestamp.digicert.com`
- 回退：`http://timestamp.sectigo.com` → `https://freetsa.org/tsr`
- 默认信任根 = 系统 CA 库 + 内置 freetsa 根
- `--tsa-ca` 覆盖信任根；显式给出则严格校验证书链
- `--tsa` 可逗号分隔多个，或 `HASHSEAL_TSA` 环境变量

GUI 中「申请可信时间戳」**默认勾选**；CLI 需要显式 `--timestamp`。

## 证书链校验与 openssl

链校验依赖系统 `openssl`：

- 严格模式（默认）在未安装 openssl 时**失败并给出安装指引**（fail-closed）；
- 非严格模式（`--allow-unverified-chain`）只跳过链校验，
  令牌内容、CMS 签名、`message_digest` 仍会校验，并明确标记「证书链未校验」；
- Windows 安装：`winget install ShiningLight.OpenSSL.Light`，或用 Git for Windows 自带的
  openssl 加入 PATH。

## 离线验证

验证不需要联网，令牌自带证书链；有 `openssl` 时本地完成链校验。
校验证书有效期用签发时刻，TSA 证书以后过期不影响历史令牌。

## 长期有效性（LTV）

1. 在旧令牌失效前，对新令牌再做一次时间戳（`hashseal renew`）；
2. 或采用 Evidence Record（RFC 4998，未实现）；
3. 一并保存：文件、`.sig`、`.tsr`、TSA 根证书、验证命令与版本。

## 连不上 TSA

```bash
hashseal timestamp app.py.sig --tsa http://timestamp.sectigo.com
export HASHSEAL_TSA=http://timestamp.sectigo.com
```

- 公司代理：`HTTPS_PROXY` / `HTTP_PROXY`
- 某些网络访问 freetsa 会卡 TLS 握手，默认已改为 DigiCert
- 完全隔离内网：只能自建 TSA

## 时间语义

- `.tsr` 由 TSA 签名，是**可信时间**；
- `.sig` 里的 `created` 是签名者自填的声明时间（未签名），不要当作可信时间；
- `verify --tsr` 校验令牌确实对应这份 `.sig`，并验证 TSA 签名与链。
