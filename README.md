# hashseal

> 用 **SHA-256 + Ed25519 + RFC 3161** 证明文件"没被改过、是谁发的、什么时候发的"。
> 一条命令完成签名与验证，支持单文件、整目录和可信时间戳。

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

---

## 目录

- [它解决什么问题](#它解决什么问题)
- [安装](#安装)
- [快速开始](#快速开始)
- [核心概念](#核心概念)
- [命令详解](#命令详解)
  - [keygen](#keygen--生成密钥)
  - [fingerprint](#fingerprint--公钥指纹)
  - [hash](#hash--计算-sha-256)
  - [manifest](#manifest--生成清单)
  - [sign](#sign--签名)
  - [verify](#verify--验证)
  - [timestamp](#timestamp--申请时间戳)
  - [ots](#ots--opentimestamps)
- [目录支持矩阵](#目录支持矩阵)
- [时间戳深入](#时间戳深入)
- [退出码与自动化](#退出码与自动化)
- [安全边界](#安全边界)
- [常见问题](#常见问题)
- [开发](#开发)
- [License](#license)

---

## 它解决什么问题

| 层级 | 手段 | 能发现 / 能证明 | 防不住 |
| --- | --- | --- | --- |
| **L1** | **SHA-256 校验和** | 传输损坏、误改 | 文件 + 哈希被一起替换 |
| **L2** | **Ed25519 签名** | 篡改、冒充、改名 | 私钥泄露；签名者签了坏文件 |
| **L3** | **L2 + RFC 3161 时间戳** | 外加"某时刻已存在"、不可否认 | 私钥泄露；TSA 不可信 |

- **MD5 不要用**：它不是签名，且已被实用碰撞攻破，只能发现传输损坏。
- **哈希不够**：如果攻击者把文件和哈希一起换掉，校验照样通过。
- **签名解决来源**：私钥只有发送方持有，别人伪造不了；接收方只需一次性核对公钥指纹。
- **时间戳解决时间**：由第三方 TSA 见证，签名者事后无法抵赖。

> **哈希一致 ≠ 运行行为一致。** Python 版本、依赖、环境变量都可能让同一份脚本行为不同；
> 需要环境一致时，请配合锁文件（如 `uv.lock`）或容器，并把镜像 digest 一起签。

---

## 安装

### 一行安装

```bash
curl -fsSL https://raw.githubusercontent.com/renengade/hashseal/main/install.sh | sh
```

脚本会：

1. 检测 `uv`，没有则自动安装；
2. 下载源码包；
3. 安装到 uv 的独立工具环境（不污染系统 Python）；
4. 把 `hashseal` 链接到 `~/.local/bin`，必要时提示/写入 `PATH`。

安装后全局可用：

```bash
hashseal --version
hashseal --help
```

### 锁定版本（推荐用于生产）

```bash
curl -fsSL https://raw.githubusercontent.com/renengade/hashseal/main/install.sh \
  | HASHSEAL_REF=v0.3.6 sh
```

`HASHSEAL_REF` 支持分支、tag 或 commit SHA。

### 其他安装方式

```bash
uv tool install git+https://github.com/renengade/hashseal   # 需要 git
pipx install git+https://github.com/renengade/hashseal      # 习惯 pipx
```

### 国内网络 / 镜像

三个环节可分别走镜像：

```bash
# 1) uv 本体（安装脚本会自动装）
export UV_INSTALLER_GITHUB_BASE_URL=https://ghfast.top/https://github.com

# 2) PyPI 依赖（uv 不读 PIP_INDEX_URL）
export UV_DEFAULT_INDEX=https://pypi.tuna.tsinghua.edu.cn/simple

# 3) hashseal 源码包
export HASHSEAL_URL=https://ghfast.top/https://github.com/renengade/hashseal/archive/main.tar.gz

curl -fsSL https://raw.githubusercontent.com/renengade/hashseal/main/install.sh | sh
```

- freetsa 根证书已内置，**不需要**访问 freetsa；
- 第三方 GitHub 代理会看到下载内容，属供应链信任边界，敏感环境请自建镜像并校验 SHA-256；
- 发布到 PyPI 后可直接 `UV_DEFAULT_INDEX=... uv tool install hashseal`。

### 升级与卸载

```bash
# 升级：重跑安装脚本（推荐，能拿到最新 tag 行为）
curl -fsSL .../install.sh | sh

# 或强制重装当前源码包
uv tool install --force /path/to/hashseal

# 卸载
uv tool uninstall hashseal
```

> `curl | sh` 本身是供应链风险，安装前可以先看脚本：
> `curl -fsSL .../install.sh | less`。

---

## 快速开始

### 1. 生成密钥（只需一次）

```bash
hashseal keygen
```

```
私钥: hashseal_private.pem  (0600, 严禁外传、严禁入 git)
公钥: hashseal_public.pem  (可公开分发)
指纹: SHA256:xQrkLFwzEYIa88bsseKnpJfrVJ81CEN4kApprXcX39U
```

把**指纹**通过电话、当面、官网 HTTPS 等**独立于文件**的渠道告诉对方。

### 2. 签名

```bash
hashseal sign app.py --signer "A <a@example.com>"
```

产物：`app.py.sig`（JSON，包含文件摘要、大小、文件名、签名者信息和 Ed25519 签名）。

### 3. 验证

```bash
hashseal verify app.py --pubkey hashseal_public.pem
```

```
结果      : ✅ 通过 —— 内容与签名完全一致，且签名来自该公钥对应的私钥
```

首次使用请核对输出里的**公钥指纹**与对方公布的是否一致。

### 4. 签名 + 时间戳（一步完成）

```bash
hashseal sign app.py --timestamp
```

默认使用 DigiCert，无需额外参数：

```
已签名 app.py
  签名文件: app.py.sig
  时间戳  : app.py.sig.tsr
            2026-11-12 09:13:26 +0800（UTC 2026-11-12 01:13:26）
            由 TSA「DigiCert SHA256 RSA4096 Timestamp Responder 2026 1」见证（证书链: ok）
```

验证时带上令牌：

```bash
hashseal verify app.py --tsr app.py.sig.tsr
```

### 5. 整个目录

```bash
hashseal sign dist/ --timestamp     # 生成清单 + 签名 + 时间戳
hashseal verify dist/               # 清单签名/时间戳 + 逐文件校验
```

```
dist/
├── MANIFEST.sha256          每个文件的 SHA-256
├── MANIFEST.sha256.sig      对清单的签名
└── MANIFEST.sha256.sig.tsr  对清单签名的时间戳
```

---

## 核心概念

### 三件产物

| 文件 | 内容 | 作用 |
| --- | --- | --- |
| `app.py.sig` | JSON：格式版本、算法、摘要、大小、文件名、签名者、签名 | 内容完整性 + 来源 |
| `app.py.sig.tsr` | RFC 3161 `TimeStampResp`（DER） | 签名在何时已存在 |
| `MANIFEST.sha256` | `sha256sum` 格式的清单 | 用一个对象绑定整批文件 |

`.sig` 是自描述 JSON，但**判定只依赖真实文件 + 公钥**；JSON 里的字段被改也骗不过验证
（有专门的单元测试覆盖这一点）。

### 公钥指纹与信任链

```
A 的私钥 ──签名──> 文件 + .sig ──交给 TSA──> .tsr
                        │
B：文件 + .sig + .tsr + A 的公钥
                        │
        核对公钥指纹（电话 / 官网 / 当面）← 只做一次
                        │
                之后所有文件自动验证
```

指纹 = `SHA256:` + base64(SHA-256(公钥 DER))，可用 openssl 独立复算：

```bash
openssl pkey -pubin -in public.pem -outform DER | openssl dgst -sha256 -binary | base64
```

⚠️ **指纹必须走与文件不同的信道**。把公钥和 `.sig` 从同一个聊天窗口一起收下，等于没验证。

### 清单（MANIFEST）为什么存在

逐个签 `.sig` 防不住"删掉文件连同签名"这种降级攻击；而 100 个文件逐个盖时间戳也很浪费。
目录签名因此采用清单打包：

```
MANIFEST.sha256          每个文件的 SHA-256
MANIFEST.sha256.sig      对清单的 Ed25519 签名
MANIFEST.sha256.sig.tsr  对签名的时间戳
```

- 新增、删除、修改任意文件都会导致校验失败；
- 一次签名、一次时间戳覆盖整批；
- 清单是标准 `sha256sum` 格式，可互操作：

```bash
cd dist && sha256sum -c ../MANIFEST.sha256
```

### 时间戳为什么盖在 `.sig` 上

`.sig` 已经把内容绑定死了；给签名盖时间戳，一份令牌同时证明"内容"和"签名时间"。

---

## 命令详解

全局选项：

```bash
hashseal --version        # 0.3.6
hashseal --help
```

### `keygen` — 生成密钥

```
hashseal keygen [--private PATH] [--public PATH] [--force]
```

| 选项 | 默认值 | 说明 |
| --- | --- | --- |
| `--private` | `hashseal_private.pem` | 私钥输出路径（PKCS#8 PEM） |
| `--public` | `hashseal_public.pem` | 公钥输出路径 |
| `--force` | — | 允许覆盖已存在的密钥文件 |

示例：

```bash
hashseal keygen --private ~/.config/hashseal/private.pem \
                --public  ~/.config/hashseal/public.pem
```

说明：

- 私钥权限设为 `0600`；**不支持口令加密**，请放在加密盘 / KMS / HSM；
- 已存在同名文件时默认拒绝覆盖，避免误毁正在使用的密钥；
- 路径必须是文件，传目录会明确报错。

### `fingerprint` — 公钥指纹

```
hashseal fingerprint [PUBLIC]
```

打印 `SHA256:...` 形式的公钥指纹；不传参数时读取 `./hashseal_public.pem`。

```bash
hashseal fingerprint ~/hashseal_public.pem
```

用途只有一个：**核对身份**。它不校验文件、目录或签名；要看"这个目录是谁签的"，用 `verify`。

### `hash` — 计算 SHA-256

```
hashseal hash FILE|DIR... [-v]
```

- 输出与 `sha256sum` 逐字节兼容：`<64 位十六进制>  <路径>`；
- 传目录时递归计算，自动跳过 `.sig`、`.tsr`、`.ots` 与 `.git`、`.venv`、`__pycache__` 等目录；
- `-v` 额外打印每个文件的字节数。

```bash
hashseal hash app.py
hashseal hash dist/ > dist.sha256
```

### `manifest` — 生成清单

```
hashseal manifest PATH... [-o OUTPUT] [--base DIR]
```

| 选项 | 默认值 | 说明 |
| --- | --- | --- |
| `-o, --output` | `MANIFEST.sha256` | 输出路径 |
| `--base` | — | 记录相对路径的基准目录 |

```bash
hashseal manifest dist/ -o dist/MANIFEST.sha256 --base dist
```

生成的格式：

```
57388acbdcf0015d...  a.txt
0263829989b6fd95...  sub/b.txt
```

`hashseal sign DIR` 会自动生成清单，通常不需要手动调用。

### `sign` — 签名

```
hashseal sign FILE|DIR... [选项]
```

| 选项 | 默认值 | 说明 |
| --- | --- | --- |
| `-k, --key` | `hashseal_private.pem` | 私钥路径（当前目录） |
| `--sig` | `<文件>.sig` | 签名输出路径（单文件或单个目录） |
| `--signer` | 空 | 署名备注，仅记录，不参与加密 |
| `--name` | 实际文件名 | 签名时记录的文件名（发布前改名时用） |
| `--timestamp` | 关 | 签名后立即申请 RFC 3161 时间戳 |
| `--tsa` | `http://timestamp.digicert.com` | 时间戳服务地址 |
| `--tsa-ca` | 内置 + 系统 CA | 覆盖时间戳信任根（PEM） |
| `--timeout` | `30` | 时间戳网络超时（秒） |
| `--tsr` | `<签名>.tsr` | 时间戳输出路径（需 `--timestamp`） |
| `--force` | — | 覆盖已存在的 `.sig` / `.tsr` |

行为：

- **单文件** → 生成 `<文件>.sig`；
- **目录** → 自动生成 `MANIFEST.sha256`，只签清单；目录输入不接受 `--sig` / `--name`；
- 可以混合传入多个文件 / 目录；`--sig`、`--tsr` 仅适用于单目标；
- **重复签名**必须加 `--force`。未加 `--force` 时会在改动任何文件**之前**退出（退出码 2），
  不会留下"清单已更新、签名还是旧的"半更新状态；
- 加 `--timestamp` 时，时间戳失败**不会丢签名**：`.sig` 已写入，命令退出码 `1`，
  并提示可重试；
- Ed25519 是确定性签名：内容不变时重复签名的 `sig` 值相同，但 `.sig` 里的 `created` 会更新。

示例：

```bash
# 单文件
hashseal sign app.py --signer "A <a@example.com>"

# 改名发布：把原文件名签进去
hashseal sign build/app.py --name app.py

# 文件 + 时间戳（默认 DigiCert）
hashseal sign app.py --timestamp

# 换 TSA / 内网 TSA
hashseal sign app.py --timestamp --tsa https://freetsa.org/tsr
hashseal sign app.py --timestamp --tsa https://tsa.internal/ --tsa-ca internal-root.pem

# 目录 + 时间戳
hashseal sign dist/ --timestamp

# 重新签名（内容已变）
hashseal sign dist/ --timestamp --force
```

### `verify` — 验证

```
hashseal verify FILE|DIR [选项]
```

| 选项 | 默认值 | 说明 |
| --- | --- | --- |
| `--sig` | `<文件>.sig` | 签名文件路径 |
| `-p, --pubkey` | `hashseal_public.pem` | 公钥 PEM |
| `--name` | 实际文件名 | 文件被改名时，指定签名时记录的原文件名 |
| `--tsr` | —（目录模式自动探测） | 同时校验时间戳令牌 |
| `--ts-only` | 关 | 只校验时间戳，不要求 `.sig` |
| `--tsa-ca` | 内置 + 系统 CA | 时间戳信任根 |
| `--json` | 关 | 输出机器可读结果（目录模式暂不支持） |

四种用法：

```bash
# 1) 只验签名
hashseal verify app.py

# 2) 签名 + 时间戳
hashseal verify app.py --tsr app.py.sig.tsr

# 3) 只验时间戳（不需要签名）
hashseal verify app.py.sig --tsr app.py.sig.tsr --ts-only

# 4) 整个目录（清单签名 + 时间戳 + 逐文件）
hashseal verify dist/
```

输出示例：

```
文件      : app.py
大小      : 128 字节
SHA-256   : 57388acbdcf0015d...
签名记录  : 名称=app.py 大小=128 签名者=A <a@example.com> 时间=2026-11-12T01:00:00+00:00
公钥指纹  : SHA256:xQrkLFwzEYIa88bsseKnpJfrVJ81CEN4kApprXcX39U
结果      : ✅ 通过 —— 内容与签名完全一致，且签名来自该公钥对应的私钥
时间戳    : ✅ 2026-11-12 09:13:26 +0800（UTC 2026-11-12 01:13:26）
            由 TSA「DigiCert ...」见证（信任根: 内置 freetsa 根 + 系统 CA 库，证书链: ok）
```

目录模式会多一行汇总：

```
逐文件校验  : ✅ 12 个文件全部一致
```

判定规则：

- **只依赖真实文件 + 公钥**，`.sig` 的 JSON 元数据被改不影响结论，只用于差异诊断；
- 目录模式先验清单，再逐文件比对 SHA-256；缺文件、多文件、内容变化都会失败；
- `--ts-only` 是显式选择，避免"没有签名"被误认为"签名通过"；
- 文件改名且内容未变时，`--name 原名` 可通过；否则视为不同交付物。

`--json` 主要字段：

```json
{
  "ok": true,
  "signature_valid": true,
  "digest": "...",
  "size": 128,
  "name": "app.py",
  "expected": { "name": "app.py", "size": 128, "digest": "...", "signer": "...", "created": "..." },
  "signer_fingerprint": "SHA256:...",
  "timestamp": { "ok": true, "gen_time": "...", "tsa": "...", "chain": "ok" }
}
```

### `timestamp` — 申请时间戳

```
hashseal timestamp FILE|DIR [选项]
```

| 选项 | 默认值 | 说明 |
| --- | --- | --- |
| `-o, --out` | `<目标>.tsr` | 令牌输出路径 |
| `--tsa` | `http://timestamp.digicert.com` | TSA 地址（可用 `HASHSEAL_TSA` 覆盖） |
| `--tsa-ca` | 内置 + 系统 CA | 信任根 PEM |
| `--timeout` | `30` | 网络超时（秒） |
| `--force` | — | 覆盖已存在的 `.tsr` |
| `--json` | 关 | 输出机器可读结果 |

目录模式自动定位盖章对象：

| 目录状态 | 盖章对象 | 含义 |
| --- | --- | --- |
| 有 `MANIFEST.sha256.sig` | 清单签名 | 证明**签名**在某时刻已存在（推荐） |
| 只有 `MANIFEST.sha256` | 清单本身，并警告 | 只证明清单存在，未证明来源 |
| 都没有 | 报错 | 先执行 `hashseal sign DIR` |

```bash
hashseal timestamp app.py.sig
hashseal timestamp dist/            # 对 dist/MANIFEST.sha256.sig 盖章
hashseal timestamp dist/ --force    # 重新盖章（续期 / 换 TSA）
```

### `ots` — OpenTimestamps

透传 OpenTimestamps 客户端，需要单独安装 `ots`：

```bash
uv tool install opentimestamps-client

hashseal ots stamp app.py.sig
hashseal ots upgrade app.py.sig.ots
hashseal ots verify app.py.sig.ots
```

特点：无需信任第三方，但有确认延迟（等比特币区块），适合长期归档。

---

## 目录支持矩阵

| 命令 | 目录 | 行为 |
| --- | --- | --- |
| `keygen` | ❌ | 输出必须是文件路径 |
| `fingerprint` | ❌ | 需要公钥文件 |
| `hash` | ✅ | 递归计算，跳过 `.sig`/`.tsr`/`.ots` 与缓存目录 |
| `manifest` | ✅ | 生成覆盖整个目录的清单 |
| `sign` | ✅ | 生成清单并签名，可选时间戳 |
| `verify` | ✅ | 验清单签名/时间戳，再逐文件比对 |
| `timestamp` | ✅ | 对 `MANIFEST.sha256.sig` 盖章 |
| `ots` | 透传 | 由 `ots` 客户端决定 |

---

## 时间戳深入

### 默认 TSA 与信任根

- 默认 TSA：`http://timestamp.digicert.com`（可用 `--tsa` 或 `HASHSEAL_TSA` 覆盖）；
- 默认信任根 = **系统 CA 库 + 内置 freetsa 根**：
  - DigiCert / Sectigo 等公共 TSA 通过系统 CA 库验证；
  - freetsa 通过内置根验证，无需下载。
- 内置 freetsa 根指纹固定为
  `2151b61137ffa86bf664691ba67e7da0b19f98c758e3d228d5d8ebf27e044438`，
  随包发布，可在 git 历史中审计。
- 内网 / 私有 TSA 请显式给 `--tsa-ca`，否则链校验会标注 `skipped`。

优先级：

```
--tsa-ca  >  环境变量 HASHSEAL_TSA_CA  >  内置 freetsa 根 + 系统 CA 库
```

### 离线验证与有效期

- **验证不需要联网**：令牌自带证书链和签名，`verify` 在本地完成校验；
- 有 `openssl` 时调用 `openssl ts -verify` 做完整链校验（含 EKU / 关键扩展）；
- 证书有效期按令牌的 `genTime` 判断，**TSA 证书以后过期不影响历史令牌**；
- 令牌要与文件一起长期保存，TSA 一般不补发。

### 连不上 TSA 怎么办

报 `handshake timed out`、`Connection refused`、`Network is unreachable` 属于网络问题，
不是证书问题——申请时间戳必须联网：

```bash
# 换一个可达的 TSA
hashseal sign app.py --timestamp --tsa https://freetsa.org/tsr
hashseal sign app.py --timestamp --tsa http://timestamp.sectigo.com

# 长期固定
export HASHSEAL_TSA=http://timestamp.sectigo.com
```

- 公司代理：urllib 会读取 `HTTPS_PROXY` / `HTTP_PROXY`；
- 某些网络访问 freetsa 会卡在 TLS 握手，所以默认已改为 DigiCert；
- 完全隔离的内网：只能自建 TSA。

### 长期有效性（LTV）

时间戳证明"某时刻已存在"，但算法会过时、TSA 根会退役。超长期归档建议：

1. 在旧令牌失效前，对新令牌再做一次时间戳（令牌续期）；
2. 或采用 Evidence Record（RFC 4998）/ 归档时间戳（RFC 5544）；
3. 一并保存：文件、`.sig`、`.tsr`、TSA 根证书、验证命令与版本。

---

## 退出码与自动化

| 退出码 | 含义 |
| --- | --- |
| `0` | 通过 / 成功 |
| `1` | 校验失败（内容、签名、时间戳），或 `sign --timestamp` 的时间戳申请失败 |
| `2` | 用法错误、路径不存在、IO 错误、参数冲突、`timestamp` 单独执行失败 |

CI 示例：

```bash
hashseal verify dist/ --tsr dist/MANIFEST.sha256.sig.tsr \
  || { echo "校验失败，拒绝部署"; exit 1; }
```

---

## 安全边界

- **脚本无法自证清白**：能改脚本的人也能改内置哈希。要运行前校验，必须使用文件之外的可信启动器。
- **签名证明"谁签的"，不证明"内容是对的"**：签名者也可能签一份坏文件。
- **时间戳证明"什么时候签的"**，不证明内容质量。
- **私钥泄露等于历史签名失效**：请用 0600、加密盘 / KMS / HSM 保管，并准备轮换与吊销。
- **二次转发**：C 必须从可信渠道获取 A 的指纹；只信"B 转发的公钥"，信任链就退化成"信 B"。
- **改名**：默认视为不同交付物；确属改名时显式 `--name 原名`。
- **换行符**：Windows 的 CRLF 转换会改变字节，哈希必变；用二进制模式传输。
- **压缩包**：zip 带时间戳，重新压缩哈希就变——签压缩后的成品。

---

## 常见问题

**Q：时间戳显示 `+00:00`，和本地时间差 8 小时？**
A：那是 UTC。现在输出会同时显示本地时间和 UTC，例如
`2026-11-12 09:13:26 +0800（UTC 2026-11-12 01:13:26）`。令牌里的时间由 TSA 给出，不受本机时钟影响。

**Q：重复执行 `sign` 会覆盖吗？**
A：不加 `--force` 会拒绝，并且在改动任何文件之前退出；加 `--force` 才重新生成清单、重签、重盖时间戳。

**Q：目录里为什么没有每个文件的 `.sig`？**
A：目录采用清单打包，只签 `MANIFEST.sha256`。这样能防"删除文件连同签名"，也避免 N 次时间戳请求。

**Q：`fingerprint` 能验证目录吗？**
A：不能。它只计算公钥指纹；验证目录用 `verify DIR`。

**Q：换电脑后怎么验证？**
A：只需要文件 + `.sig`（+ `.tsr`）+ 发送方公钥。验证不需要网络、不需要私钥。

**Q：旧版 `fileproof` 生成的 `.sig` 还能验吗？**
A：能。hashseal 只读兼容 `fileproof/1` 格式；新签名统一写 `hashseal/1`。

---

## 开发

```bash
uv sync
uv run hashseal --help
uv run python -m hashseal --version
```

测试、离线夹具与攻防演示在独立仓库
[hashseal-dev](https://github.com/renengade/hashseal-dev)：

```bash
git clone https://github.com/renengade/hashseal-dev
cd hashseal-dev
./run-tests.sh        # 默认测试同级 ../hashseal 源码
```

---

## License

MIT
