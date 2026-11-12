# hashseal

用 **SHA-256 + Ed25519 + RFC 3161** 证明三件事：

1. 文件有没有被改过；
2. 是不是某个人发出的（而不是别人冒充）；
3. 是**什么时候**签的，事后能不能抵赖。

一条命令搞定签名与验证，安装后**全局可用**，不污染系统 Python。

---

## 安装

```bash
curl -fsSL https://raw.githubusercontent.com/renengade/hashseal/main/install.sh | sh
```

脚本会确保有 [uv](https://docs.astral.sh/uv/)，把 hashseal 装进独立工具环境，并链接到 `~/.local/bin`。

生产环境建议锁定版本，而不是跟随 `main`：

```bash
curl -fsSL https://raw.githubusercontent.com/renengade/hashseal/main/install.sh | HASHSEAL_REF=v0.3.4 sh
```

其他安装方式：

```bash
uv tool install git+https://github.com/renengade/hashseal   # 需要 git
pipx install git+https://github.com/renengade/hashseal      # 习惯 pipx 的话
```

升级与卸载：

```bash
# 升级：重新跑安装脚本即可
uv tool uninstall hashseal
```

> `curl | sh` 本身是供应链风险。安装前可以先看脚本：
> `curl -fsSL .../install.sh | less`。

### 国内网络 / 镜像

安装依赖分三部分，可分别走镜像：

```bash
# 1) uv 本体（脚本会自动安装）走 GitHub 代理
export UV_INSTALLER_GITHUB_BASE_URL=https://ghfast.top/https://github.com

# 2) PyPI 依赖走国内镜像（uv 不读 PIP_INDEX_URL，必须用 UV_DEFAULT_INDEX）
export UV_DEFAULT_INDEX=https://pypi.tuna.tsinghua.edu.cn/simple

# 3) hashseal 源码包走任意可达地址（GitHub 代理 / Gitee 镜像 / 自建）
export HASHSEAL_URL=https://ghfast.top/https://github.com/renengade/hashseal/archive/main.tar.gz

curl -fsSL https://raw.githubusercontent.com/renengade/hashseal/main/install.sh | sh
```

- freetsa 根证书已内置，**不需要**访问 freetsa，也不存在"证书镜像"这回事。
- 第三方 GitHub 代理会看到并转发下载内容，属供应链信任边界；对安全敏感的环境请用自建镜像并校验 SHA-256。
- 发布到 PyPI 后可直接走索引镜像，不经过 GitHub：
  `UV_DEFAULT_INDEX=https://pypi.tuna.tsinghua.edu.cn/simple uv tool install hashseal`。

---

## 60 秒上手

```bash
# A：一次性生成密钥（私钥 0600，切勿外传/入 git）
hashseal keygen
#   → hashseal_private.pem / hashseal_public.pem / 指纹 SHA256:...

# A：签名
hashseal sign app.py --signer "A <a@example.com>"

# A：签名 + 时间戳一步完成（需要联网）
hashseal sign app.py --timestamp

# B：验证（任意目录都能用）
hashseal verify app.py --pubkey hashseal_public.pem
```

```
结果      : ✅ 通过 —— 内容与签名完全一致，且签名来自该公钥对应的私钥
```

退出码：`0` 通过 / `1` 不一致 / `2` 用法或 IO 错误，可直接用于 CI：

```bash
hashseal verify app.py -p pub.pem || { echo "校验失败，拒绝部署"; exit 1; }
```

---

## 它能证明什么，不能证明什么

| 层级 | 手段 | 能发现 / 能证明 | 防不住 |
| --- | --- | --- | --- |
| L1 | SHA-256 校验和 | 传输损坏、误改 | 文件 + 哈希被一起替换 |
| **L2** | **Ed25519 签名** | 篡改、冒充、改名 | 私钥泄露；签名者签了坏文件 |
| **L3** | **L2 + RFC 3161 时间戳** | 外加"某时刻已存在"、不可否认 | 私钥泄露；TSA 不可信 |

**哈希一致 ≠ 运行行为一致。** Python 版本、依赖版本、环境变量都可能让同一份脚本行为不同；要环境一致，请配合锁文件（如 `uv.lock`）或容器，并把镜像 digest 一起签。

---

## 常用命令

```bash
hashseal keygen       [--private P] [--public P] [--force]
hashseal fingerprint  [PUBLIC]
hashseal hash         FILE...                    # 输出与 sha256sum 兼容
hashseal manifest     PATH... [-o OUT] [--base DIR]
hashseal sign         FILE|DIR... [-k 私钥] [--signer 文本] [--name 名字]
                              [--timestamp] [--tsa URL] [--tsa-ca 根] [--tsr 路径]
hashseal verify       FILE|DIR [--sig 路径] [-p 公钥] [--name 原名]
                              [--tsr 令牌] [--ts-only] [--tsa-ca 根证书]
hashseal timestamp    FILE|DIR [--tsa URL] [--tsa-ca 根证书]
hashseal ots          stamp|verify|upgrade FILE   # 可选：OpenTimestamps
```

### 对整个目录签名

直接传目录即可，内部会自动生成 `MANIFEST.sha256`，只签**清单**、只申请**一次**时间戳：

```bash
# A：一条命令搞定整个目录（含时间戳）
hashseal sign dist/ --timestamp

# 产物
#   dist/MANIFEST.sha256          每个文件的 SHA-256
#   dist/MANIFEST.sha256.sig      对清单的签名
#   dist/MANIFEST.sha256.sig.tsr  对清单签名的时间戳

# B：一条命令验证整个目录
hashseal verify dist/
#   → 先验清单的签名 + 时间戳，再逐个比对文件内容
```

行为说明：

- 目录里新增/删除/改动任意文件，`verify dist/` 都会失败（清单绑定的是完整集合）；
- 遍历时自动跳过 `.sig` / `.tsr` / `.ots`、`MANIFEST.sha256`，以及 `.git`、`.venv`、`__pycache__` 等目录；
- 签名/时间戳都只有一份，不会因为文件多而产生 N 次网络请求；
- **重复签名必须显式加 `--force`**：未加时会在改动任何文件之前退出（退出码 2），
  不会留下"清单已更新、签名还是旧的"这种半更新状态；
- `--force` 会重新生成清单、重签；若同时带 `--timestamp`，还会重新申请时间戳（旧 `.tsr` 被覆盖）；
- 需要更细粒度控制时，仍可手动 `manifest` + `sign MANIFEST.sha256`。

---

## 可信时间戳（L3）

```bash
# 一步完成：签名 + 时间戳（失败时保留 .sig，退出码 1）
hashseal sign app.py --timestamp

# 也可以分两步：先签名，再单独盖章
hashseal timestamp app.py.sig

# B：签名 + 时间戳一起验（离线即可）
hashseal verify app.py --tsr app.py.sig.tsr

# 只验时间戳、不要求签名（原 check-timestamp）
hashseal verify app.py.sig --tsr app.py.sig.tsr --ts-only
```

目录也可以直接盖章/核验（自动定位 `MANIFEST.sha256.sig`）：

```bash
hashseal timestamp dist/           # 对 dist/MANIFEST.sha256.sig 申请时间戳
hashseal verify dist/ --ts-only    # 自动读取 dist/MANIFEST.sha256.sig.tsr
```

- **默认 TSA 是 DigiCert**（`http://timestamp.digicert.com`），一般网络都可直连；
  默认信任根 = 系统 CA 库 + 内置 freetsa 根，开箱即用，A/B 都不用手动下载。
- 要换 TSA 时才需要 `--tsa`；临时固定用 `export HASHSEAL_TSA=...`。
- `--tsr` 是**时间戳输出路径**，不是选择 TSA；不写就默认 `<签名>.tsr`。
- 需要换信任根时：`--tsa-ca your-ca.pem` 或环境变量 `HASHSEAL_TSA_CA`。
- 公共 TSA（DigiCert / Sectigo / freetsa）都被默认信任根覆盖，可直接 `--tsa` 换；
  **内网/私有 TSA** 请显式给出 `--tsa-ca`，否则链校验标注 `skipped`。
- 时间戳盖在 **`.sig`** 上：一份令牌同时绑定内容和签名时间。
- 验证**不需要联网**，令牌自带证书链；有 openssl 时在本地完成链校验。
- 校验证书有效期用的是**签发时刻**，所以 TSA 证书以后过期不影响历史令牌。
- 令牌要与文件一起长期保存，TSA 一般不补发。

### 连不上 TSA 怎么办

`timestamp` 报 `handshake timed out`、`Connection refused` 或 `Network is unreachable`，是**网络问题**，
不是证书问题——时间戳必须在线申请，内置根只负责验证、免去下载 CA。

默认用 DigiCert；若它不可达，换一个：

```bash
hashseal sign app.py --timestamp --tsa https://freetsa.org/tsr
hashseal sign app.py --timestamp --tsa http://timestamp.sectigo.com

# 长期固定
export HASHSEAL_TSA=http://timestamp.sectigo.com
```

- 公司代理：urllib 会读取 `HTTPS_PROXY` / `HTTP_PROXY`。
- 某些网络访问 freetsa 会卡在 TLS 握手，所以默认已改为 DigiCert。
- 完全隔离的内网：只能自建 TSA；OpenTimestamps 同样需要外网。

---

## 信任从哪来

`verify` 会打印公钥指纹：

```
SHA256:xQrkLFwzEYIa88bsseKnpJfrVJ81CEN4kApprXcX39U
```

它是对公钥 DER 编码做 SHA-256 的 base64 结果。**请通过另一条信道**（电话、当面、官网 HTTPS）与发送方核对一次；一致就代表这把公钥确实是对方的，之后所有文件都能自动验证。

⚠️ 如果公钥和 `.sig` 是从同一个聊天窗口一起收到的，等于没验证——中间人可以把两者一起换掉。

---

## 安全边界

- 脚本**无法自证清白**：能改脚本的人也能改内置哈希。要运行前校验，必须用文件之外的可信启动器。
- 私钥泄露等于所有历史签名失效：请用 0600、加密盘/KMS/HSM 保管，并准备轮换。
- 签名证明"谁签的"，不证明"内容是对的"；时间戳证明"什么时候签的"，不证明内容质量。
- 默认用**内置 freetsa 根 + 系统 CA 库**校验证书链；私有 TSA 没给 `--tsa-ca` 时会标注 `skipped`，别把"签名有效"当成"TSA 可信"。

---

## 开发

```bash
uv sync                 # 创建 .venv
uv run hashseal --help
uv run python -m hashseal --version
```

## License

MIT
