# hashseal

用 **SHA-256 + Ed25519 + RFC 3161** 证明文件“没被改过、是谁发的、什么时候发的”。

## 安装

```bash
curl -fsSL https://raw.githubusercontent.com/renengade/hashseal/main/install.sh | sh
```

## 三分钟上手

```bash
hashseal keygen
hashseal sign app.py --signer "A <a@example.com>"
hashseal verify app.py
```

目录与时间戳：

```bash
hashseal sign dist/ --timestamp
hashseal verify dist/
```

完整命令、配置与安全说明见
[GitHub README](https://github.com/renengade/hashseal#readme)。
