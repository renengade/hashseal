# 审计与配置

## 配置文件

默认路径 `~/.config/hashseal/config.toml`，可用 `HASHSEAL_CONFIG` 覆盖。

```toml
[hashseal]
tsa = "https://timestamp.digicert.com"
tsa_ca = "/path/to/ca.pem"
key = "~/.config/hashseal/private.pem"
pubkey = "~/.config/hashseal/public.pem"
exclude = ["*.log"]
follow_symlinks = false

audit = true
audit_sink = "both"          # file | syslog | both
audit_file = "~/.local/state/hashseal/audit.jsonl"
audit_max_bytes = 10485760
audit_backups = 5
audit_facility = "user"
```

优先级：命令行 > 环境变量 > 配置文件 > 内置默认值。

## 审计日志

默认写 JSON Lines：

```json
{"ts":"2026-11-13T12:00:00+00:00","event":"sign","path":"dist/MANIFEST.sha256","ok":true,"timestamp":true}
```

- `audit_sink=file`：本地文件，按大小轮转（默认 10 MiB × 5）；
- `audit_sink=syslog`：写入系统 syslog（Unix），不写本地文件；
- `audit_sink=both`：两边都写，syslog 失败不影响文件。

环境变量：

| 变量 | 作用 |
| --- | --- |
| `HASHSEAL_NO_AUDIT=1` | 完全关闭 |
| `HASHSEAL_AUDIT_SINK` | 覆盖 sink |
| `HASHSEAL_AUDIT_LOG` | 覆盖文件路径 |
| `HASHSEAL_AUDIT_MAX_BYTES` | 轮转阈值 |
| `HASHSEAL_AUDIT_BACKUPS` | 保留份数 |

查看：

```bash
hashseal audit -n 50
journalctl -t hashseal        # sink=syslog 时
```

> 本地文件与本地 syslog 都无法防 root 篡改。合规场景应把日志转发到 SIEM 或只写存储。
