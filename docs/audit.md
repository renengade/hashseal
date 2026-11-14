# 审计与配置

## 配置文件

默认路径 `~/.config/hashseal/config.toml`，可用 `HASHSEAL_CONFIG` 覆盖。

```toml
[hashseal]
tsa = "http://timestamp.digicert.com"
tsa_ca = "/path/to/ca.pem"
key = "~/.config/hashseal/private.pem"
pubkey = "~/.config/hashseal/public.pem"
exclude = ["*.log"]
follow_symlinks = false

audit_sink = "both"          # file | syslog | both
audit_file = "~/.local/state/hashseal/audit.jsonl"
audit_max_bytes = 10485760
audit_retention_days = 90
audit_facility = "user"
```

优先级：命令行 > 环境变量 > 配置文件 > 内置默认值。

## 审计日志

默认写 JSON Lines，按天或 10 MiB 滚动，超过 90 天的归档自动删除。`audit` 会同时读取活跃文件与归档。

```json
{
  "ts": "2026-11-13T12:00:00+00:00",
  "ts_local": "2026-11-13 20:00:00 +0800（UTC 2026-11-13 12:00:00）",
  "event": "sign",
  "user": "jianglinlin",
  "uid": 1000,
  "hostname": "workstation",
  "ip": "192.168.1.20",
  "path": "dist/.hashseal/MANIFEST.sha256",
  "ok": true
}
```

审计日志始终开启，不提供关闭开关。每条记录包含操作者 `user`、`uid`、
`hostname` 与主 IPv4 `ip`；通过 SSH 执行时额外记录 `ssh_client`，`sudo` 下记录 `sudo_user`。

> CLI 没有“客户端/服务端”概念，`ip` 是本机主 IP；`ssh_client` 才是 SSH 来源 IP。

- `audit_sink=file`：本地文件，按天或 10 MiB 滚动，默认保留 90 天；
- `audit_sink=syslog`：写入系统 syslog（Unix）；不可用时回退本地文件；
- `audit_sink=both`：两边都写，syslog 失败不影响文件。

环境变量：

| 变量 | 作用 |
| --- | --- |
| `HASHSEAL_AUDIT_SINK` | 覆盖 sink |
| `HASHSEAL_AUDIT_LOG` | 覆盖文件路径 |
| `HASHSEAL_AUDIT_MAX_BYTES` | 轮转阈值 |
| `HASHSEAL_AUDIT_RETENTION_DAYS` | 保留天数（默认 90） |

查看：

```bash
hashseal audit -n 50
journalctl -t hashseal        # sink=syslog 时
```

> 本地文件与本地 syslog 都无法防 root 篡改。合规场景应把日志转发到 SIEM 或只写存储。
