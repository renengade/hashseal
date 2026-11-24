# 审计与配置

## 配置文件

默认路径 `~/.config/hashseal/config.toml`，可用 `HASHSEAL_CONFIG` 覆盖；
`hashseal config-init` 生成模板，`hashseal config` 查看生效值。

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

> **Windows 路径写法**：TOML 双引号里的 `\` 是转义。请用正斜杠
> `key = "C:/Users/me/key.pem"` 或单引号 `key = 'C:\Users\me\key.pem'`。
> 解析失败时 hashseal 会给出这条提示。

## 审计日志

默认写 JSON Lines，按天或 10 MiB 滚动，超过 90 天的归档自动删除；
`audit` 会读取活跃文件与归档。

审计日志**始终开启**，没有关闭开关；CLI 与 GUI 的每个操作都记录。

```json
{
  "ts": "2026-11-24T12:00:00+00:00",
  "ts_local": "2026-11-24 20:00:00 +0800（UTC 2026-11-24 12:00:00）",
  "event": "sign",
  "source": "cli",
  "user": "jianglinlin",
  "uid": 1000,
  "hostname": "workstation",
  "ip": "192.168.1.20",
  "path": "dist/.hashseal/MANIFEST.sha256",
  "ok": true
}
```

- `source`：`cli` 或 `gui`；
- 失败也会留痕：命令异常退出且尚未写过失败事件时，补一条
  `{"event":"command_failed","command":"verify","error":"…","exit_code":2}`；
  命令自身已审计失败（`ok:false`）时不重复；
- 操作者信息：`user`、`uid`、`hostname`、主 IPv4 `ip`；SSH 下附 `ssh_client`，
  `sudo` 下附 `sudo_user`。

sink：

- `file`：本地文件（按天/大小滚动，保留 90 天）；
- `syslog`：写入系统 syslog（Unix；Windows 无 syslog，自动回退文件）；
- `both`：两边都写，syslog 失败不影响文件。

环境变量：

| 变量 | 作用 |
| --- | --- |
| `HASHSEAL_AUDIT_SINK` | 覆盖 sink |
| `HASHSEAL_AUDIT_LOG` | 覆盖文件路径 |
| `HASHSEAL_AUDIT_MAX_BYTES` | 轮转阈值 |
| `HASHSEAL_AUDIT_RETENTION_DAYS` | 保留天数（默认 90） |

查看：

```bash
hashseal audit -n 50          # 最近 50 条
hashseal audit -n 500 --json  # 原始 JSON Lines
```

GUI 的「审计」页提供同样内容（按事件/路径过滤）。

> 本地文件与本地 syslog 都无法防 root 篡改；审计没有哈希链/外部锚点，
> 合规场景应把日志转发到 SIEM 或只写存储。
