# 性能

实测 256 MB 随机数据（单文件）：

| 操作 | 优化前 | 优化后 |
| --- | --- | --- |
| sign / verify 哈希 | ~0.3 s | ~0.3–0.5 s |
| bundle | **6.6 s**（deflate） | **1.9 s**（stored） |
| unpack | 2.6 s | **1.0 s** |

- bundle 默认**不压缩**（stored）：zip 仅作容器，GB 级交付物通常已压缩；
- 需要减小体积用 `--compress deflate`；
- 多文件目录可用 `-j N` 并行计算哈希。

## GB 级优化空间

| 方向 | 预期收益 |
| --- | --- |
| zstd 压缩 | deflate 快 3–5×，需 PyPI 依赖 |
| 并行哈希 | 已覆盖多文件 |
| 磁盘 I/O | stored 模式主要瓶颈是磁盘 |
