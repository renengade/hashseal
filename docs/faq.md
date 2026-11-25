# 常见问题

**Q：时间戳显示 `+00:00`，和本地时间差 8 小时？**
A：那是 UTC。输出同时显示本地时间和 UTC；令牌时间由 TSA 给出，不受本机时钟影响。

**Q：重复执行 `sign` 会覆盖吗？**
A：不加 `--force` 会拒绝，且在改动任何文件之前退出；加 `--force` 才覆盖。

**Q：目录里为什么没有每个文件的 `.sig`？**
A：目录采用清单打包，只签 `MANIFEST.sha256`。防「删除文件连同签名」，避免 N 次时间戳请求。

**Q：换电脑后怎么验证？**
A：只需要文件 + `.sig`（+ `.tsr`）+ 发送方公钥。验证不需要网络、不需要私钥。

**Q：旧版 `fileproof` 生成的 `.sig` 还能验吗？**
A：能。只读兼容 `fileproof/1` 与 `hashseal/1`；新签名写 `hashseal/2`。

**Q：手动解压 bundle 后 `verify` 报「未列入」两个文件？**
A：0.10.18+ 已把 `hashseal-bundle.json`、`hashseal-public.pem` 放进 `.hashseal/`，
并按固定路径忽略，手动解压后可直接验证；旧 bundle 同样兼容。注意 `.hashseal/`
只允许已知元数据，放入其他文件仍会被判为未列入（防绕过）。

**Q：SBOM 默认生成到哪里？为什么不放进已签名目录？**
A：默认生成在与目录同级的 `<目录>.cdx.json`。放进已签名目录会变成未列入文件，
导致 `verify` 失败；`bundle` 也不会自动包含 SBOM，需要分发时单独签名，
或放进目录后重新签名打包。

**Q：`.sig` 里的 `created` 是可信时间吗？**
A：不是。它是签名者自填的声明时间，未参与签名；可信时间看 `.tsr`。

**Q：`fingerprint` 能验证目录吗？**
A：不能。它只计算公钥指纹；验证目录用 `verify DIR`。

**Q：GUI 和 CLI 操作会冲突吗？**
A：可以同时使用，共用同一套密钥/配置/审计。避免对同一文件同时写 `.sig`；
GUI 的任务是串行执行的。

**Q：启动命令是 `hashseal web` 还是 `hashseal gui`？**
A：推荐 `hashseal web`；`hashseal gui` 保留为兼容别名（旧脚本/习惯仍可用）。

**Q：浏览器提示 401 会话无效？**
A：服务重启后 token 会变化。回终端复制新地址（含 `#token=…`）重新打开。

**Q：GUI 为什么能浏览整个磁盘？可以限制吗？**
A：默认放开整机（本地 token 保护），方便选择任意目录；启动时加
`--restrict-roots` 即收紧为「主目录 + 当前目录 + `--root`」白名单。

**Q：TSA 是 HTTP 的，为什么还需要本机 OpenSSL？**
A：HTTP 只影响与 TSA 的传输；TSA 返回的令牌带有 TSA 证书与签名。hashseal 需要在本机
验证「令牌签名 + 证书链是否链到可信根（含 timeStamping EKU、有效期）」，
这一步目前调用本机 `openssl` 完成（不是访问 TSA 需要它）。没有它时普通签名/验证照常，
只跳过时间戳或明确使用 `--allow-unverified-chain`。

**Q：Windows 上签名报错「未安装 openssl」，必须安装吗？**
A：不是必须。只有**时间戳的 TSA 证书链校验**需要它；普通签名/验证、目录、bundle、
审计都不需要。Windows 安装器**不会自动安装**（避免与企业软件管控冲突），只检测并提示；
按公司政策决定是否安装，或使用 WSL 侧 / 跳过时间戳。需要时也可手动安装
`winget install ShiningLight.OpenSSL.Light`（或把 Git for Windows 的 openssl 加入 PATH），
装完刷新 GUI 即可。明确接受风险可用 `--allow-unverified-chain`（只跳过链校验）。

**Q：Windows 的 TOML 配置写了 `C:\...` 读不出来？**
A：双引号里的 `\` 是转义。改成 `C:/...` 或单引号 `'C:\...'`；hashseal 会提示这一点。

**Q：GUI 为什么没有“CLI 原始输出”？**
A：结果是结构化的（字段、表格、原因），比原始文本更可靠；需要复现时用 CLI。

**Q：弱口令为什么 CLI 能生成、GUI 不能？**
A：GUI 面向人工操作，强制「≥8 位 + 至少 3 种字符类型」；
CLI 为兼容脚本只警告。生产环境建议始终设置强口令。

**Q：WSL 和 Windows 都要各装一次吗？**
A：是。两边是独立安装（各自的密钥/配置/审计），升级也需分别执行；
`hashseal --version` 可核对。

**Q：解包别人给的 bundle 安全吗？**
A：有 zip-slip、符号链接、条目数（10 万）与解压后大小（8 GiB）防护；
但仍建议先用可信公钥验证，再使用内容。
