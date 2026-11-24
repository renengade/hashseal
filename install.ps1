# hashseal installer（Windows PowerShell 5.1+，无需 WSL）
#
#   irm https://github.com/renengade/hashseal/releases/latest/download/install.ps1 | iex
#
# 注意：本文件必须保存为 UTF-8（无 BOM）+ CRLF——BOM 会让 `irm | iex` 把首行
# 解析成命令而出错（PS5.1 双击/落盘运行无 BOM 文件会按 ANSI 误读中文，因此
# 落盘运行请先：Get-Content -Raw -Encoding UTF8 install.ps1 | iex）。
#
# 可用环境变量覆盖（与 install.sh 一致）：
#   HASHSEAL_REF=v0.10.4   指定 tag/分支（生产建议锁定 tag；main 表示跟随开发分支）
#   HASHSEAL_REPO=owner/repo
#   HASHSEAL_URL=<url>     直接指定源码包地址（跳过 latest 解析）
#   HASHSEAL_API_URL=<url> 覆盖 latest release API
#   HASHSEAL_SHA256=<hex>  校验下载包
#   GITHUB_TOKEN=<token>   提高 GitHub API 速率限制

#Requires -Version 5.1
$ErrorActionPreference = "Stop"
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

$Repo = if ($env:HASHSEAL_REPO) { $env:HASHSEAL_REPO } else { "renengade/hashseal" }
$ApiUrl = if ($env:HASHSEAL_API_URL) { $env:HASHSEAL_API_URL } else { "https://api.github.com/repos/$Repo/releases/latest" }
$ArchiveBase = if ($env:HASHSEAL_ARCHIVE_BASE) { $env:HASHSEAL_ARCHIVE_BASE } else { "https://github.com/$Repo/archive" }

function Say($msg) { Write-Host $msg }
function Die($msg) { Write-Error $msg; exit 1 }

function Resolve-LatestViaRedirect {
    # releases/latest 是 302 → Location 头就是最新 tag。
    # 用 .NET HttpWebRequest 关自动跳转，跨 PS5.1/PS7 都能拿到 Location。
    $resp = $null
    try {
        $req = [System.Net.HttpWebRequest]::Create("https://github.com/$Repo/releases/latest")
        $req.AllowAutoRedirect = $false
        $req.Timeout = 15000
        $req.UserAgent = "hashseal-installer"
        try { $resp = $req.GetResponse() } catch { $resp = $_.Exception.Response }
        if (-not $resp) { return $null }
        $loc = $resp.Headers["Location"]
        if (-not $loc) { return $null }
        $tag = ($loc -replace ".*/tag/", "").Trim()
        if ($tag -match "^[A-Za-z0-9._-]+$") { return $tag }
        return $null
    } finally {
        if ($resp) { $resp.Close() }
    }
}

function Resolve-Latest {
    # 方式 1: GitHub API
    try {
        $headers = @{}
        if ($env:GITHUB_TOKEN) { $headers["Authorization"] = "Bearer $($env:GITHUB_TOKEN)" }
        $json = Invoke-RestMethod -Uri $ApiUrl -TimeoutSec 20 -Headers $headers
        if ($json.tag_name) { return [string]$json.tag_name }
    } catch { }

    # 方式 2: 302 redirect（不需要 API）
    $tag = Resolve-LatestViaRedirect
    if ($tag) { return $tag }

    throw "latest"
}

function Show-OpenSSLStatus {
    if (Get-Command openssl -ErrorAction SilentlyContinue) {
        Say "OpenSSL: 已安装（时间戳证书链校验可用）"
        return
    }
    Say "未检测到 OpenSSL：仅影响时间戳的 TSA 证书链校验，普通签名/验证不需要。"
    Say "需要可信时间戳时，请在允许的环境中安装 OpenSSL，或使用 WSL 侧 GUI / 跳过链校验。"
    Say "（安装器不会自动安装 OpenSSL，避免与企业软件管控冲突。）"
}

if (-not (Get-Command tar -ErrorAction SilentlyContinue)) {
    Die "需要 tar.exe（Windows 10 1803+ 自带）；请在高级设置里启用或手动解压源码包"
}

# 0) 解析要安装的版本
if ($env:HASHSEAL_URL) {
    $Ref = if ($env:HASHSEAL_REF) { $env:HASHSEAL_REF } else { "custom" }
    $Url = $env:HASHSEAL_URL
} elseif ($env:HASHSEAL_REF) {
    $Ref = $env:HASHSEAL_REF
    $Url = "$ArchiveBase/$Ref.tar.gz"
} else {
    try {
        $Ref = Resolve-Latest
    } catch {
        Die "无法获取 latest release（网络不可达或限流）。请先设置: `$env:HASHSEAL_REF='v0.10.4' 再重试"
    }
    Say "使用最新发布: $Ref"
    $Url = "$ArchiveBase/$Ref.tar.gz"
}

# 1) 确保有 uv
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Say "未找到 uv，正在安装（https://astral.sh/uv）..."
    $script = Invoke-RestMethod -Uri "https://astral.sh/uv/install.ps1"
    ($script | Invoke-Expression) | Out-Null
    $env:Path = "$env:USERPROFILE\.local\bin;$env:Path"
}
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Die "uv 安装失败，请手动安装后重试：https://docs.astral.sh/uv/getting-started/installation/"
}

# 2) 下载源码包
$Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("hashseal-install-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $Tmp | Out-Null
try {
    Say "下载 $Url"
    Invoke-WebRequest -Uri $Url -OutFile (Join-Path $Tmp "src.tar.gz") -UseBasicParsing

    if ($env:HASHSEAL_SHA256) {
        $actual = (Get-FileHash (Join-Path $Tmp "src.tar.gz") -Algorithm SHA256).Hash.ToLower()
        if ($actual -ne $env:HASHSEAL_SHA256.ToLower()) {
            Die "SHA-256 校验失败（期望 $($env:HASHSEAL_SHA256)，实际 $actual）"
        }
        Say "SHA-256 校验通过"
    }

    # 3) 解包并安装到独立环境
    tar -xzf (Join-Path $Tmp "src.tar.gz") -C $Tmp
    if ($LASTEXITCODE -ne 0) { Die "解压失败" }
    $Src = (Get-ChildItem $Tmp -Directory | Select-Object -First 1).FullName
    if (-not $Src) { Die "源码包结构异常" }

    # Windows 文件锁：运行中的旧 hashseal 会导致 uv tool install --force 失败
    $running = @(Get-CimInstance Win32_Process -Filter "Name = 'hashseal.exe'" -ErrorAction SilentlyContinue)
    if (-not $running) {
        $running = @(
            Get-CimInstance Win32_Process -Filter "Name like 'python%'" -ErrorAction SilentlyContinue |
                Where-Object { $_.CommandLine -match 'hashseal' }
        )
    }
    if ($running.Count -gt 0) {
        Say "检测到运行中的 hashseal 进程，正在停止以完成升级 ..."
        foreach ($proc in $running) {
            Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Seconds 1
    }

    Say "安装 hashseal ..."
    uv tool install --force $Src
    if ($LASTEXITCODE -ne 0) { Die "uv tool install 失败" }
} finally {
    Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}

# 4) 确保 hashseal 在 PATH 上（当前会话 + 用户级持久化）
$BinDir = "$env:USERPROFILE\.local\bin"
try { $uvBin = (uv tool dir --bin) 2>$null; if ($LASTEXITCODE -eq 0 -and $uvBin) { $BinDir = ($uvBin | Select-Object -First 1) } } catch { }
$env:Path = "$BinDir;$env:Path"

Say ""
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$BinDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$BinDir;$userPath", "User")
    Say "已把 $BinDir 加入用户 PATH（重开终端生效）"
}

if (-not (Test-Path (Join-Path $BinDir "hashseal.exe"))) {
    Die "安装后未找到 hashseal.exe（$BinDir）。请重试；若仍失败请运行 uv tool install --force 并查看输出"
}

$hashseal = Get-Command hashseal -ErrorAction SilentlyContinue
if ($hashseal) {
    Say ("✅ 安装完成: " + $hashseal.Source)
    hashseal --version
} else {
    Say "✅ 已安装。重开 PowerShell 后运行：hashseal --version"
}

Say ""
Show-OpenSSLStatus
Say ""
Say "启动界面: hashseal web        （或 hashseal gui）"
Say "升级: 重新执行本脚本"
Say "卸载: uv tool uninstall hashseal"
