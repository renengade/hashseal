# hashseal installer（Windows PowerShell 5.1+，无需 WSL）
#
#   irm https://raw.githubusercontent.com/renengade/hashseal/main/install.ps1 | iex
#
# 安装到 uv 的独立工具环境（不污染系统 Python），并把 hashseal 加入用户 PATH。
# 可用环境变量覆盖（与 install.sh 一致）：
#   HASHSEAL_REF=v0.10.0   指定 tag/分支（生产建议锁定 tag；main 表示跟随开发分支）
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

function Resolve-Latest {
    # 方式 1: GitHub API
    try {
        $headers = @{}
        if ($env:GITHUB_TOKEN) { $headers["Authorization"] = "Bearer $($env:GITHUB_TOKEN)" }
        $json = Invoke-RestMethod -Uri $ApiUrl -TimeoutSec 20 -Headers $headers
        if ($json.tag_name) { return [string]$json.tag_name }
    } catch { }

    # 方式 2: releases/latest 302 redirect（不需要 API）
    try {
        $resp = Invoke-WebRequest -Uri "https://github.com/$Repo/releases/latest" `
            -MaximumRedirection 0 -UseBasicParsing -ErrorAction SilentlyContinue
        if (-not $resp -and $?) { }
    } catch {
        $resp = $_.Exception.Response
    }
    if ($resp -and $resp.Headers) {
        $loc = $resp.Headers["Location"]
        if ($loc) {
            $tag = ($loc -replace ".*/tag/", "").Trim()
            if ($tag -match "^[A-Za-z0-9._-]+$") { return $tag }
        }
    }
    throw "latest"
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
        Die "无法获取 latest release（网络不可达或限流）。请先设置: `$env:HASHSEAL_REF='v0.10.0' 再重试"
    }
    Say "使用最新发布: $Ref"
    $Url = "$ArchiveBase/$Ref.tar.gz"
}

# 1) 确保有 uv
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Say "未找到 uv，正在安装（https://astral.sh/uv）..."
    $script = Invoke-RestMethod -Uri "https://astral.sh/uv/install.ps1"
    ($script | Invoke-Expression) 2>&1 | Out-Null
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

    Say "安装 hashseal ..."
    uv tool install --force $Src
    if ($LASTEXITCODE -ne 0) { Die "uv tool install 失败" }
} finally {
    Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}

# 4) 确保 hashseal 在 PATH 上（写入用户级 PATH）
$BinDir = "$env:USERPROFILE\.local\bin"
try { $uvBin = (uv tool dir --bin) 2>$null; if ($LASTEXITCODE -eq 0 -and $uvBin) { $BinDir = $uvBin } } catch { }

Say ""
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$BinDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$BinDir;$userPath", "User")
    Say "已把 $BinDir 加入用户 PATH（重开终端生效）"
}

$hashseal = Get-Command hashseal -ErrorAction SilentlyContinue
if ($hashseal) {
    Say ("✅ 安装完成: " + $hashseal.Source)
    hashseal --version
} else {
    Say "✅ 已安装。重开 PowerShell 后运行：hashseal --version"
}

Say ""
Say "启动界面: hashseal web        （或 hashseal gui）"
Say "升级: 重新执行本脚本"
Say "卸载: uv tool uninstall hashseal"
