#Requires -Version 5.1
<#
    hashseal installer for Windows PowerShell 5.1 / PowerShell 7+

    用法：
        irm https://raw.githubusercontent.com/renengade/hashseal/main/install.ps1 | iex

    可用环境变量覆盖：
        $env:HASHSEAL_REF  = 'v0.3.7'        指定 tag / 分支 / commit
        $env:HASHSEAL_REPO = 'owner/repo'    指定仓库
        $env:HASHSEAL_URL  = 'https://...zip' 直接指定源码包（.zip 或 .tar.gz）

    说明：
    - 通过 uv 安装到独立工具环境，不污染系统 Python；
    - 失败时用 throw 结束，不会关闭你的 PowerShell 会话；
    - 不修改文件权限之外的系统设置，只可能追加用户 PATH。
#>

# 记住当前会话设置，结束时恢复，避免 iex 改变用户的全局偏好
$OldEAP = $ErrorActionPreference
$OldPythonUtf8 = $env:PYTHONUTF8
$OldConsoleEncoding = $null
try { $OldConsoleEncoding = [Console]::OutputEncoding } catch { }

$ErrorActionPreference = 'Stop'

# PS 5.1 默认可能未启用 TLS 1.2
try {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

# 中文输出尽量不走 GBK
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }
$env:PYTHONUTF8 = '1'

function Restore-Session {
    $global:ErrorActionPreference = $OldEAP
    if ($null -eq $OldPythonUtf8) {
        Remove-Item Env:PYTHONUTF8 -ErrorAction SilentlyContinue
    } else {
        $env:PYTHONUTF8 = $OldPythonUtf8
    }
    if ($null -ne $OldConsoleEncoding) {
        try { [Console]::OutputEncoding = $OldConsoleEncoding } catch { }
    }
}

$Repo = if ($env:HASHSEAL_REPO) { $env:HASHSEAL_REPO } else { 'renengade/hashseal' }
$Ref  = if ($env:HASHSEAL_REF)  { $env:HASHSEAL_REF }  else { 'main' }
$Url  = $env:HASHSEAL_URL

$Sep = [IO.Path]::PathSeparator

function Write-Step([string]$Message) {
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Fail([string]$Message) {
    Write-Host "错误: $Message" -ForegroundColor Red
    Restore-Session
    throw $Message
}

# ---------------------------------------------------------------------------
# 1) 确保有 uv
# ---------------------------------------------------------------------------
$uv = Get-Command uv -ErrorAction SilentlyContinue
if (-not $uv) {
    Write-Step '未找到 uv，正在安装（https://astral.sh/uv）...'
    try {
        Invoke-RestMethod -Uri 'https://astral.sh/uv/install.ps1' -TimeoutSec 300 | Invoke-Expression
    } catch {
        Fail "uv 安装失败: $($_.Exception.Message)"
    }

    # 刷新当前会话 PATH（uv 安装在 ~/.local/bin）
    $candidates = @(
        (Join-Path $HOME '.local/bin'),
        (Join-Path $HOME '.cargo/bin')
    )
    $env:Path = (($candidates + $env:Path) | Where-Object { $_ }) -join $Sep
    $uv = Get-Command uv -ErrorAction SilentlyContinue
    if (-not $uv) {
        Fail 'uv 安装后仍未找到，请重开终端后重试，或手动安装 uv。'
    }
}
Write-Step "uv: $(& uv --version)"

# ---------------------------------------------------------------------------
# 2) 下载源码包
# ---------------------------------------------------------------------------
$Work = Join-Path ([IO.Path]::GetTempPath()) ("hashseal-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Work -Force | Out-Null

$OldProgress = $ProgressPreference
$ProgressPreference = 'SilentlyContinue'   # PS 5.1 进度条会严重拖慢下载
try {
    if ($Url) {
        $archiveUrl = $Url
    } else {
        $archiveUrl = "https://github.com/$Repo/archive/$Ref.zip"
    }

    $isTar = $archiveUrl -match '\.(tar\.gz|tgz)$'
    $archive = Join-Path $Work ($(if ($isTar) { 'src.tar.gz' } else { 'src.zip' }))

    Write-Step "下载 $archiveUrl"
    try {
        Invoke-WebRequest -Uri $archiveUrl -OutFile $archive -UseBasicParsing -TimeoutSec 600
    } catch {
        Fail "下载失败（检查仓库/分支/网络，或设置 HASHSEAL_REF / HASHSEAL_URL）: $($_.Exception.Message)"
    }

    # Expand-Archive 要求 .zip 扩展名，所以归档文件按类型命名
    if ($isTar) {
        if (-not (Get-Command tar -ErrorAction SilentlyContinue)) {
            Fail '解压 .tar.gz 需要 tar（Windows 10 1803+ 自带）；也可以改用 .zip 地址'
        }
        & tar -xzf $archive -C $Work
        if ($LASTEXITCODE -ne 0) { Fail '解压失败（需要 tar，Windows 10 1803+ 自带）' }
    } else {
        try {
            Expand-Archive -Path $archive -DestinationPath $Work -Force
        } catch {
            Fail "解压失败: $($_.Exception.Message)"
        }
    }

    $src = Get-ChildItem -LiteralPath $Work -Directory |
        Where-Object { Test-Path (Join-Path $_.FullName 'pyproject.toml') } |
        Select-Object -First 1
    if (-not $src) { Fail '源码包结构异常：找不到包含 pyproject.toml 的目录' }

    # -----------------------------------------------------------------------
    # 3) 安装到 uv tool 环境
    # -----------------------------------------------------------------------
    Write-Step '安装 hashseal ...'
    & uv tool install --force $src.FullName
    if ($LASTEXITCODE -ne 0) { Fail "uv tool install 失败（退出码 $LASTEXITCODE）" }
}
finally {
    $ProgressPreference = $OldProgress
    Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# 4) 确保可执行文件在 PATH 上
# ---------------------------------------------------------------------------
$binDir = (& uv tool dir --bin 2>$null | Select-Object -First 1)
if ($binDir) { $binDir = $binDir.Trim() }
if (-not $binDir) {
    $binDir = if ($env:USERPROFILE) { Join-Path $env:USERPROFILE '.local\bin' } else { Join-Path $HOME '.local/bin' }
}

$pathEntries = $env:Path -split [Regex]::Escape($Sep)
if ($pathEntries -notcontains $binDir) {
    $env:Path = "$binDir$Sep$env:Path"
}

$cmd = Get-Command hashseal -ErrorAction SilentlyContinue
Write-Host ''
if ($cmd) {
    Write-Host "✅ 安装完成: $($cmd.Source)" -ForegroundColor Green
    & hashseal --version
} else {
    Write-Host "✅ 已安装，但 $binDir 不在 PATH 中。" -ForegroundColor Yellow
    $isWindowsOS = ($env:OS -eq 'Windows_NT') -or ($PSVersionTable.PSEdition -eq 'Desktop')
    if ($isWindowsOS) {
        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        if (-not $userPath) { $userPath = '' }
        if (($userPath -split ';') -notcontains $binDir) {
            $newPath = ($userPath.TrimEnd(';') + ';' + $binDir).TrimStart(';')
            [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
            Write-Host "已把 $binDir 写入用户 PATH，请重开终端后运行: hashseal --version"
        } else {
            Write-Host "请重开终端，或执行: `$env:Path = `"$binDir$Sep`$env:Path`""
        }
    } else {
        Write-Host "请执行: export PATH=`"$binDir`:`$PATH`""
    }
}

Write-Host ''
Write-Host '升级: 重新执行本脚本'
Write-Host '卸载: uv tool uninstall hashseal'

Restore-Session
