<#
    hashseal installer for Windows PowerShell 5.1 / PowerShell 7+

    Usage:
        irm https://raw.githubusercontent.com/renengade/hashseal/main/install.ps1 | iex

    Environment overrides:
        $env:HASHSEAL_REF  = 'v0.3.7'          tag / branch / commit
        $env:HASHSEAL_REPO = 'owner/repo'      repository
        $env:HASHSEAL_URL  = 'https://...zip'  direct source archive (.zip or .tar.gz)

    Notes:
    - Installs into an isolated uv tool environment (no system Python pollution).
    - Fails with a normal PowerShell error; it never closes your session.
    - Only the user PATH may be appended, and only when needed.

    This file is intentionally ASCII-only: Windows PowerShell 5.1 does not
    reliably decode UTF-8 scripts fetched through `irm | iex`.
#>

# Remember session settings so `iex` does not permanently change the user's shell.
$OldEAP = $ErrorActionPreference
$OldPythonUtf8 = $env:PYTHONUTF8
$OldConsoleEncoding = $null
try { $OldConsoleEncoding = [Console]::OutputEncoding } catch { }

$ErrorActionPreference = 'Stop'

# Windows PowerShell 5.1 may not enable TLS 1.2 by default.
try {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

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
$Sep  = [IO.Path]::PathSeparator

function Write-Step([string]$Message) {
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Fail([string]$Message) {
    Write-Host "Error: $Message" -ForegroundColor Red
    Restore-Session
    throw $Message
}

# ---------------------------------------------------------------------------
# 1) Ensure uv is available and actually runnable
# ---------------------------------------------------------------------------
$uv = Get-Command uv -ErrorAction SilentlyContinue
$uvOk = $false
if ($uv) {
    try {
        & uv --version *> $null
        $uvOk = ($LASTEXITCODE -eq 0)
    } catch {
        $uvOk = $false
    }
}

if (-not $uvOk) {
    Write-Step 'uv not found (or not runnable), installing uv ...'
    try {
        Invoke-RestMethod -Uri 'https://astral.sh/uv/install.ps1' -TimeoutSec 300 | Invoke-Expression
    } catch {
        Fail "failed to install uv: $($_.Exception.Message)"
    }

    # uv installs into ~/.local/bin; refresh PATH for this session.
    $candidates = @(
        (Join-Path $HOME '.local/bin'),
        (Join-Path $HOME '.cargo/bin')
    )
    $env:Path = (($candidates + $env:Path) | Where-Object { $_ }) -join $Sep

    $uv = Get-Command uv -ErrorAction SilentlyContinue
    if (-not $uv) {
        Fail 'uv is still not available; reopen the terminal and retry, or install uv manually.'
    }
}
Write-Step "uv: $(& uv --version)"

# ---------------------------------------------------------------------------
# 2) Download the source archive
# ---------------------------------------------------------------------------
$Work = Join-Path ([IO.Path]::GetTempPath()) ("hashseal-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Work -Force | Out-Null

$OldProgress = $ProgressPreference
$ProgressPreference = 'SilentlyContinue'   # the PS 5.1 progress bar is very slow
try {
    if ($Url) {
        $archiveUrl = $Url
    } else {
        $archiveUrl = "https://github.com/$Repo/archive/$Ref.zip"
    }

    $isTar = $archiveUrl -match '\.(tar\.gz|tgz)$'
    $archive = Join-Path $Work ($(if ($isTar) { 'src.tar.gz' } else { 'src.zip' }))

    Write-Step "downloading $archiveUrl"
    try {
        Invoke-WebRequest -Uri $archiveUrl -OutFile $archive -UseBasicParsing -TimeoutSec 600
    } catch {
        Fail "download failed (check repo/ref/network, or set HASHSEAL_REF / HASHSEAL_URL): $($_.Exception.Message)"
    }

    # Expand-Archive requires a .zip extension, hence the name chosen above.
    if ($isTar) {
        if (-not (Get-Command tar -ErrorAction SilentlyContinue)) {
            Fail 'extracting .tar.gz requires tar (bundled with Windows 10 1803+); use a .zip URL instead'
        }
        & tar -xzf $archive -C $Work
        if ($LASTEXITCODE -ne 0) { Fail 'extraction failed (tar)' }
    } else {
        try {
            Expand-Archive -Path $archive -DestinationPath $Work -Force
        } catch {
            Fail "extraction failed: $($_.Exception.Message)"
        }
    }

    $src = Get-ChildItem -LiteralPath $Work -Directory |
        Where-Object { Test-Path (Join-Path $_.FullName 'pyproject.toml') } |
        Select-Object -First 1
    if (-not $src) { Fail 'unexpected archive layout: no directory with pyproject.toml' }

    # -----------------------------------------------------------------------
    # 3) Install into the uv tool environment
    # -----------------------------------------------------------------------
    Write-Step 'installing hashseal ...'
    & uv tool install --force $src.FullName
    if ($LASTEXITCODE -ne 0) { Fail "uv tool install failed (exit code $LASTEXITCODE)" }
}
finally {
    $ProgressPreference = $OldProgress
    Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# 4) Make sure the executable is on PATH
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
    Write-Host "Installation complete: $($cmd.Source)" -ForegroundColor Green
    & hashseal --version
} else {
    Write-Host "Installed, but $binDir is not on PATH." -ForegroundColor Yellow
    $isWindowsOS = ($env:OS -eq 'Windows_NT') -or ($PSVersionTable.PSEdition -eq 'Desktop')
    if ($isWindowsOS) {
        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        if (-not $userPath) { $userPath = '' }
        if (($userPath -split ';') -notcontains $binDir) {
            $newPath = ($userPath.TrimEnd(';') + ';' + $binDir).TrimStart(';')
            [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
            Write-Host "Added $binDir to the user PATH. Reopen the terminal, then run: hashseal --version"
        } else {
            Write-Host "Reopen the terminal, or run: `$env:Path = `"$binDir$Sep`$env:Path`""
        }
    } else {
        Write-Host "Run: export PATH=`"$binDir`:`$PATH`""
    }
}

Write-Host ''
Write-Host 'Upgrade: rerun this script'
Write-Host 'Uninstall: uv tool uninstall hashseal'

Restore-Session
