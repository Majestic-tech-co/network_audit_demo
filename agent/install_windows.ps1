# NetAudit Agent — Windows Installer
# Run in PowerShell as Administrator:
#   powershell -ExecutionPolicy Bypass -File install_windows.ps1 -DashboardUrl https://... -AgentToken YOUR_TOKEN
#
# Optional: add -InstallClamAV to auto-install ClamAV via winget

param(
    [Parameter(Mandatory=$true)]
    [string]$DashboardUrl,

    [Parameter(Mandatory=$true)]
    [string]$AgentToken,

    [switch]$InstallClamAV
)

$ErrorActionPreference = "Stop"
$AgentScript = Join-Path $PSScriptRoot "agent.py"

# ── Require Admin ────────────────────────────────────────────────────
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator. Right-click PowerShell and choose 'Run as Administrator'."
    exit 1
}

# ── Find Python ──────────────────────────────────────────────────────
Write-Host "`nLooking for Python..." -ForegroundColor Cyan
$Python = $null
foreach ($candidate in @("python", "python3", "py")) {
    try {
        $ver = & $candidate --version 2>&1
        if ($ver -match "Python 3\.(\d+)") {
            $minor = [int]$Matches[1]
            if ($minor -ge 9) {
                $Python = (Get-Command $candidate).Source
                Write-Host "  Found: $Python ($ver)" -ForegroundColor Green
                break
            }
        }
    } catch {}
}
if (-not $Python) {
    Write-Error "Python 3.9 or newer not found. Download from https://www.python.org/downloads/ and re-run this script."
    exit 1
}

# ── Install Python dependencies ───────────────────────────────────────
Write-Host "`nInstalling Python dependencies..." -ForegroundColor Cyan
& $Python -m pip install --quiet httpx structlog
if ($LASTEXITCODE -ne 0) {
    Write-Error "pip install failed. Make sure pip is available."
    exit 1
}
Write-Host "  Dependencies installed." -ForegroundColor Green

# ── Install ClamAV (optional) ─────────────────────────────────────────
if ($InstallClamAV) {
    Write-Host "`nInstalling ClamAV..." -ForegroundColor Cyan
    $clamInstalled = $false

    # Try winget first
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install ClamAV.ClamAV --accept-package-agreements --accept-source-agreements --silent
        if ($LASTEXITCODE -eq 0) { $clamInstalled = $true }
    }

    if (-not $clamInstalled) {
        Write-Warning "Could not install ClamAV automatically."
        Write-Host "  Download from: https://www.clamav.net/downloads" -ForegroundColor Yellow
        Write-Host "  Install it, then re-run this script (without -InstallClamAV)." -ForegroundColor Yellow
    } else {
        Write-Host "  ClamAV installed." -ForegroundColor Green

        # Run freshclam to initialise signature database
        $freshclam = "C:\Program Files\ClamAV\freshclam.exe"
        if (Test-Path $freshclam) {
            Write-Host "  Updating ClamAV signatures (this may take a minute)..." -ForegroundColor Cyan
            & $freshclam
        }
    }
} else {
    # Check if ClamAV is already present
    $clamPaths = @(
        "C:\Program Files\ClamAV\clamscan.exe",
        "C:\Program Files (x86)\ClamAV\clamscan.exe"
    )
    $clamFound = $clamPaths | Where-Object { Test-Path $_ }
    if (-not $clamFound) {
        Write-Warning "ClamAV not found — virus scanning will be unavailable."
        Write-Host "  To install: winget install ClamAV.ClamAV" -ForegroundColor Yellow
        Write-Host "  Or re-run this script with -InstallClamAV" -ForegroundColor Yellow
    } else {
        Write-Host "  ClamAV found at $($clamFound[0])" -ForegroundColor Green
    }
}

# ── Configure agent ───────────────────────────────────────────────────
Write-Host "`nConfiguring agent..." -ForegroundColor Cyan
& $Python $AgentScript configure --url $DashboardUrl --token $AgentToken
if ($LASTEXITCODE -ne 0) {
    Write-Error "Agent configuration failed."
    exit 1
}
Write-Host "  Agent configured." -ForegroundColor Green

# ── Register as Scheduled Task ────────────────────────────────────────
Write-Host "`nRegistering as Windows Scheduled Task..." -ForegroundColor Cyan
$TaskName = "NetAuditAgent"

$Action    = New-ScheduledTaskAction -Execute $Python -Argument "`"$AgentScript`" start"
$Trigger   = New-ScheduledTaskTrigger -AtLogOn
$Settings  = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1)
$Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest

Register-ScheduledTask `
    -TaskName  $TaskName `
    -Action    $Action `
    -Trigger   $Trigger `
    -Settings  $Settings `
    -Principal $Principal `
    -Force | Out-Null

Write-Host "  Scheduled task '$TaskName' created." -ForegroundColor Green

# ── Start agent now ───────────────────────────────────────────────────
Write-Host "`nStarting agent..." -ForegroundColor Cyan
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 2
$task = Get-ScheduledTask -TaskName $TaskName
Write-Host "  Task state: $($task.State)" -ForegroundColor Green

# ── Done ──────────────────────────────────────────────────────────────
Write-Host "`n========================================" -ForegroundColor Green
Write-Host " NetAudit Agent installed successfully!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "The agent runs in the background and checks in with:"
Write-Host "  $DashboardUrl"
Write-Host ""
Write-Host "Useful commands:"
Write-Host "  Check status : python `"$AgentScript`" status"
Write-Host "  Manual scan  : python `"$AgentScript`" scan --quick"
Write-Host "  View task    : schtasks /query /tn NetAuditAgent /fo LIST"
Write-Host "  Uninstall    : python `"$AgentScript`" uninstall"
Write-Host ""
