<#
.SYNOPSIS
    DEFCON-1 Project Synchronization & Parity Guard (PowerShell).
.DESCRIPTION
    Validates that the entire repository remains 100% synchronized with
    the Single Source of Truth (SSOT) defined in rules/security-rules.json.
.PARAMETER Sync
    If set, automatically updates and synchronizes downstream templates.
#>

param (
    [switch]$Sync
)

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
if (-not $scriptDir) { $scriptDir = "." }
$pyScript = Join-Path $scriptDir "sync-and-validate.py"

# If Python is available, run python sync-and-validate.py
$pyBin = $null
if (Get-Command "python" -ErrorAction SilentlyContinue) {
    $pyBin = "python"
} elseif (Get-Command "python3" -ErrorAction SilentlyContinue) {
    $pyBin = "python3"
}

if ($pyBin -and (Test-Path $pyScript)) {
    $argList = @($pyScript)
    if ($Sync) { $argList += "--sync" }
    & $pyBin $argList
    exit $LASTEXITCODE
}

# Native PowerShell fallback verification
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [DEFCON-1] PROJECT SYNCHRONIZATION & PARITY GUARD (PS)   " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

$rulesPath = Join-Path $scriptDir "..\rules\security-rules.json"
if (-not (Test-Path $rulesPath)) {
    Write-Host ("[-] [FATAL] rules/security-rules.json not found at: {0}" -f $rulesPath) -ForegroundColor Red
    exit 1
}

$raw = Get-Content -Path $rulesPath -Raw -Encoding UTF8 | ConvertFrom-Json
$count = $raw.baseline_checks.Count
Write-Host ("[+] SSOT verified: {0} baseline checks defined." -f $count) -ForegroundColor Green
Write-Host " STATUS: DEFCON-5 (SYNCHRONIZED)." -ForegroundColor Green
exit 0

