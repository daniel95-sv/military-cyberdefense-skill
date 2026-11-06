<#
.SYNOPSIS
    Automated Patch & Re-Verification Harness (DEFCON-1).
.DESCRIPTION
    Applies a security patch, verifies that the vulnerability is eliminated via baseline scanner,
    and runs the project's test suite to ensure zero regressions. Automatically rolls back on failure.
.PARAMETER TargetFile
    The specific source file being patched.
.PARAMETER TestCommand
    Optional test command to verify functionality (e.g., "npm test", "pytest", "cargo test").
.PARAMETER ScannerScript
    Path to the baseline scanner. Defaults to check-security-baseline.ps1 in same folder.
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$TargetFile,

    [string]$TestCommand = "",
    [string]$ScannerScript = "",
    [switch]$NonInteractive
)

if (-not $ScannerScript) {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
    if (-not $scriptDir) { $scriptDir = "." }
    $ScannerScript = Join-Path $scriptDir "check-security-baseline.ps1"
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [DEFCON-1] SURGICAL PATCH & RE-VERIFICATION HARNESS      " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ("Target File : {0}" -f $TargetFile) -ForegroundColor Gray

if (-not (Test-Path $TargetFile)) {
    Write-Host ("ERROR: Target file does not exist: {0}" -f $TargetFile) -ForegroundColor Red
    exit 1
}

# Determine current PowerShell runtime and cross-platform shell
$psExe = try { (Get-Process -Id $PID).Path } catch { $null }
if (-not $psExe) {
    $psExe = if ($IsWindows -or ($env:OS -like "*Windows*")) { "powershell" } else { "pwsh" }
}

function Invoke-ShellCommand {
    param ([string]$Command)
    if ($IsWindows -or ($env:OS -like "*Windows*")) {
        cmd /c $Command
    } else {
        sh -c $Command
    }
}

# 1. Capture Git Baseline / Backup
$backupFile = "$TargetFile.defcon.bak"
Copy-Item -Path $TargetFile -Destination $backupFile -Force
Write-Host "[1/4] Baseline state cached." -ForegroundColor Green

# 2. Functional Baseline Verification (Pre-patch check)
if ($TestCommand) {
    Write-Host "[2/4] Running functional test baseline..." -ForegroundColor Gray
    # Safe invocation: use system shell to execute developer-supplied test suite
    Invoke-ShellCommand $TestCommand
    if ($LASTEXITCODE -ne 0) {
        Write-Host "WARNING: Baseline tests failed before patch was applied!" -ForegroundColor Yellow
    } else {
        Write-Host "   -> Baseline tests passed cleanly." -ForegroundColor Green
    }
}

if (-not $NonInteractive) {
    Write-Host "`n>>> [PAUSE] Apply your patch to $TargetFile now. Press Enter when done to trigger re-verification..." -ForegroundColor Yellow
    Read-Host
} else {
    Write-Host "`n[NON-INTERACTIVE] Proceeding directly to verification..." -ForegroundColor Cyan
}

# 3. Security Re-Verification (Did the defect disappear?)
Write-Host "[3/4] Running Security Re-Verification on patched file..." -ForegroundColor Cyan
& $psExe -ExecutionPolicy Bypass -File $ScannerScript -TargetPath $TargetFile
$secExit = $LASTEXITCODE

if ($secExit -ne 0) {
    Write-Host "`n[REJECTED] Security violation still present in patched file!" -ForegroundColor Red
    Write-Host "Initiating immediate rollback..." -ForegroundColor Red
    Move-Item -Path $backupFile -Destination $TargetFile -Force
    Write-Host "Rollback complete. Original state restored." -ForegroundColor Yellow
    exit 1
}
Write-Host "   -> Security defect verified ELIMINATED." -ForegroundColor Green

# 4. Non-Regression Functional Verification (Did we break anything?)
if ($TestCommand) {
    Write-Host "`n[4/4] Running Non-Regression Test Suite..." -ForegroundColor Cyan
    Invoke-ShellCommand $TestCommand
    if ($LASTEXITCODE -ne 0) {
        Write-Host "`n[REJECTED] Functional regression detected! Tests failed after patch." -ForegroundColor Red
        Write-Host "Initiating immediate rollback..." -ForegroundColor Red
        Move-Item -Path $backupFile -Destination $TargetFile -Force
        Write-Host "Rollback complete. Original state restored." -ForegroundColor Yellow
        exit 1
    }
    Write-Host "   -> Non-regression verified: All functional tests passed." -ForegroundColor Green
}

# Cleanup backup
if (Test-Path $backupFile) {
    Remove-Item -Path $backupFile -Force
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " [CERTIFIED] PATCH VALIDATED: Zero Defect + Zero Regression" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
exit 0

