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
    [switch]$NonInteractive,
    [switch]$AllowDirty,
    [switch]$DryRun,
    [switch]$ConfirmPatch
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
if ($DryRun) {
    Write-Host "Mode        : DRY RUN (Simulation only)" -ForegroundColor Magenta
}

if (-not (Test-Path $TargetFile)) {
    Write-Host ("ERROR: Target file does not exist: {0}" -f $TargetFile) -ForegroundColor Red
    exit 1
}

# Determine current PowerShell runtime and cross-platform shell
$psExe = try { (Get-Process -Id $PID).Path } catch { $null }
if (-not $psExe) {
    $psExe = if ($IsWindows -or ($env:OS -like "*Windows*")) { "powershell" } else { "pwsh" }
}

function Invoke-SafeCommand {
    param ([string]$Command)
    if (-not $Command) { return 0 }

    # Parse executable and arguments safely without shell=True or cmd/sh
    $parts = [System.Management.Automation.PsParser]::Tokenize($Command, [ref]$null) | ForEach-Object { $_.Content }
    if ($parts.Count -eq 0) { return 0 }

    $exe = $parts[0]
    $cmdArgs = if ($parts.Count -gt 1) { $parts[1..($parts.Count - 1)] } else { @() }

    try {
        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName = $exe
        $pinfo.Arguments = ($cmdArgs | ForEach-Object {
            if ($_ -match '[\s"]') {
                '"{0}"' -f ($_ -replace '"', '\"')
            } else {
                $_
            }
        }) -join ' '
        $pinfo.UseShellExecute = $false
        $proc = [System.Diagnostics.Process]::Start($pinfo)
        $proc.WaitForExit()
        return $proc.ExitCode
    } catch {
        Write-Host ("[-] Process execution failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
        return 1
    }
}

# Authorization Check
if (-not $DryRun) {
    if ($NonInteractive -and (-not $ConfirmPatch)) {
        Write-Host "[-] [ABORT] Modifying source code in non-interactive mode requires explicit authorization." -ForegroundColor Red
        Write-Host "    Pass -ConfirmPatch to authorize surgical patch application." -ForegroundColor Red
        exit 1
    } elseif ((-not $NonInteractive) -and (-not $ConfirmPatch)) {
        $ans = Read-Host "[AUTHORIZATION] Do you authorize applying a surgical patch to '$TargetFile'? [y/N]"
        if ($ans -notmatch "^(y|yes)$") {
            Write-Host "[-] [CANCELLED] Patch application aborted by operator." -ForegroundColor Yellow
            exit 1
        }
    }
}

# 1. Capture Git Baseline / Backup
$backupFile = "$TargetFile.defcon.bak"
Copy-Item -Path $TargetFile -Destination $backupFile -Force
Write-Host "[1/4] Baseline state cached." -ForegroundColor Green

# 2. Functional Baseline Verification (Pre-patch check)
if ($TestCommand) {
    Write-Host "[2/4] Running functional test baseline..." -ForegroundColor Gray
    $baseExit = Invoke-SafeCommand $TestCommand
    if ($baseExit -ne 0) {
        Write-Host "[-] [ABORT] Functional baseline tests failed BEFORE applying patch!" -ForegroundColor Red
        Write-Host "    Cannot establish a working baseline. Fix failing tests or use -AllowDirty." -ForegroundColor Red
        if (-not $AllowDirty) {
            if (Test-Path $backupFile) { Remove-Item -Path $backupFile -Force }
            exit 1
        }
        Write-Host "WARNING: Proceeding despite failing baseline due to -AllowDirty switch." -ForegroundColor Yellow
    } else {
        Write-Host "   -> Baseline tests passed cleanly." -ForegroundColor Green
    }
}

if ($DryRun) {
    Write-Host "`n[DRY RUN] Simulating patch verification with baseline scanner..." -ForegroundColor Magenta
    & $psExe -ExecutionPolicy Bypass -File $ScannerScript -TargetPath $TargetFile
    $dryExit = $LASTEXITCODE
    if (Test-Path $backupFile) { Remove-Item -Path $backupFile -Force }
    Write-Host "`n[DRY RUN] Simulation complete. No modifications retained." -ForegroundColor Magenta
    exit $dryExit
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
    if (Test-Path $TargetFile) {
        Write-Host "Rollback complete. Original state restored." -ForegroundColor Yellow
    } else {
        Write-Host "[-] [CRITICAL] Failed verifying restored target file!" -ForegroundColor Red
    }
    exit 1
}
Write-Host "   -> Security defect verified ELIMINATED." -ForegroundColor Green

# 4. Non-Regression Functional Verification (Did we break anything?)
if ($TestCommand) {
    Write-Host "`n[4/4] Running Non-Regression Test Suite..." -ForegroundColor Cyan
    $regExit = Invoke-SafeCommand $TestCommand
    if ($regExit -ne 0) {
        Write-Host "`n[REJECTED] Functional regression detected! Tests failed after patch." -ForegroundColor Red
        Write-Host "Initiating immediate rollback..." -ForegroundColor Red
        Move-Item -Path $backupFile -Destination $TargetFile -Force
        if (Test-Path $TargetFile) {
            Write-Host "Rollback complete. Original state restored." -ForegroundColor Yellow
        }
        exit 1
    }
    Write-Host "   -> Non-regression verified: All functional tests passed." -ForegroundColor Green
}

# Cleanup backup
if (Test-Path $backupFile) {
    Remove-Item -Path $backupFile -Force
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
if ($TestCommand) {
    Write-Host " [CERTIFIED] PATCH VALIDATED: Zero Defect + Zero Regression" -ForegroundColor Green
} else {
    Write-Host " [CERTIFIED] PATCH VALIDATED: Zero Security Defect (Functional regression unverified: no test suite executed)" -ForegroundColor Yellow
}
Write-Host "==========================================================" -ForegroundColor Cyan
exit 0

