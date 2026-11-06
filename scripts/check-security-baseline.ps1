<#
.SYNOPSIS
    Military-Grade Cyberdefense Baseline Scanner (DEFCON-1).
.DESCRIPTION
    Scans a project repository for critical vulnerabilities, hardcoded secrets,
    insecure cryptographic algorithms, unsafe reflection/eval, and dangerous platform settings.
    Supports standard SARIF 2.1.0 output and Git differential scanning.
.PARAMETER TargetPath
    The root path of the project to scan. Defaults to current directory.
.PARAMETER OutputSarif
    Optional file path to export results in OASIS SARIF 2.1.0 format.
.PARAMETER GitDiff
    If set, only scans files that are modified or staged according to Git.
#>

param (
    [string]$TargetPath = ".",
    [string]$OutputSarif = "",
    [switch]$GitDiff,
    [string[]]$ExcludeDirs = @()
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [DEFCON-1] MILITARY-GRADE CYBERDEFENSE BASELINE SCANNER  " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ("Target Directory: {0}" -f $TargetPath) -ForegroundColor Gray

if ($GitDiff) {
    Write-Host "Mode: GIT DIFF (Differential scan on changed files only)" -ForegroundColor Magenta
}

$script:issuesFound = 0
$script:warningsFound = 0
$script:sarifResults = @()

$excludedDirs = @(
    "node_modules", ".git", ".next", "dist", "build", "vendor",
    "bin", "obj", ".idea", ".vscode", "coverage", "__pycache__", ".pytest_cache"
)
if ($ExcludeDirs -and $ExcludeDirs.Count -gt 0) {
    $excludedDirs += $ExcludeDirs
    Write-Host ("Configured Exclusions: {0}" -f ($ExcludeDirs -join ", ")) -ForegroundColor Gray
}

$toolInternalNames = @(
    "check-security-baseline.ps1",
    "check-security-baseline.py",
    "security-rules.json",
    ".gitleaks.toml"
)

# Determine candidate files
$allFiles = @()
if ($GitDiff) {
    try {
        $gitStatus = git -C $TargetPath status --porcelain 2>$null
        if ($gitStatus) {
            foreach ($line in $gitStatus) {
                if ($line.Length -gt 3) {
                    $relPath = $line.Substring(3).Trim().Trim('"')
                    if ($relPath -match " -> ") {
                        $relPath = ($relPath -split " -> ")[-1].Trim().Trim('"')
                    }
                    $fileName = [System.IO.Path]::GetFileName($relPath)
                    if ($toolInternalNames -contains $fileName) {
                        continue
                    }
                    $fullPath = Join-Path (Resolve-Path $TargetPath).Path $relPath
                    if (Test-Path $fullPath -PathType Leaf) {
                        $allFiles += Get-Item $fullPath
                    }
                }
            }
        }
    } catch {}
    if ($allFiles.Count -eq 0) {
        Write-Host "[*] No modified or staged files detected via Git diff." -ForegroundColor Yellow
    }
} elseif (Test-Path $TargetPath -PathType Leaf) {
    $allFiles = @(Get-Item (Resolve-Path $TargetPath).Path)
} else {
    $allFiles = @(Get-ChildItem -Path $TargetPath -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
        $filePath = $_.FullName
        $fileName = $_.Name
        if ($toolInternalNames -contains $fileName) {
            return $false
        }
        $isExcluded = $false
        foreach ($ex in $excludedDirs) {
            if ($filePath -match "[\\/]$ex[\\/]") {
                $isExcluded = $true
                break
            }
        }
        -not $isExcluded
    })
}

function Test-RegexInFiles {
    param (
        [string]$RuleId,
        [string]$Category,
        [string]$Description,
        [string]$Regex,
        [string[]]$Extensions,
        [string]$Severity # CRITICAL, HIGH, MEDIUM
    )

    $color = switch ($Severity) {
        "CRITICAL" { "Red" }
        "HIGH"     { "Magenta" }
        "MEDIUM"   { "Yellow" }
        Default    { "White" }
    }

    $sarifLevel = switch ($Severity) {
        "CRITICAL" { "error" }
        "HIGH"     { "error" }
        "MEDIUM"   { "warning" }
        Default    { "note" }
    }

    $isSingleFile = Test-Path $TargetPath -PathType Leaf
    $targetResolved = (Resolve-Path $TargetPath).Path

    $candidates = @($allFiles | Where-Object {
        $ext = $_.Extension.ToLower()
        $name = $_.Name
        $nameLower = $name.ToLower()
        
        $matches = ($Extensions.Count -eq 0) -or ($Extensions -contains $ext)
        if (-not $matches -and ($Extensions -contains ".env")) {
            if ($nameLower -eq ".env" -or $nameLower -like ".env.*" -or $nameLower -like "*.env") {
                $matches = $true
            }
        }
        if (-not $matches -and ($Extensions -contains "")) {
            if ($name -eq "Dockerfile" -or $name -like "Dockerfile.*" -or $ext -eq "") {
                $matches = $true
            }
        }
        if (-not $matches -and (($Extensions -contains ".env") -or ($Extensions -contains ".json") -or ($Extensions -contains ".conf"))) {
            if ($nameLower -in @(".npmrc", ".pypirc", ".htpasswd", "credentials", "id_rsa", "id_ed25519")) {
                $matches = $true
            }
        }
        $matches
    })

    $matched = @()
    foreach ($file in $candidates) {
        try {
            $lines = @(Get-Content -Path $file.FullName -ErrorAction SilentlyContinue)
            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match $Regex) {
                    $matched += [PSCustomObject]@{
                        File = $file
                        Line = $i + 1
                        Text = $lines[$i].Trim()
                    }
                    if ($OutputSarif) {
                        $rel = if ($isSingleFile) { $file.Name } else {
                            $file.FullName.Substring($targetResolved.Length).TrimStart('\', '/')
                        }
                        $script:sarifResults += @{
                            ruleId = $RuleId
                            level = $sarifLevel
                            message = @{ text = ("[{0}] {1}: {2}" -f $Severity, $Category, $Description) }
                            locations = @(
                                @{
                                    physicalLocation = @{
                                        artifactLocation = @{ uri = $rel.Replace('\', '/') }
                                        region = @{ startLine = ($i + 1) }
                                    }
                                }
                            )
                        }
                    }
                }
            }
        } catch {}
    }

    if ($matched.Count -gt 0) {
        Write-Host ("[{0}] {1}: {2}" -f $Severity, $Category, $Description) -ForegroundColor $color
        foreach ($m in $matched | Select-Object -First 5) {
            $rel = if ($isSingleFile) { $m.File.Name } else {
                $m.File.FullName.Substring($targetResolved.Length).TrimStart('\', '/')
            }
            Write-Host ("   -> Affected: {0}:{1}" -f $rel, $m.Line) -ForegroundColor Gray
        }
        if ($matched.Count -gt 5) {
            Write-Host ("   -> ... and {0} more instances." -f ($matched.Count - 5)) -ForegroundColor DarkGray
        }
        if ($Severity -eq "CRITICAL" -or $Severity -eq "HIGH") {
            $script:issuesFound += $matched.Count
        } else {
            $script:warningsFound += $matched.Count
        }
    }
}

# Resolve Single Source of Truth (SSOT) rules
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
if (-not $scriptDir) { $scriptDir = "." }

$rulesCandidatePaths = @(
    (Join-Path $scriptDir "..\rules\security-rules.json"),
    (Join-Path $scriptDir "security-rules.json")
)

$rulesFile = $null
foreach ($rc in $rulesCandidatePaths) {
    if (Test-Path $rc) {
        $rulesFile = (Resolve-Path $rc).Path
        break
    }
}

$loadedSSOT = $false
if ($rulesFile) {
    try {
        $rulesJson = Get-Content -Path $rulesFile -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($rulesJson.baseline_checks) {
            $currentCat = ""
            foreach ($chk in $rulesJson.baseline_checks) {
                if ($chk.category -ne $currentCat) {
                    $currentCat = $chk.category
                    Write-Host ("`n--- Scanning: {0} ---" -f $currentCat) -ForegroundColor Blue
                }
                Test-RegexInFiles -RuleId $chk.id -Category $chk.category -Description $chk.desc -Regex $chk.regex -Extensions @($chk.exts) -Severity $chk.severity
            }
            $loadedSSOT = $true
        }
    } catch {
        Write-Host ("[WARN] Could not parse rules from {0}: {1}. Using embedded fallback rules." -f $rulesFile, $_.Exception.Message) -ForegroundColor Yellow
    }
}

if (-not $loadedSSOT) {
    Write-Host "--- 1. Scanning for Hardcoded Secrets & Credentials ---" -ForegroundColor Blue
    Test-RegexInFiles -RuleId "SEC-001" -Category "Secrets" -Description "Hardcoded Private Key Block" -Regex 'BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY' -Extensions @(".ts", ".js", ".json", ".env", ".py", ".dart", ".kt", ".swift", ".yml", ".yaml", ".go", ".rs", ".rb", ".php") -Severity "CRITICAL"
    Test-RegexInFiles -RuleId "SEC-002" -Category "Secrets" -Description "Hardcoded AWS Access Key" -Regex '(?i)AKIA[0-9A-Z]{16}' -Extensions @(".ts", ".js", ".json", ".py", ".dart", ".kt", ".swift", ".go", ".rs", ".rb", ".php") -Severity "CRITICAL"
    Test-RegexInFiles -RuleId "SEC-003" -Category "Secrets" -Description "Hardcoded Bearer or Secret Token" -Regex '(?i)(api[_-]?key|secret[_-]?key|jwt[_-]?token)\s*[:=]\s*[''"][a-zA-Z0-9_\-]{20,}[''"]' -Extensions @(".ts", ".js", ".json", ".py", ".dart", ".kt", ".swift", ".go", ".rs", ".rb", ".php") -Severity "HIGH"
    Test-RegexInFiles -RuleId "SEC-004" -Category "Secrets" -Description "Hardcoded GitHub Personal Token" -Regex 'ghp_[0-9a-zA-Z]{36}' -Extensions @(".ts", ".js", ".json", ".py", ".dart", ".kt", ".swift", ".env", ".go", ".rs", ".rb", ".php") -Severity "CRITICAL"
    Test-RegexInFiles -RuleId "SEC-005" -Category "Secrets" -Description "Hardcoded Google / Gemini API Key" -Regex 'AIza[0-9A-Za-z\-_]{35}' -Extensions @(".ts", ".js", ".json", ".py", ".dart", ".kt", ".swift", ".env", ".go", ".rs", ".rb", ".php") -Severity "CRITICAL"
    Test-RegexInFiles -RuleId "SEC-006" -Category "Secrets" -Description "Hardcoded Stripe Live Secret Key" -Regex 'sk_live_[0-9a-zA-Z]{24}' -Extensions @(".ts", ".js", ".json", ".py", ".dart", ".kt", ".swift", ".env", ".go", ".rs", ".rb", ".php") -Severity "CRITICAL"
    Test-RegexInFiles -RuleId "SEC-007" -Category "Secrets" -Description "Hardcoded Database URI with Real Password" -Regex '(?i)(postgres|mysql|mongodb)(\+srv)?://[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-\$%\^&@]{4,}@[a-zA-Z0-9_\-\.]+' -Extensions @(".ts", ".js", ".json", ".py", ".dart", ".env", ".go", ".rs", ".rb", ".php") -Severity "CRITICAL"

    Write-Host "`n--- 2. Scanning for Weak / Broken Cryptography ---" -ForegroundColor Blue
    Test-RegexInFiles -RuleId "CRY-001" -Category "Crypto" -Description "Broken Hashing Algorithm (MD5/SHA1)" -Regex '(?i)(createHash\([''"]md5[''"]|createHash\([''"]sha1[''"]|MessageDigest\.getInstance\([''"]MD5[''"]|MessageDigest\.getInstance\([''"]SHA-?1[''"])' -Extensions @(".ts", ".js", ".java", ".kt", ".py", ".dart", ".cs") -Severity "HIGH"
    Test-RegexInFiles -RuleId "CRY-002" -Category "Crypto" -Description "Insecure Random Number Generator" -Regex '(?i)(Math\.random\(\)|random\.random\(\)|Random\.nextInt\(\))' -Extensions @(".ts", ".js", ".java", ".kt", ".py", ".dart") -Severity "MEDIUM"
    Test-RegexInFiles -RuleId "CRY-003" -Category "Crypto" -Description "Insecure Cipher Mode (AES-ECB)" -Regex '(?i)(AES/ECB/|mode\s*:\s*[''"]ECB[''"])' -Extensions @(".ts", ".js", ".java", ".kt", ".py", ".cs") -Severity "CRITICAL"

    Write-Host "`n--- 3. Scanning for Dangerous Code Execution & Injection ---" -ForegroundColor Blue
    Test-RegexInFiles -RuleId "INJ-001" -Category "Injection" -Description "Dangerous Dynamic Evaluation (eval/exec)" -Regex '(?i)(\beval\s*\(|\bexec\s*\(|\bFunction\s*\(.*new)' -Extensions @(".ts", ".js", ".py", ".php") -Severity "HIGH"
    Test-RegexInFiles -RuleId "INJ-002" -Category "Injection" -Description "Unsanitized Raw HTML Injection (XSS Vector)" -Regex '(?i)(innerHTML\s*=|dangerouslySetInnerHTML)' -Extensions @(".ts", ".tsx", ".js", ".jsx") -Severity "MEDIUM"
    Test-RegexInFiles -RuleId "INJ-003" -Category "Injection" -Description "Raw SQL Concatenation" -Regex '(?i)(query\s*\(\s*[''"`].*\$\{.*\}.*[''"`]|SELECT\s+.*\s+FROM\s+.*[''"]\s*\+)' -Extensions @(".ts", ".js", ".py", ".java", ".kt", ".cs") -Severity "CRITICAL"
    Test-RegexInFiles -RuleId "INJ-004" -Category "Injection" -Description "Unconfined Path Concatenation (Traversal Risk)" -Regex '(?i)(readFile\s*\(\s*path\.join\s*\(|readFile\s*\(.*\+.*req\.)' -Extensions @(".ts", ".js", ".py") -Severity "HIGH"

    Write-Host "`n--- 4. Scanning for Insecure Platform & API Configurations ---" -ForegroundColor Blue
    Test-RegexInFiles -RuleId "CFG-001" -Category "Android" -Description "Cleartext Traffic Allowed in Manifest" -Regex 'android:usesCleartextTraffic\s*=\s*[''"]true[''"]' -Extensions @(".xml") -Severity "CRITICAL"
    Test-RegexInFiles -RuleId "CFG-002" -Category "Android" -Description "Insecure Application Backup Enabled" -Regex 'android:allowBackup\s*=\s*[''"]true[''"]' -Extensions @(".xml") -Severity "HIGH"
    Test-RegexInFiles -RuleId "CFG-003" -Category "Web" -Description "Overly Permissive Wildcard CORS with Credentials" -Regex '(?i)Access-Control-Allow-Origin.*[\*]' -Extensions @(".ts", ".js", ".py", ".go", ".conf", ".json") -Severity "MEDIUM"
    Test-RegexInFiles -RuleId "API-001" -Category "API/JWT" -Description "Dangerous JWT 'none' Algorithm Allowed" -Regex '(?i)(algorithms\s*:\s*\[.*[''"]none[''"].*\]|"alg"\s*:\s*"none")' -Extensions @(".ts", ".js", ".py", ".json") -Severity "CRITICAL"
    Test-RegexInFiles -RuleId "API-002" -Category "API/Fingerprint" -Description "Leaked Server Fingerprinting Header" -Regex '(?i)(Server-Tokens\s+on|add_header\s+[''"]?X-Powered-By|setHeader\s*\([^)]*X-Powered-By)' -Extensions @(".conf", ".ts", ".js", ".py") -Severity "MEDIUM"
    Test-RegexInFiles -RuleId "IAC-001" -Category "IaC/Container" -Description "Dangerous Docker Socket Mounting" -Regex '(?i)(/var/run/docker\.sock)' -Extensions @(".yml", ".yaml", ".sh", ".json", ".conf") -Severity "CRITICAL"
    Test-RegexInFiles -RuleId "IAC-002" -Category "IaC/Container" -Description "Unpinned Mutable Container Base Tag (:latest)" -Regex '(?i)^\s*FROM\s+[^\s@]+:latest' -Extensions @(".dockerfile", "") -Severity "MEDIUM"
    Test-RegexInFiles -RuleId "IAC-003" -Category "IaC/Prowler" -Description "Privileged Container / Capability Escalation in K8s or Compose" -Regex '(?i)(privileged\s*:\s*true|allowPrivilegeEscalation\s*:\s*true)' -Extensions @(".yml", ".yaml", ".json") -Severity "CRITICAL"
    Test-RegexInFiles -RuleId "IAC-004" -Category "IaC/Prowler" -Description "Host Namespace Sharing in Container / Pod (hostPID/hostNetwork)" -Regex '(?i)(hostPID\s*:\s*true|hostNetwork\s*:\s*true|hostIPC\s*:\s*true)' -Extensions @(".yml", ".yaml", ".json") -Severity "HIGH"
    Test-RegexInFiles -RuleId "IAC-005" -Category "IaC/Prowler" -Description "Cloud Storage Public Read/Write ACL (S3/GCS/Azure)" -Regex '(?i)(acl\s*=\s*[''"]public-read[''"]|acl\s*=\s*[''"]public-read-write[''"])' -Extensions @(".tf", ".json", ".yml", ".yaml") -Severity "CRITICAL"
    Test-RegexInFiles -RuleId "IAC-006" -Category "IaC/Prowler" -Description "Wildcard Administrator Privilege in Cloud IAM Policy" -Regex '(?i)("Action"\s*:\s*"\*"\s*,\s*"Resource"\s*:\s*"\*")' -Extensions @(".json", ".tf", ".yml", ".yaml") -Severity "CRITICAL"
    Test-RegexInFiles -RuleId "NET-001" -Category "Network/LateralMovement" -Description "Insecure Database or Cache Port Bound to All Interfaces (0.0.0.0)" -Regex '^\s*-\s*[''"]?(0\.0\.0\.0:)?(6379|27017|9200|5432|3306|2375):[0-9]+' -Extensions @(".yml", ".yaml") -Severity "HIGH"

    Write-Host "`n--- 5. Scanning for AI Agent Skill Poisoning & Steganography ---" -ForegroundColor Blue
    Test-RegexInFiles -RuleId "AI-001" -Category "AI/Steganography" -Description "Hidden Zero-Width / RTL Cloaking in Prompt or Skill" -Regex '[\u200B-\u200D\uFEFF\u202A-\u202E]' -Extensions @(".md", ".txt", ".prompt", ".json", ".yaml", ".yml") -Severity "CRITICAL"
    Test-RegexInFiles -RuleId "AI-002" -Category "AI/AgentSkill" -Description "Instruction Override / Prompt Injection in Skill Configuration" -Regex '(?i)(ignore\s+previous\s+instructions|system\s+prompt\s+override|bypass\s+safety\s+filters|disregard\s+prior\s+directives)' -Extensions @(".prompt", ".txt", ".yaml", ".yml", ".json") -Severity "HIGH"
}

# Export SARIF if requested
if ($OutputSarif) {
    $sarifDoc = @{
        '$schema' = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        version = "2.1.0"
        runs = @(
            @{
                tool = @{
                    driver = @{
                        name = "DEFCON-1 Military Cyberdefense Scanner"
                        version = "2.0.0"
                        informationUri = "https://github.com/google-antigravity"
                    }
                }
                results = $script:sarifResults
            }
        )
    }
    $sarifDoc | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputSarif -Encoding UTF8
    Write-Host ("`n[SARIF] Report successfully exported to: {0}" -f $OutputSarif) -ForegroundColor Cyan
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " SCAN COMPLETE" -ForegroundColor Yellow
$finalIssues = $script:issuesFound
$finalWarns = $script:warningsFound
Write-Host (" Critical / High Defects: {0}" -f $finalIssues) -ForegroundColor $(if ($finalIssues -eq 0) { "Green" } else { "Red" })
Write-Host (" Warnings / Medium Risks: {0}" -f $finalWarns) -ForegroundColor $(if ($finalWarns -eq 0) { "Green" } else { "Yellow" })
Write-Host "==========================================================" -ForegroundColor Cyan

if ($finalIssues -eq 0 -and $finalWarns -eq 0) {
    Write-Host " STATUS: DEFCON-5 (COMPLIANT). No baseline violations detected." -ForegroundColor Green
    exit 0
} else {
    Write-Host " STATUS: REMEDIATION REQUIRED. Address defects before release." -ForegroundColor Red
    exit 1
}
