#!/usr/bin/env python3
"""
Military-Grade Cyberdefense Baseline Scanner (DEFCON-1).
Scans a target directory for high-severity vulnerabilities, weak crypto,
hardcoded secrets, and unsafe platform configurations.
Supports Git differential scanning and OASIS SARIF 2.1.0 output.
"""

import os
import re
import sys
import json
import subprocess
import argparse
from pathlib import Path

EXCLUDED_DIRS = {
    "node_modules", ".git", ".next", "dist", "build", "vendor",
    "bin", "obj", ".idea", ".vscode", "coverage", "rules", "tests", "__pycache__"
}

FALLBACK_CHECKS = [
    {
        "id": "SEC-001",
        "category": "Secrets",
        "desc": "Hardcoded Private Key Block",
        "regex": re.compile(r"BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY"),
        "exts": {".ts", ".js", ".json", ".env", ".py", ".dart", ".kt", ".swift", ".yml", ".yaml", ".go", ".rs", ".rb", ".php"},
        "severity": "CRITICAL"
    },
    {
        "id": "SEC-002",
        "category": "Secrets",
        "desc": "Hardcoded AWS Access Key",
        "regex": re.compile(r"AKIA[0-9A-Z]{16}"),
        "exts": {".ts", ".js", ".json", ".py", ".dart", ".kt", ".swift", ".go", ".rs", ".rb", ".php"},
        "severity": "CRITICAL"
    },
    {
        "id": "SEC-003",
        "category": "Secrets",
        "desc": "Hardcoded Bearer / Secret Token",
        "regex": re.compile(r"(?i)(api[_-]?key|secret[_-]?key|jwt[_-]?token)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{20,}['\"]"),
        "exts": {".ts", ".js", ".json", ".py", ".dart", ".kt", ".swift", ".go", ".rs", ".rb", ".php"},
        "severity": "HIGH"
    },
    {
        "id": "SEC-004",
        "category": "Secrets",
        "desc": "Hardcoded GitHub Personal Token",
        "regex": re.compile(r"ghp_[0-9a-zA-Z]{36}"),
        "exts": {".ts", ".js", ".json", ".py", ".dart", ".kt", ".swift", ".env", ".go", ".rs", ".rb", ".php"},
        "severity": "CRITICAL"
    },
    {
        "id": "SEC-005",
        "category": "Secrets",
        "desc": "Hardcoded Google / Gemini API Key",
        "regex": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "exts": {".ts", ".js", ".json", ".py", ".dart", ".kt", ".swift", ".env", ".go", ".rs", ".rb", ".php"},
        "severity": "CRITICAL"
    },
    {
        "id": "SEC-006",
        "category": "Secrets",
        "desc": "Hardcoded Stripe Live Secret Key",
        "regex": re.compile(r"sk_live_[0-9a-zA-Z]{24}"),
        "exts": {".ts", ".js", ".json", ".py", ".dart", ".kt", ".swift", ".env", ".go", ".rs", ".rb", ".php"},
        "severity": "CRITICAL"
    },
    {
        "id": "SEC-007",
        "category": "Secrets",
        "desc": "Hardcoded Database URI with Real Password",
        "regex": re.compile(r"(?i)(postgres|mysql|mongodb)(\+srv)?://[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-\$%\^&@]{4,}@[a-zA-Z0-9_\-\.]+"),
        "exts": {".ts", ".js", ".json", ".py", ".dart", ".env", ".go", ".rs", ".rb", ".php"},
        "severity": "CRITICAL"
    },
    {
        "id": "CRY-001",
        "category": "Crypto",
        "desc": "Broken Hashing Algorithm (MD5/SHA1)",
        "regex": re.compile(r"(?i)(createHash\(['\"]md5['\"]|createHash\(['\"]sha1['\"]|MessageDigest\.getInstance\(['\"]MD5['\"]|MessageDigest\.getInstance\(['\"]SHA-?1['\"])"),
        "exts": {".ts", ".js", ".java", ".kt", ".py", ".dart", ".cs"},
        "severity": "HIGH"
    },
    {
        "id": "CRY-002",
        "category": "Crypto",
        "desc": "Insecure Random Generator (Not CSPRNG)",
        "regex": re.compile(r"(?i)(Math\.random\(\)|random\.random\(\)|Random\.nextInt\(\))"),
        "exts": {".ts", ".js", ".java", ".kt", ".py", ".dart"},
        "severity": "MEDIUM"
    },
    {
        "id": "CRY-003",
        "category": "Crypto",
        "desc": "Insecure Cipher Mode (AES-ECB)",
        "regex": re.compile(r"(?i)(AES/ECB/|mode\s*:\s*['\"]ECB['\"])"),
        "exts": {".ts", ".js", ".java", ".kt", ".py", ".cs"},
        "severity": "CRITICAL"
    },
    {
        "id": "INJ-001",
        "category": "Injection",
        "desc": "Dangerous Dynamic Evaluation (eval/exec)",
        "regex": re.compile(r"(?i)(\beval\s*\(|\bexec\s*\(|\bFunction\s*\(.*new)"),
        "exts": {".ts", ".js", ".py", ".php"},
        "severity": "HIGH"
    },
    {
        "id": "INJ-002",
        "category": "Injection",
        "desc": "Unsanitized Raw HTML Injection (XSS Vector)",
        "regex": re.compile(r"(?i)(innerHTML\s*=|dangerouslySetInnerHTML)"),
        "exts": {".ts", ".tsx", ".js", ".jsx"},
        "severity": "MEDIUM"
    },
    {
        "id": "INJ-003",
        "category": "Injection",
        "desc": "Raw SQL Concatenation (SQLi Risk)",
        "regex": re.compile(r"(?i)(query\s*\(\s*['\"`].*\$\{.*\}.*['\"`]|SELECT\s+.*\s+FROM\s+.*['\"]\s*\+)"),
        "exts": {".ts", ".js", ".py", ".java", ".kt", ".cs"},
        "severity": "CRITICAL"
    },
    {
        "id": "INJ-004",
        "category": "Injection",
        "desc": "Unconfined Path Concatenation (Traversal Risk)",
        "regex": re.compile(r"(?i)(readFile\s*\(\s*path\.join\s*\(|readFile\s*\(.*\+.*req\.)"),
        "exts": {".ts", ".js", ".py"},
        "severity": "HIGH"
    },
    {
        "id": "CFG-001",
        "category": "Android",
        "desc": "Cleartext Traffic Allowed in Manifest",
        "regex": re.compile(r"android:usesCleartextTraffic\s*=\s*['\"]true['\"]"),
        "exts": {".xml"},
        "severity": "CRITICAL"
    },
    {
        "id": "CFG-002",
        "category": "Android",
        "desc": "Insecure Application Backup Enabled",
        "regex": re.compile(r"android:allowBackup\s*=\s*['\"]true['\"]"),
        "exts": {".xml"},
        "severity": "HIGH"
    },
    {
        "id": "CFG-003",
        "category": "Web",
        "desc": "Overly Permissive Wildcard CORS with Credentials",
        "regex": re.compile(r"(?i)Access-Control-Allow-Origin.*[\*]"),
        "exts": {".ts", ".js", ".py", ".go", ".conf", ".json"},
        "severity": "MEDIUM"
    },
    {
        "id": "API-001",
        "category": "API/JWT",
        "desc": "Dangerous JWT 'none' Algorithm Allowed",
        "regex": re.compile(r"(?i)(algorithms\s*:\s*\[.*['\"]none['\"].*\]|\"alg\"\s*:\s*\"none\")"),
        "exts": {".ts", ".js", ".py", ".json"},
        "severity": "CRITICAL"
    },
    {
        "id": "API-002",
        "category": "API/Fingerprint",
        "desc": "Leaked Server Fingerprinting Header",
        "regex": re.compile(r"(?i)(Server-Tokens\s+on|add_header\s+['\"]?X-Powered-By|setHeader\s*\([^)]*X-Powered-By)"),
        "exts": {".conf", ".ts", ".js", ".py"},
        "severity": "MEDIUM"
    },
    {
        "id": "IAC-001",
        "category": "IaC/Container",
        "desc": "Dangerous Docker Socket Mounting",
        "regex": re.compile(r"(?i)(/var/run/docker\.sock)"),
        "exts": {".yml", ".yaml", ".sh", ".json", ".conf"},
        "severity": "CRITICAL"
    },
    {
        "id": "IAC-002",
        "category": "IaC/Container",
        "desc": "Unpinned Mutable Container Base Tag (:latest)",
        "regex": re.compile(r"(?i)^\s*FROM\s+[^\s@]+:latest"),
        "exts": {".dockerfile", ""},
        "severity": "MEDIUM"
    },
    {
        "id": "IAC-003",
        "category": "IaC/Prowler",
        "desc": "Privileged Container / Capability Escalation in K8s or Compose",
        "regex": re.compile(r"(?i)(privileged\s*:\s*true|allowPrivilegeEscalation\s*:\s*true)"),
        "exts": {".yml", ".yaml", ".json"},
        "severity": "CRITICAL"
    },
    {
        "id": "IAC-004",
        "category": "IaC/Prowler",
        "desc": "Host Namespace Sharing in Container / Pod (hostPID/hostNetwork)",
        "regex": re.compile(r"(?i)(hostPID\s*:\s*true|hostNetwork\s*:\s*true|hostIPC\s*:\s*true)"),
        "exts": {".yml", ".yaml", ".json"},
        "severity": "HIGH"
    },
    {
        "id": "IAC-005",
        "category": "IaC/Prowler",
        "desc": "Cloud Storage Public Read/Write ACL (S3/GCS/Azure)",
        "regex": re.compile(r"(?i)(acl\s*=\s*['\"]public-read['\"]|acl\s*=\s*['\"]public-read-write['\"])"),
        "exts": {".tf", ".json", ".yml", ".yaml"},
        "severity": "CRITICAL"
    },
    {
        "id": "IAC-006",
        "category": "IaC/Prowler",
        "desc": "Wildcard Administrator Privilege in Cloud IAM Policy",
        "regex": re.compile(r"(?i)(\"Action\"\s*:\s*\"\*\"\s*,\s*\"Resource\"\s*:\s*\"\*\")"),
        "exts": {".json", ".tf", ".yml", ".yaml"},
        "severity": "CRITICAL"
    },
    {
        "id": "NET-001",
        "category": "Network/LateralMovement",
        "desc": "Insecure Database / Cache Port Bound to All Interfaces (0.0.0.0)",
        "regex": re.compile(r"^\s*-\s*['\"]?(0\.0\.0\.0:)?(6379|27017|9200|5432|3306|2375):[0-9]+"),
        "exts": {".yml", ".yaml"},
        "severity": "HIGH"
    },
    {
        "id": "AI-001",
        "category": "AI/Steganography",
        "desc": "Hidden Zero-Width / RTL Cloaking in Prompt or Skill",
        "regex": re.compile(r"[\u200B-\u200D\uFEFF\u202A-\u202E]"),
        "exts": {".md", ".txt", ".prompt", ".json", ".yaml", ".yml"},
        "severity": "CRITICAL"
    },
    {
        "id": "AI-002",
        "category": "AI/AgentSkill",
        "desc": "Instruction Override / Prompt Injection in Skill Configuration",
        "regex": re.compile(r"(?i)(ignore\s+previous\s+instructions|system\s+prompt\s+override|bypass\s+safety\s+filters|disregard\s+prior\s+directives)"),
        "exts": {".prompt", ".txt", ".yaml", ".yml", ".json"},
        "severity": "HIGH"
    }
]

def load_checks():
    """Load baseline checks from Single Source of Truth (rules/security-rules.json)."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(script_dir, "..", "rules", "security-rules.json"),
        os.path.join(script_dir, "security-rules.json")
    ]
    for rules_path in candidates:
        if os.path.isfile(rules_path):
            try:
                with open(rules_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                loaded = []
                for c in data.get("baseline_checks", []):
                    loaded.append({
                        "id": c["id"],
                        "category": c["category"],
                        "desc": c["desc"],
                        "regex": re.compile(c["regex"]),
                        "exts": set(c["exts"]),
                        "severity": c["severity"]
                    })
                if loaded:
                    return loaded
            except Exception:
                pass
    return FALLBACK_CHECKS

CHECKS = load_checks()

def get_git_diff_files(target_dir):
    try:
        res = subprocess.run(["git", "-C", target_dir, "status", "--porcelain"], capture_output=True, text=True, check=True)
        files = []
        for line in res.stdout.splitlines():
            if len(line) > 3:
                rel = line[3:].strip().strip('"')
                if " -> " in rel:
                    rel = rel.split(" -> ")[-1].strip().strip('"')
                fname = os.path.basename(rel)
                if fname.startswith("check-") or fname.startswith("patch-"):
                    continue
                full = os.path.join(target_dir, rel)
                if os.path.isfile(full):
                    files.append(full)
        return files
    except Exception:
        return []

def scan_repository(target_path: str, sarif_output: str = None, git_diff: bool = False):
    print("==========================================================")
    print(" [DEFCON-1] MILITARY-GRADE CYBERDEFENSE BASELINE SCANNER  ")
    print("==========================================================")
    print(f"Target Directory: {target_path}")
    if git_diff:
        print("Mode: GIT DIFF (Differential scan on changed files only)")
    print()

    issues_count = 0
    warnings_count = 0
    sarif_results = []

    if git_diff:
        all_files = get_git_diff_files(target_path)
        if not all_files:
            print("[*] No modified or staged files detected via Git diff.")
    elif os.path.isfile(target_path):
        all_files = [os.path.abspath(target_path)]
    else:
        all_files = []
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
            for f in files:
                if f.startswith("check-") or f.startswith("patch-"):
                    continue
                all_files.append(os.path.join(root, f))

    is_single_file = os.path.isfile(target_path)

    for check in CHECKS:
        matched_instances = []
        for file_path in all_files:
            fname = os.path.basename(file_path)
            _, ext = os.path.splitext(file_path)
            ext_lower = ext.lower()
            matches_ext = (
                ext_lower in check["exts"] or
                ("" in check["exts"] and (fname == "Dockerfile" or fname.startswith("Dockerfile.")))
            )
            if not matches_ext:
                continue
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_no, line in enumerate(f, start=1):
                        if check["regex"].search(line):
                            matched_instances.append({
                                "file": file_path,
                                "line": line_no,
                                "text": line.strip()
                            })
                            if sarif_output:
                                rel = os.path.basename(file_path) if is_single_file else os.path.relpath(file_path, target_path).replace("\\", "/")
                                sarif_level = "error" if check["severity"] in ("CRITICAL", "HIGH") else "warning"
                                sarif_results.append({
                                    "ruleId": check["id"],
                                    "level": sarif_level,
                                    "message": {"text": f"[{check['severity']}] {check['category']}: {check['desc']}"},
                                    "locations": [{
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": rel},
                                            "region": {"startLine": line_no}
                                        }
                                    }]
                                })
            except Exception:
                pass

        if matched_instances:
            sev = check["severity"]
            print(f"[{sev}] {check['category']}: {check['desc']}")
            for m in matched_instances[:5]:
                rel_path = os.path.basename(m["file"]) if is_single_file else os.path.relpath(m["file"], target_path)
                print(f"   -> Affected: {rel_path}:{m['line']}")
            if len(matched_instances) > 5:
                print(f"   -> ... and {len(matched_instances) - 5} more instances.")
            print()
            if sev in ("CRITICAL", "HIGH"):
                issues_count += len(matched_instances)
            else:
                warnings_count += len(matched_instances)

    if sarif_output:
        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "DEFCON-1 Military Cyberdefense Scanner",
                        "version": "2.0.0",
                        "informationUri": "https://github.com/google-antigravity"
                    }
                },
                "results": sarif_results
            }]
        }
        with open(sarif_output, "w", encoding="utf-8") as f:
            json.dump(sarif_doc, f, indent=2)
        print(f"\n[SARIF] Report successfully exported to: {sarif_output}")

    print("\n==========================================================")
    print(" SCAN COMPLETE")
    print(f" Critical / High Defects: {issues_count}")
    print(f" Warnings / Medium Risks: {warnings_count}")
    print("==========================================================")

    if issues_count == 0 and warnings_count == 0:
        print(" STATUS: DEFCON-5 (COMPLIANT). No baseline violations detected.")
        return 0
    else:
        print(" STATUS: REMEDIATION REQUIRED. Address defects before release.")
        return 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DEFCON-1 Baseline Scanner")
    parser.add_argument("target", nargs="?", default=".", help="Target path to scan")
    parser.add_argument("--sarif", help="Path to export SARIF 2.1.0 report")
    parser.add_argument("--diff", action="store_true", help="Scan only git modified/staged files")
    args = parser.parse_args()

    sys.exit(scan_repository(args.target, sarif_output=args.sarif, git_diff=args.diff))
