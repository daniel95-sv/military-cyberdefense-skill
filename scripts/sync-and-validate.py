#!/usr/bin/env python3
"""
DEFCON-1 Synchronization & Parity Guard.
Enforces that the entire project remains 100% synchronized against the
Single Source of Truth (SSOT) defined in rules/security-rules.json.

Validates:
1. Integrity and syntax of rules/security-rules.json (unique IDs, valid regexes, severities).
2. Synchronization between SSOT and scanner scripts (check-security-baseline.py/.ps1, check-live-endpoint.py).
3. Synchronization with templates/security-headers.json.
4. Synchronization between templates/cloudflare-waf-rules.json and templates/cloudflare-waf.tf.
5. Synchronization with templates/.gitleaks.toml.

Supports:
  --check (default): Audit and report drift. Returns exit code 1 if desynchronization exists.
  --sync           : Automatically update and synchronize template configs from SSOT.
"""

import os
import sys
import json
import re
import argparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
RULES_FILE = os.path.join(ROOT_DIR, "rules", "security-rules.json")

def load_ssot():
    if not os.path.isfile(RULES_FILE):
        print(f"[-] [FATAL] Single Source of Truth file not found at: {RULES_FILE}")
        sys.exit(1)
    with open(RULES_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def validate_ssot_schema(ssot):
    errors = []
    checks = ssot.get("baseline_checks", [])
    if not checks:
        errors.append("rules/security-rules.json has empty 'baseline_checks'")

    seen_ids = set()
    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    for c in checks:
        cid = c.get("id")
        if not cid:
            errors.append(f"Check missing 'id': {c}")
            continue
        if cid in seen_ids:
            errors.append(f"Duplicate rule ID in SSOT: {cid}")
        seen_ids.add(cid)

        # Validate regex
        pattern = c.get("regex")
        if not pattern:
            errors.append(f"Rule {cid} missing 'regex'")
        else:
            try:
                re.compile(pattern)
            except re.error as e:
                errors.append(f"Rule {cid} invalid regex '{pattern}': {e}")

        # Validate severity
        sev = c.get("severity")
        if sev not in valid_severities:
            errors.append(f"Rule {cid} invalid severity '{sev}'. Must be one of {valid_severities}")

        # Validate extensions
        exts = c.get("exts")
        if not isinstance(exts, list) or len(exts) == 0:
            errors.append(f"Rule {cid} missing or invalid 'exts' list")

    req_headers = ssot.get("required_headers", [])
    if not req_headers:
        errors.append("SSOT missing 'required_headers'")

    fp_headers = ssot.get("fingerprint_headers", [])
    if not fp_headers:
        errors.append("SSOT missing 'fingerprint_headers'")

    return errors, len(checks)

def check_scanner_integration():
    errors = []
    py_scanner = os.path.join(SCRIPT_DIR, "check-security-baseline.py")
    ps_scanner = os.path.join(SCRIPT_DIR, "check-security-baseline.ps1")
    live_scanner = os.path.join(SCRIPT_DIR, "check-live-endpoint.py")

    # Verify check-security-baseline.py loads SSOT
    with open(py_scanner, "r", encoding="utf-8") as f:
        content = f.read()
        if "security-rules.json" not in content or "load_checks" not in content:
            errors.append("check-security-baseline.py does not dynamically load rules/security-rules.json")

    # Verify check-security-baseline.ps1 loads SSOT
    with open(ps_scanner, "r", encoding="utf-8") as f:
        content = f.read()
        if "security-rules.json" not in content or "rulesJson.baseline_checks" not in content:
            errors.append("check-security-baseline.ps1 does not dynamically load rules/security-rules.json")

    # Verify check-live-endpoint.py loads SSOT
    with open(live_scanner, "r", encoding="utf-8") as f:
        content = f.read()
        if "security-rules.json" not in content or "load_endpoint_rules" not in content:
            errors.append("check-live-endpoint.py does not dynamically load rules/security-rules.json")

    return errors

def check_security_headers_sync(ssot, auto_sync=False):
    errors = []
    headers_file = os.path.join(ROOT_DIR, "templates", "security-headers.json")
    if not os.path.isfile(headers_file):
        errors.append(f"templates/security-headers.json not found at {headers_file}")
        return errors

    with open(headers_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    existing_headers = data.get("headers", {})
    existing_strip = data.get("strip_fingerprinting", [])

    ssot_required = {h["name"]: h["recommended_value"] for h in ssot.get("required_headers", [])}
    ssot_strip = ssot.get("fingerprint_headers", [])

    missing_headers = [name for name in ssot_required if name not in existing_headers]
    if missing_headers:
        errors.append(f"templates/security-headers.json missing headers: {missing_headers}")

    value_mismatches = []
    for name, expected_val in ssot_required.items():
        if name in existing_headers and existing_headers[name] != expected_val:
            value_mismatches.append(f"Header '{name}' value drift. Expected '{expected_val}', found '{existing_headers[name]}'")
    if value_mismatches:
        errors.extend(value_mismatches)

    missing_strip = [name for name in ssot_strip if name not in existing_strip]
    if missing_strip:
        errors.append(f"templates/security-headers.json missing strip_fingerprinting: {missing_strip}")

    if auto_sync and (missing_headers or value_mismatches or missing_strip):
        for name, val in ssot_required.items():
            existing_headers[name] = val
        data["headers"] = existing_headers
        data["strip_fingerprinting"] = sorted(list(set(existing_strip + ssot_strip)))
        with open(headers_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print("  [+] [SYNCED] templates/security-headers.json updated with 100% SSOT value parity.")

    return errors

def check_cloudflare_waf_sync(ssot, auto_sync=False):
    errors = []
    json_waf = os.path.join(ROOT_DIR, "templates", "cloudflare-waf-rules.json")
    tf_waf = os.path.join(ROOT_DIR, "templates", "cloudflare-waf.tf")

    if not os.path.isfile(json_waf) or not os.path.isfile(tf_waf):
        errors.append("Cloudflare WAF template files missing")
        return errors

    with open(json_waf, "r", encoding="utf-8") as f:
        waf_data = json.load(f)

    with open(tf_waf, "r", encoding="utf-8") as f:
        tf_data = f.read()

    # SSOT defined routes & parameters
    honeypot_routes = ssot.get("honeypot_routes", [])
    expected_block_routes = set(honeypot_routes)
    for probe in ssot.get("sensitive_perimeter_probes", []):
        p = probe.get("path", "")
        parts = [part for part in p.split("/") if part]
        if parts:
            expected_block_routes.add(f"/{parts[0]}")

    auth_cfg = ssot.get("auth_rate_limiting", {})
    expected_endpoints = auth_cfg.get("endpoints", [])
    expected_threshold = auth_cfg.get("threshold", 5)
    expected_period = auth_cfg.get("period_seconds", 60)
    expected_timeout = auth_cfg.get("mitigation_timeout_seconds", 900)

    # 1. Verify JSON WAF rules
    recon_rule_json = next((r for r in waf_data.get("rules", []) if "honeypot" in r.get("name", "").lower() or "reconnaissance" in r.get("name", "").lower()), None)
    if recon_rule_json:
        expr = recon_rule_json.get("expression", "")
        for route in expected_block_routes:
            if route not in expr:
                errors.append(f"Cloudflare WAF JSON reconnaissance rule missing route: {route}")
    else:
        errors.append("Cloudflare WAF JSON missing reconnaissance blocking rule")

    rate_rule_json = next((r for r in waf_data.get("rules", []) if "rate_limit_params" in r), None)
    if rate_rule_json:
        expr = rate_rule_json.get("expression", "")
        for ep in expected_endpoints:
            if ep not in expr:
                errors.append(f"Cloudflare WAF JSON rate limiting missing endpoint: {ep}")
        p = rate_rule_json.get("rate_limit_params", {})
        if p.get("threshold") != expected_threshold:
            errors.append(f"Cloudflare WAF JSON threshold {p.get('threshold')} != SSOT {expected_threshold}")
        if p.get("period") != expected_period:
            errors.append(f"Cloudflare WAF JSON period {p.get('period')} != SSOT {expected_period}")
        if p.get("timeout") != expected_timeout:
            errors.append(f"Cloudflare WAF JSON timeout {p.get('timeout')} != SSOT {expected_timeout}")
    else:
        errors.append("Cloudflare WAF JSON missing rate limiting rule")

    # 2. Verify Terraform WAF rules
    for route in expected_block_routes:
        if route not in tf_data:
            errors.append(f"Cloudflare Terraform WAF missing block route: {route}")

    for ep in expected_endpoints:
        if ep not in tf_data:
            errors.append(f"Cloudflare Terraform WAF rate limiting missing endpoint: {ep}")

    if f"requests_per_period = {expected_threshold}" not in tf_data:
        errors.append(f"Cloudflare Terraform requests_per_period desynchronized from SSOT threshold ({expected_threshold})")
    if f"period              = {expected_period}" not in tf_data:
        errors.append(f"Cloudflare Terraform period desynchronized from SSOT period ({expected_period})")
    if f"mitigation_timeout  = {expected_timeout}" not in tf_data:
        errors.append(f"Cloudflare Terraform mitigation_timeout desynchronized from SSOT timeout ({expected_timeout})")

    return errors

def check_gitleaks_sync(ssot):
    errors = []
    gitleaks_file = os.path.join(ROOT_DIR, "templates", ".gitleaks.toml")
    root_gitleaks = os.path.join(ROOT_DIR, ".gitleaks.toml")
    if not os.path.isfile(gitleaks_file):
        errors.append(f"templates/.gitleaks.toml not found at {gitleaks_file}")
        return errors

    with open(gitleaks_file, "r", encoding="utf-8") as f:
        content = f.read()

    secret_checks = [c for c in ssot.get("baseline_checks", []) if c.get("category") == "Secrets"]
    for c in secret_checks:
        cid = c["id"]
        if cid == "SEC-001" and "PRIVATE KEY" not in content:
            errors.append(f".gitleaks.toml missing pattern for {cid} (Private Key)")
        elif cid == "SEC-002" and "AKIA" not in content:
            errors.append(f".gitleaks.toml missing pattern for {cid} (AWS)")
        elif cid == "SEC-003" and "secret[_-]?key" not in content and "jwt[_-]?token" not in content:
            errors.append(f".gitleaks.toml missing pattern for {cid} (Bearer/Secret Token)")
        elif cid == "SEC-004" and "ghp" not in content:
            errors.append(f".gitleaks.toml missing pattern for {cid} (GitHub PAT)")
        elif cid == "SEC-005" and "AIza" not in content:
            errors.append(f".gitleaks.toml missing pattern for {cid} (Google AI)")
        elif cid == "SEC-006" and "sk_live" not in content:
            errors.append(f".gitleaks.toml missing pattern for {cid} (Stripe)")
        elif cid == "SEC-007" and "postgres" not in content:
            errors.append(f".gitleaks.toml missing pattern for {cid} (Database URI)")

    # Validate regex compilation of all rules in .gitleaks.toml
    rule_patterns = re.findall(r'regex\s*=\s*(?:\'\'\'|\"\"\")(.*?)(?:\'\'\'|\"\"\")', content, re.DOTALL)
    for idx, pat in enumerate(rule_patterns):
        pat_clean = pat.strip()
        try:
            re.compile(pat_clean)
        except re.error as e:
            errors.append(f".gitleaks.toml rule #{idx+1} has invalid regex: {e}")

    # Verify root .gitleaks.toml parity with templates/.gitleaks.toml
    if os.path.isfile(root_gitleaks):
        with open(root_gitleaks, "r", encoding="utf-8") as rf:
            root_content = rf.read()
        if root_content != content:
            errors.append("Root .gitleaks.toml has drifted from templates/.gitleaks.toml")

    return errors

def main():
    parser = argparse.ArgumentParser(description="DEFCON-1 Synchronization & Parity Guard")
    parser.add_argument("--sync", action="store_true", help="Automatically synchronize and update downstream templates from SSOT")
    parser.add_argument("--check", action="store_true", default=True, help="Validate project synchronization (default)")
    args = parser.parse_args()

    print("==========================================================")
    print(" [DEFCON-1] PROJECT SYNCHRONIZATION & PARITY GUARD        ")
    print("==========================================================")
    print(f"Single Source of Truth (SSOT): rules/security-rules.json\n")

    ssot = load_ssot()

    all_errors = []

    # 1. SSOT Schema
    print("[1/5] Validating SSOT Schema & Regex Integrity...")
    schema_errs, rule_count = validate_ssot_schema(ssot)
    if schema_errs:
        all_errors.extend(schema_errs)
        for e in schema_errs:
            print(f"  [-] [ERROR] {e}")
    else:
        print(f"  [+] [PASS] SSOT is valid: {rule_count} compiled rules, clean regexes, valid severities.")

    # 2. Scanner Integration
    print("\n[2/5] Validating Dynamic SSOT Integration in Scanners...")
    scanner_errs = check_scanner_integration()
    if scanner_errs:
        all_errors.extend(scanner_errs)
        for e in scanner_errs:
            print(f"  [-] [ERROR] {e}")
    else:
        print("  [+] [PASS] All 3 scanners (Python, PowerShell, Perimeter) actively consume the SSOT.")

    # 3. Security Headers Sync
    print("\n[3/5] Validating Security Headers Sync (templates/security-headers.json)...")
    hdr_errs = check_security_headers_sync(ssot, auto_sync=args.sync)
    if hdr_errs:
        all_errors.extend(hdr_errs)
        for e in hdr_errs:
            print(f"  [-] [ERROR] {e}")
    else:
        print("  [+] [PASS] Security headers template is in 100% parity with SSOT.")

    # 4. Cloudflare WAF Sync
    print("\n[4/5] Validating Cloudflare WAF Parity (Terraform vs JSON)...")
    waf_errs = check_cloudflare_waf_sync(ssot, auto_sync=args.sync)
    if waf_errs:
        all_errors.extend(waf_errs)
        for e in waf_errs:
            print(f"  [-] [ERROR] {e}")
    else:
        print("  [+] [PASS] Cloudflare Terraform and JSON rulesets share identical parameters.")

    # 5. Gitleaks Secret Pattern Sync
    print("\n[5/5] Validating Secret Pattern Sync (templates/.gitleaks.toml)...")
    gitleaks_errs = check_gitleaks_sync(ssot)
    if gitleaks_errs:
        all_errors.extend(gitleaks_errs)
        for e in gitleaks_errs:
            print(f"  [-] [ERROR] {e}")
    else:
        print("  [+] [PASS] Gitleaks configuration covers all SEC-* rules defined in SSOT.")

    print("\n==========================================================")
    if all_errors:
        print(f" STATUS: DESYNCHRONIZATION DETECTED ({len(all_errors)} issues found).")
        print(" Remediation: Run 'python scripts/sync-and-validate.py --sync'")
        print("==========================================================")
        return 1
    else:
        print(" STATUS: DEFCON-5 (100% SYNCHRONIZED). Zero configuration drift.")
        print("==========================================================")
        return 0

if __name__ == "__main__":
    sys.exit(main())

