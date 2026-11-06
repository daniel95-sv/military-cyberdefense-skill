#!/usr/bin/env python3
"""
DEFCON-1 Supply Chain Auditor (Powered by Google OSV.dev).
Queries Google's Open Source Vulnerabilities database via public API
to check third-party dependencies (npm, PyPI, Cargo/Rust) for known CVEs.
Uses only the Python standard library (no external packages required).
"""

import os
import sys
import json
import urllib.request
import urllib.error
import argparse
from pathlib import Path

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

def parse_package_lock(file_path, parse_errors=None):
    packages = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        # npm lockfile v2/v3 (packages key)
        if "packages" in data:
            for pkg_path, info in data["packages"].items():
                if not pkg_path:  # root package
                    continue
                name = pkg_path.split("node_modules/")[-1]
                version = info.get("version")
                if name and version:
                    packages.append({"name": name, "version": version, "ecosystem": "npm", "file_path": file_path})
        elif "dependencies" in data:
            for name, info in data["dependencies"].items():
                version = info.get("version")
                if name and version:
                    packages.append({"name": name, "version": version, "ecosystem": "npm", "file_path": file_path})
    except Exception as e:
        msg = f"Failed parsing {file_path}: {e}"
        print(f"[WARN] {msg}")
        if parse_errors is not None:
            parse_errors.append(msg)
    return packages

def parse_requirements_txt(file_path, parse_errors=None):
    packages = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.split("#")[0].strip()
                if not line or line.startswith("#"):
                    continue
                if "==" in line:
                    parts = line.split("==")
                    name = parts[0].strip()
                    version = parts[1].split(";")[0].strip()
                    packages.append({"name": name, "version": version, "ecosystem": "PyPI", "file_path": file_path})
    except Exception as e:
        msg = f"Failed parsing {file_path}: {e}"
        print(f"[WARN] {msg}")
        if parse_errors is not None:
            parse_errors.append(msg)
    return packages

def parse_cargo_lock(file_path, parse_errors=None):
    """Parse Rust's Cargo.lock (TOML format) for crates.io ecosystem packages."""
    packages = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            current_pkg = {}
            for line in f:
                line_s = line.strip()
                if line_s == "[[package]]":
                    if current_pkg.get("name") and current_pkg.get("version"):
                        packages.append({
                            "name": current_pkg["name"],
                            "version": current_pkg["version"],
                            "ecosystem": "crates.io",
                            "file_path": file_path
                        })
                    current_pkg = {}
                elif line_s.startswith("name = ") or line_s.startswith("name="):
                    current_pkg["name"] = line_s.split("=", 1)[1].strip().strip('"').strip("'")
                elif line_s.startswith("version = ") or line_s.startswith("version="):
                    current_pkg["version"] = line_s.split("=", 1)[1].strip().strip('"').strip("'")
            # Flush last package
            if current_pkg.get("name") and current_pkg.get("version"):
                packages.append({
                    "name": current_pkg["name"],
                    "version": current_pkg["version"],
                    "ecosystem": "crates.io",
                    "file_path": file_path
                })
    except Exception as e:
        msg = f"Failed parsing {file_path}: {e}"
        print(f"[WARN] {msg}")
        if parse_errors is not None:
            parse_errors.append(msg)
    return packages

def parse_poetry_lock(file_path, parse_errors=None):
    """Parse Python's poetry.lock (TOML format) for PyPI ecosystem packages."""
    packages = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            current_pkg = {}
            for line in f:
                line_s = line.strip()
                if line_s == "[[package]]":
                    if current_pkg.get("name") and current_pkg.get("version"):
                        packages.append({
                            "name": current_pkg["name"],
                            "version": current_pkg["version"],
                            "ecosystem": "PyPI",
                            "file_path": file_path
                        })
                    current_pkg = {}
                elif line_s.startswith("name = ") or line_s.startswith("name="):
                    current_pkg["name"] = line_s.split("=", 1)[1].strip().strip('"').strip("'")
                elif line_s.startswith("version = ") or line_s.startswith("version="):
                    current_pkg["version"] = line_s.split("=", 1)[1].strip().strip('"').strip("'")
            if current_pkg.get("name") and current_pkg.get("version"):
                packages.append({
                    "name": current_pkg["name"],
                    "version": current_pkg["version"],
                    "ecosystem": "PyPI",
                    "file_path": file_path
                })
    except Exception as e:
        msg = f"Failed parsing {file_path}: {e}"
        print(f"[WARN] {msg}")
        if parse_errors is not None:
            parse_errors.append(msg)
    return packages

def parse_go_sum(file_path, parse_errors=None):
    """Parse Go's go.sum for Go ecosystem dependencies."""
    packages = []
    seen = set()
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2:
                    mod_name = parts[0]
                    version = parts[1].split("/")[0].lstrip("v")
                    if (mod_name, version) not in seen and version:
                        seen.add((mod_name, version))
                        packages.append({
                            "name": mod_name,
                            "version": version,
                            "ecosystem": "Go",
                            "file_path": file_path
                        })
    except Exception as e:
        msg = f"Failed parsing {file_path}: {e}"
        print(f"[WARN] {msg}")
        if parse_errors is not None:
            parse_errors.append(msg)
    return packages

def parse_yarn_lock(file_path, parse_errors=None):
    """Parse Yarn lockfile (v1 format) for npm ecosystem packages."""
    packages = []
    seen = set()
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            current_pkgs = []
            for line in f:
                line_s = line.strip()
                if not line_s or line_s.startswith("#"):
                    continue
                if line.startswith(" ") or line.startswith("\t"):
                    if line_s.startswith("version ") or line_s.startswith("version:"):
                        ver = line_s.split()[1].strip('"').strip("'")
                        for pkg_name in current_pkgs:
                            if (pkg_name, ver) not in seen:
                                seen.add((pkg_name, ver))
                                packages.append({
                                    "name": pkg_name,
                                    "version": ver,
                                    "ecosystem": "npm",
                                    "file_path": file_path
                                })
                        current_pkgs = []
                else:
                    entries = [e.strip().strip('"').strip(':') for e in line_s.split(",")]
                    current_pkgs = []
                    for entry in entries:
                        if "@" in entry:
                            last_at = entry.rfind("@")
                            if last_at > 0:
                                name = entry[:last_at]
                                current_pkgs.append(name)
    except Exception as e:
        msg = f"Failed parsing {file_path}: {e}"
        print(f"[WARN] {msg}")
        if parse_errors is not None:
            parse_errors.append(msg)
    return packages

def parse_pnpm_lock(file_path, parse_errors=None):
    """Parse pnpm-lock.yaml (v5/v6/v9 format) for npm ecosystem packages."""
    packages = []
    seen = set()
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line_s = line.strip()
                if line_s.endswith(":") and "@" in line_s:
                    raw = line_s.rstrip(":").strip("'").strip('"').lstrip("/")
                    last_at = raw.rfind("@")
                    if last_at > 0:
                        name = raw[:last_at]
                        ver = raw[last_at + 1:].split("(")[0].split("_")[0]
                        if ver and ver[0].isdigit() and (name, ver) not in seen:
                            seen.add((name, ver))
                            packages.append({
                                "name": name,
                                "version": ver,
                                "ecosystem": "npm",
                                "file_path": file_path
                            })
    except Exception as e:
        msg = f"Failed parsing {file_path}: {e}"
        print(f"[WARN] {msg}")
        if parse_errors is not None:
            parse_errors.append(msg)
    return packages

def query_osv_batch(packages):
    """
    Queries OSV API for a list of packages.
    Returns: (all_vulns, query_errors)
    Where query_errors is a list of error strings if any batch query failed.
    """
    if not packages:
        return [], []

    # Process in chunks of 500 (OSV API limit)
    chunk_size = 500
    all_vulns = []
    query_errors = []

    for i in range(0, len(packages), chunk_size):
        chunk = packages[i:i + chunk_size]
        queries = [{"package": {"name": p["name"], "ecosystem": p["ecosystem"]}, "version": p["version"]} for p in chunk]
        payload = json.dumps({"queries": queries}).encode("utf-8")

        req = urllib.request.Request(
            OSV_BATCH_URL,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "DEFCON-1-OSV-Auditor"}
        )

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                results = data.get("results", [])
                for idx, res in enumerate(results):
                    vulns = res.get("vulns", [])
                    if vulns:
                        pkg = chunk[idx]
                        for v in vulns:
                            all_vulns.append({
                                "package": pkg["name"],
                                "version": pkg["version"],
                                "ecosystem": pkg["ecosystem"],
                                "file_path": pkg.get("file_path", "lockfile"),
                                "id": v.get("id", "UNKNOWN"),
                                "summary": v.get("summary", "No summary provided"),
                                "details": v.get("details", "")
                            })
        except Exception as e:
            err_msg = f"OSV.dev query batch [{i}:{i+len(chunk)}] failed: {e}"
            print(f"[-] [ERROR] {err_msg}")
            query_errors.append(err_msg)

    return all_vulns, query_errors

def export_sarif(sarif_path, target_dir, vulns):
    sarif_results = []
    for v in vulns:
        raw_fp = v.get("file_path", "lockfile")
        rel_fp = os.path.relpath(raw_fp, target_dir).replace("\\", "/") if os.path.exists(raw_fp) else raw_fp
        sarif_results.append({
            "ruleId": v["id"],
            "level": "error",
            "message": {"text": f"Vulnerable dependency {v['package']}@{v['version']}: {v['summary']}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": rel_fp},
                    "region": {"startLine": 1}
                }
            }]
        })
    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "DEFCON-1 Supply Chain Auditor (Google OSV)",
                    "version": "1.0.0",
                    "informationUri": "https://osv.dev"
                }
            },
            "results": sarif_results
        }]
    }
    with open(sarif_path, "w", encoding="utf-8") as sf:
        json.dump(sarif_doc, sf, indent=2)
    print(f"\n[SARIF] Exported supply chain SARIF to: {sarif_path}")

def main():
    parser = argparse.ArgumentParser(description="DEFCON-1 Supply Chain Auditor (Google OSV)")
    parser.add_argument("target", nargs="?", default=".", help="Target directory to scan for lockfiles")
    parser.add_argument("--sarif", help="Export findings in SARIF 2.1.0 format")
    args = parser.parse_args()

    print("==========================================================")
    print(" [DEFCON-1] SUPPLY CHAIN AUDITOR (GOOGLE OSV.DEV ENGINE) ")
    print("==========================================================")
    print(f"Target Directory: {args.target}\n")

    packages_to_check = []
    parse_errors = []

    # Check for lockfiles
    for root, dirs, files in os.walk(args.target):
        dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", ".next", "dist", "build", "vendor")]
        for f in files:
            full_path = os.path.join(root, f)
            if f == "package-lock.json":
                print(f"[*] Detected npm lockfile: {full_path}")
                packages_to_check.extend(parse_package_lock(full_path, parse_errors))
            elif f in ("requirements.txt", "requirements-dev.txt"):
                print(f"[*] Detected PyPI requirements: {full_path}")
                packages_to_check.extend(parse_requirements_txt(full_path, parse_errors))
            elif f == "Cargo.lock":
                print(f"[*] Detected Rust Cargo lockfile: {full_path}")
                packages_to_check.extend(parse_cargo_lock(full_path, parse_errors))
            elif f == "poetry.lock":
                print(f"[*] Detected Poetry lockfile: {full_path}")
                packages_to_check.extend(parse_poetry_lock(full_path, parse_errors))
            elif f == "go.sum":
                print(f"[*] Detected Go sumfile: {full_path}")
                packages_to_check.extend(parse_go_sum(full_path, parse_errors))
            elif f == "yarn.lock":
                print(f"[*] Detected Yarn lockfile: {full_path}")
                packages_to_check.extend(parse_yarn_lock(full_path, parse_errors))
            elif f in ("pnpm-lock.yaml", "pnpm-lock.yml"):
                print(f"[*] Detected pnpm lockfile: {full_path}")
                packages_to_check.extend(parse_pnpm_lock(full_path, parse_errors))

    # Deduplicate
    unique_pkgs = list({(p["name"], p["version"], p["ecosystem"]): p for p in packages_to_check}.values())
    print(f"[*] Total unique dependencies resolved: {len(unique_pkgs)}")

    if not unique_pkgs:
        if parse_errors:
            print("\n[-] [ERROR] Lockfiles were found but could not be parsed:")
            for pe in parse_errors:
                print(f"   -> {pe}")
            print("==========================================================")
            print(" STATUS: UNVERIFIED / ERROR (Parsing failed; cannot certify clean state).")
            return 2
        print("[*] No supported lockfiles or dependencies found to audit.")
        print("==========================================================")
        print(" STATUS: DEFCON-5 (No third-party packages to inspect).")
        if args.sarif:
            export_sarif(args.sarif, args.target, [])
        return 0

    print("[*] Querying Google OSV.dev vulnerability database in real-time...")
    vulns, query_errors = query_osv_batch(unique_pkgs)

    print("\n==========================================================")
    print(" SUPPLY CHAIN AUDIT REPORT")
    print(f" Dependencies Scanned : {len(unique_pkgs)}")
    print(f" Vulnerabilities Found: {len(vulns)}")
    if query_errors:
        print(f" Query Errors / Failed: {len(query_errors)}")
    if parse_errors:
        print(f" Lockfile Parse Errors: {len(parse_errors)}")
    print("==========================================================")

    if vulns:
        for v in vulns:
            print(f"\n[CRITICAL] {v['ecosystem']}/{v['package']} @ {v['version']}")
            print(f"   Advisory ID: {v['id']}")
            print(f"   Summary    : {v['summary'][:120]}...")
            print(f"   Reference  : https://osv.dev/vulnerability/{v['id']}")

    if args.sarif:
        export_sarif(args.sarif, args.target, vulns)

    # Differentiate the 3 audit states:
    # 1. Any errors during query or parsing -> Audit incomplete / unverified (exit 2)
    # 2. Vulnerabilities found -> Remediation required (exit 1)
    # 3. Clean completed scan with 0 vulnerabilities -> Compliant (exit 0)
    if query_errors or parse_errors:
        print("\n[-] [ERROR] OSV supply chain audit could not be fully completed.")
        for err in (parse_errors + query_errors):
            print(f"    ! {err}")
        print("\n STATUS: UNVERIFIED / ERROR. Incomplete audit cannot declare project compliant.")
        return 2

    if vulns:
        print("\n STATUS: REMEDIATION REQUIRED. Upgrade vulnerable packages.")
        return 1

    print("\n STATUS: DEFCON-5 (COMPLIANT). 0 known CVEs across all dependencies.")
    return 0

if __name__ == "__main__":
    sys.exit(main())

