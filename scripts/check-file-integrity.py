#!/usr/bin/env python3
"""
DEFCON-1 File Integrity Monitor (FIM) - Inspired by Wazuh XDR/SIEM.
Generates and verifies cryptographic SHA-256 baselines of critical project
and server files to detect runtime tampering, webshell drops, and unauthorized modifications.
Supports optional HMAC-SHA384 manifest authentication to prevent baseline forgery.
Uses only the Python standard library (zero external dependencies).

SECURITY NOTE: The baseline JSON file should be stored in a write-protected or
read-only location (e.g., mounted read-only volume, immutable S3 object, or
HSM-signed store) to prevent an attacker with filesystem access from forging
hashes and evading FIM detection. When the --secret argument is provided, the
manifest is cryptographically signed with HMAC-SHA384, guaranteeing detection
if an adversary modifies the baseline file itself.
"""

import os
import sys
import json
import hmac
import hashlib
import argparse
from pathlib import Path
from datetime import datetime, timezone

EXCLUDED_DIRS = {
    ".git", "node_modules", ".next", "dist", "build", "vendor",
    "__pycache__", ".idea", ".vscode", "coverage", ".pytest_cache"
}

def calculate_sha256(filepath: str) -> str:
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()

def scan_directory(target_dir: str, exclude_files: set = None, read_errors: list = None):
    inventory = {}
    target_path = Path(target_dir).resolve()
    exclude_files = exclude_files or set()
    
    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for file in files:
            full_path = os.path.join(root, file)
            try:
                full_path_abs = os.path.abspath(full_path)
                if full_path_abs in exclude_files:
                    continue
                rel_path = os.path.relpath(full_path, target_path).replace("\\", "/")
                if rel_path in exclude_files:
                    continue
                file_hash = calculate_sha256(full_path)
                file_size = os.path.getsize(full_path)
                inventory[rel_path] = {
                    "sha256": file_hash,
                    "size": file_size
                }
            except Exception as e:
                if read_errors is not None:
                    read_errors.append((full_path, str(e)))
    return inventory

def compute_manifest_hmac(files_dict: dict, secret: str) -> str:
    canonical = json.dumps(files_dict, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hmac.new(secret.encode('utf-8'), canonical, hashlib.sha384).hexdigest()

def init_baseline(target_dir: str, output_file: str, secret: str = None):
    secret = secret or os.environ.get("DEFCON_FIM_SECRET")
    print("==========================================================")
    print(" [DEFCON-1] WAZUH-GRADE FILE INTEGRITY MONITOR (INIT)     ")
    print("==========================================================")
    print(f"Target Directory: {target_dir}")
    print(f"Output Baseline:  {output_file}\n")
    
    exclude = {os.path.abspath(output_file)}
    read_errors = []
    inventory = scan_directory(target_dir, exclude_files=exclude, read_errors=read_errors)
    if read_errors:
        print(f"[-] [WARN] {len(read_errors)} files could not be read during baseline initialization:")
        for rf, err in read_errors[:5]:
            print(f"    ! {rf}: {err}")

    metadata = {
        "generator": "DEFCON-1 FIM Engine (Wazuh Doctrine)",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "target": os.path.abspath(target_dir),
        "file_count": len(inventory)
    }

    if secret:
        signature = compute_manifest_hmac(inventory, secret)
        metadata["hmac_sha384"] = signature
        print(f"[+] Cryptographic HMAC-SHA384 signature attached: {signature[:16]}...")
    else:
        print("[!] [NOTE] Baseline created without HMAC secret. Store baseline file in a read-only partition.")

    manifest = {
        "metadata": metadata,
        "files": inventory
    }
    
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        
    print(f"[+] Baseline successfully created with {len(inventory)} hashed files.")
    print(f"[+] Cryptographic manifest stored at: {output_file}")
    return 0

def verify_baseline(target_dir: str, baseline_file: str, sarif_file: str = None, secret: str = None):
    secret = secret or os.environ.get("DEFCON_FIM_SECRET")
    print("==========================================================")
    print(" [DEFCON-1] WAZUH-GRADE FILE INTEGRITY MONITOR (VERIFY)   ")
    print("==========================================================")
    print(f"Target Directory: {target_dir}")
    print(f"Baseline File:    {baseline_file}\n")
    
    if not os.path.isfile(baseline_file):
        print(f"[-] [FATAL] Baseline file not found: {baseline_file}")
        return 2
        
    try:
        with open(baseline_file, "r", encoding="utf-8") as f:
            baseline_data = json.load(f)
    except Exception as e:
        print(f"[-] [FATAL] Corrupted baseline file: {e}")
        return 2
        
    base_files = baseline_data.get("files", {})
    metadata = baseline_data.get("metadata", {})

    # HMAC integrity verification of the baseline itself
    expected_hmac = metadata.get("hmac_sha384")
    if expected_hmac:
        if not secret:
            print("[-] [CRITICAL DEFCON-1] Baseline was generated with HMAC protection, but no secret (or DEFCON_FIM_SECRET) was provided to verify it!")
            return 2
        actual_hmac = compute_manifest_hmac(base_files, secret)
        if not hmac.compare_digest(expected_hmac, actual_hmac):
            print("[-] [CRITICAL DEFCON-1] BASELINE MANIFEST FORGERY DETECTED: HMAC signature mismatch!")
            print("    The baseline manifest file itself was modified or tampered with.")
            return 2
        print("[+] [PASS] Baseline manifest HMAC-SHA384 authentic and untampered.")
    elif secret:
        print("[!] [WARN] Secret provided, but baseline has no stored HMAC signature.")

    exclude = {os.path.abspath(baseline_file)}
    if sarif_file:
        exclude.add(os.path.abspath(sarif_file))
    read_errors = []
    current_inventory = scan_directory(target_dir, exclude_files=exclude, read_errors=read_errors)
    if read_errors:
        print(f"[-] [WARN] {len(read_errors)} files could not be read during integrity verification:")
        for rf, err in read_errors[:5]:
            print(f"    ! {rf}: {err}")
    
    tampered = []
    unauthorized = []
    deleted = []
    
    # Check baseline files against current
    for rel_path, data in base_files.items():
        if rel_path not in current_inventory:
            deleted.append(rel_path)
        elif current_inventory[rel_path]["sha256"] != data["sha256"]:
            tampered.append({
                "path": rel_path,
                "expected": data["sha256"],
                "actual": current_inventory[rel_path]["sha256"]
            })
            
    # Check newly created / unauthorized files
    for rel_path in current_inventory:
        if rel_path not in base_files:
            unauthorized.append(rel_path)
            
    print("--- Integrity Verification Results ---")
    if not tampered and not unauthorized and not deleted:
        print(f"[PASS] All {len(current_inventory)} files match baseline. Zero integrity anomalies.")
        print("==========================================================")
        print(" STATUS: DEFCON-5 (COMPLIANT). Cryptographic state verified.")
        print("==========================================================")
        return 0
        
    if tampered:
        print(f"[-] [CRITICAL DEFCON-1] {len(tampered)} Tampered/Modified Files Detected:")
        for t in tampered[:10]:
            print(f"    [MODIFIED] {t['path']}")
            print(f"       Expected: {t['expected'][:16]}... | Found: {t['actual'][:16]}...")
        if len(tampered) > 10:
            print(f"    ... and {len(tampered) - 10} more tampered files (Total: {len(tampered)}).")
            
    if unauthorized:
        print(f"[-] [HIGH RISK] {len(unauthorized)} Unauthorized/New Files (Potential Webshells):")
        for u in unauthorized[:10]:
            print(f"    [NEW/UNTRACKED] {u}")
        if len(unauthorized) > 10:
            print(f"    ... and {len(unauthorized) - 10} more unauthorized files (Total: {len(unauthorized)}).")
            
    if deleted:
        print(f"[-] [WARNING] {len(deleted)} Baseline Files Deleted:")
        for d in deleted[:10]:
            print(f"    [DELETED] {d}")
        if len(deleted) > 10:
            print(f"    ... and {len(deleted) - 10} more deleted files (Total: {len(deleted)}).")

    # Export SARIF 2.1.0 report if requested (all entries included)
    if sarif_file:
        sarif_results = []
        for t in tampered:
            sarif_results.append({
                "ruleId": "FIM-001",
                "level": "error",
                "message": {"text": f"Cryptographic integrity breach: File modified from baseline. Expected SHA-256 {t['expected'][:16]}..., found {t['actual'][:16]}..."},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": t["path"]}, "region": {"startLine": 1}}}]
            })
        for u in unauthorized:
            sarif_results.append({
                "ruleId": "FIM-002",
                "level": "error",
                "message": {"text": f"Unauthorized/untracked file detected (potential webshell or backdoor): {u}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": u}, "region": {"startLine": 1}}}]
            })
        for d in deleted:
            sarif_results.append({
                "ruleId": "FIM-003",
                "level": "warning",
                "message": {"text": f"Baseline file unexpectedly deleted: {d}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": d}, "region": {"startLine": 1}}}]
            })
        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "DEFCON-1 File Integrity Monitor (Wazuh SIEM)",
                        "version": "2.0.0",
                        "informationUri": "https://wazuh.com"
                    }
                },
                "results": sarif_results
            }]
        }
        with open(sarif_file, "w", encoding="utf-8") as sf:
            json.dump(sarif_doc, sf, indent=2)
        print(f"\n[SARIF] Exported FIM SARIF report to: {sarif_file}")
            
    print("\n==========================================================")
    print(f" VERIFICATION FAILED: {len(tampered)} tampered, {len(unauthorized)} unauthorized, {len(deleted)} deleted.")
    print(" STATUS: DEFCON-1 (INTEGRITY BREACH). Investigate immediately.")
    print("==========================================================")
    return 1

def main():
    parser = argparse.ArgumentParser(
        description="DEFCON-1 File Integrity Monitor (Wazuh SIEM/XDR Doctrine)",
        epilog="Example: python check-file-integrity.py /app --init baseline.json --secret MY_KEY"
    )
    parser.add_argument("directory", help="Target directory to inspect")
    parser.add_argument("--init", dest="init_file", help="Initialize and export new baseline JSON")
    parser.add_argument("--verify", dest="verify_file", help="Verify target directory against existing baseline JSON")
    parser.add_argument("--sarif", dest="sarif_file", help="Export integrity findings in SARIF 2.1.0 format")
    parser.add_argument("--secret", dest="secret", help="Optional secret key for HMAC-SHA384 manifest authentication")
    
    args = parser.parse_args()
    
    if args.init_file:
        sys.exit(init_baseline(args.directory, args.init_file, secret=args.secret))
    elif args.verify_file:
        sys.exit(verify_baseline(args.directory, args.verify_file, sarif_file=args.sarif_file, secret=args.secret))
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
