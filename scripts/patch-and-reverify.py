#!/usr/bin/env python3
"""
DEFCON-1 Surgical Patch & Re-Verification Harness (Python / Cross-Platform).
Implements the 6-phase surgical patch loop:
1. Backup target file (.defcon.bak)
2. Functional test baseline check (pre-patch)
3. Patch application (interactive pause or non-interactive flag)
4. Security defect elimination verification (via check-security-baseline.py)
5. Non-regression functional verification
6. Automatic rollback on defect persistence or functional failure.
Uses only the Python standard library.
"""

import os
import sys
import shutil
import argparse
import subprocess

def run_command(cmd: str) -> int:
    """Executes a test command and streams output safely."""
    try:
        proc = subprocess.run(cmd, shell=True)
        return proc.returncode
    except Exception as e:
        print(f"[-] Execution failed: {e}")
        return 1

def patch_and_reverify(target_file: str, test_cmd: str = None, scanner_script: str = None, non_interactive: bool = False):
    print("==========================================================")
    print(" [DEFCON-1] SURGICAL PATCH & RE-VERIFICATION HARNESS      ")
    print("==========================================================")
    print(f"Target File : {target_file}")

    if not os.path.isfile(target_file):
        print(f"[-] [FATAL] Target file does not exist: {target_file}")
        return 1

    script_dir = os.path.dirname(os.path.abspath(__file__))
    if not scanner_script:
        scanner_script = os.path.join(script_dir, "check-security-baseline.py")

    backup_file = target_file + ".defcon.bak"
    try:
        shutil.copy2(target_file, backup_file)
        print("[1/4] Baseline state cached successfully.")
    except Exception as e:
        print(f"[-] [FATAL] Could not create backup: {e}")
        return 1

    # 2. Pre-patch functional baseline verification
    if test_cmd:
        print(f"\n[2/4] Running functional test baseline: '{test_cmd}'...")
        res = run_command(test_cmd)
        if res != 0:
            print(" [!] [WARN] Baseline tests failed before patch was applied!")
        else:
            print(" [+] Baseline tests passed cleanly.")

    # 3. Pause for patch application
    if not non_interactive:
        print(f"\n>>> [PAUSE] Apply your surgical patch to {target_file} now.")
        input("Press [Enter] when ready to trigger verification and re-test...")
    else:
        print("\n[NON-INTERACTIVE] Proceeding directly to verification...")

    # 4. Security Re-Verification
    print("\n[3/4] Running Security Re-Verification on patched file...")
    scan_proc = subprocess.run([sys.executable, scanner_script, target_file])
    if scan_proc.returncode != 0:
        print("\n[-] [REJECTED] Security violation still present in patched file!")
        print("    Initiating immediate rollback...")
        shutil.move(backup_file, target_file)
        print("    [ROLLBACK COMPLETE] Original state restored.")
        return 1
    print(" [+] Security defect verified ELIMINATED.")

    # 5. Non-Regression Functional Verification
    if test_cmd:
        print(f"\n[4/4] Running Non-Regression Test Suite: '{test_cmd}'...")
        reg_res = run_command(test_cmd)
        if reg_res != 0:
            print("\n[-] [REJECTED] Functional regression detected! Test suite failed after patch.")
            print("    Initiating immediate rollback...")
            shutil.move(backup_file, target_file)
            print("    [ROLLBACK COMPLETE] Original state restored.")
            return 1
        print(" [+] Non-regression verified: All functional tests passed.")

    # Cleanup backup on success
    if os.path.exists(backup_file):
        os.remove(backup_file)

    print("\n==========================================================")
    print(" [CERTIFIED] PATCH VALIDATED: Zero Defect + Zero Regression")
    print("==========================================================")
    return 0

def main():
    parser = argparse.ArgumentParser(
        description="DEFCON-1 Surgical Patch & Re-Verification Harness (Python)",
        epilog="Example: python patch-and-reverify.py src/auth.py --test 'pytest' --non-interactive"
    )
    parser.add_argument("target", help="Specific source file being patched")
    parser.add_argument("--test", dest="test_cmd", help="Optional test suite command (e.g., 'npm test', 'pytest')")
    parser.add_argument("--scanner", dest="scanner_script", help="Path to baseline scanner (default: check-security-baseline.py)")
    parser.add_argument("--non-interactive", action="store_true", help="Run without pausing for manual input (CI/CD mode)")

    args = parser.parse_args()
    sys.exit(patch_and_reverify(
        target_file=args.target,
        test_cmd=args.test_cmd,
        scanner_script=args.scanner_script,
        non_interactive=args.non_interactive
    ))

if __name__ == "__main__":
    main()

