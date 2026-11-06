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
import shlex
import argparse
import subprocess

def run_command(cmd: str) -> int:
    """Executes a test command safely without shell=True to prevent command injection."""
    try:
        args = shlex.split(cmd, posix=(os.name != "nt"))
        proc = subprocess.run(args, shell=False)
        return proc.returncode
    except Exception as e:
        print(f"[-] Execution failed: {e}")
        return 1

def patch_and_reverify(
    target_file: str,
    test_cmd: str = None,
    scanner_script: str = None,
    non_interactive: bool = False,
    allow_dirty: bool = False,
    dry_run: bool = False,
    authorized: bool = False
):
    print("==========================================================")
    print(" [DEFCON-1] SURGICAL PATCH & RE-VERIFICATION HARNESS      ")
    print("==========================================================")
    print(f"Target File : {target_file}")
    if dry_run:
        print("Mode        : DRY RUN (Simulation only)")

    if not os.path.isfile(target_file):
        print(f"[-] [FATAL] Target file does not exist: {target_file}")
        return 1

    # Authorization Check for Destructive / Modifying Operations
    if not dry_run:
        if non_interactive and not authorized:
            print("[-] [ABORT] Modifying source code in non-interactive mode requires explicit authorization.")
            print("    Pass --confirm (or --authorized) to authorize surgical patch application.")
            return 1
        elif not non_interactive and not authorized:
            try:
                confirm = input(f"[AUTHORIZATION] Do you authorize applying a surgical patch to '{target_file}'? [y/N]: ").strip().lower()
                if confirm not in ("y", "yes"):
                    print("[-] [CANCELLED] Patch application aborted by operator.")
                    return 1
            except (EOFError, KeyboardInterrupt):
                print("\n[-] [CANCELLED] Operation cancelled.")
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
            print(" [-] [ABORT] Functional baseline tests failed BEFORE applying the patch!")
            print("     Cannot establish a working baseline. Fix failing tests first or specify --allow-dirty.")
            if not allow_dirty:
                if os.path.exists(backup_file):
                    os.remove(backup_file)
                return 1
            print(" [!] [WARN] Proceeding despite failing baseline due to --allow-dirty flag.")
        else:
            print(" [+] Baseline tests passed cleanly.")

    if dry_run:
        print("\n[DRY RUN] Simulating patch verification with baseline scanner...")
        scan_proc = subprocess.run([sys.executable, scanner_script, target_file])
        if os.path.exists(backup_file):
            os.remove(backup_file)
        print("\n[DRY RUN] Simulation finished. No modifications retained.")
        return scan_proc.returncode

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
        if os.path.isfile(target_file):
            print("    [ROLLBACK COMPLETE] Original state verified and restored.")
        else:
            print("    [-] [CRITICAL] Failed verifying restored target file!")
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
            if os.path.isfile(target_file):
                print("    [ROLLBACK COMPLETE] Original state verified and restored.")
            else:
                print("    [-] [CRITICAL] Failed verifying restored target file!")
            return 1
        print(" [+] Non-regression verified: All functional tests passed.")

    # Cleanup backup on success
    if os.path.exists(backup_file):
        os.remove(backup_file)

    print("\n==========================================================")
    if test_cmd:
        print(" [CERTIFIED] PATCH VALIDATED: Zero Defect + Zero Regression")
    else:
        print(" [CERTIFIED] PATCH VALIDATED: Zero Security Defect (Functional regression unverified: no test suite provided)")
    print("==========================================================")
    return 0

def main():
    parser = argparse.ArgumentParser(
        description="DEFCON-1 Surgical Patch & Re-Verification Harness (Python)",
        epilog="Example: python patch-and-reverify.py src/auth.py --test 'pytest' --non-interactive"
    )
    parser.add_argument("target", help="Specific source file being patched")
    parser.add_argument("--test", dest="test_cmd", help="Optional test suite command (e.g., 'pytest', 'npm test')")
    parser.add_argument("--scanner", dest="scanner_script", help="Path to baseline scanner (default: check-security-baseline.py)")
    parser.add_argument("--non-interactive", action="store_true", help="Run without pausing for manual input (CI/CD mode)")
    parser.add_argument("--allow-dirty", action="store_true", help="Proceed even if pre-patch tests fail")
    parser.add_argument("--dry-run", action="store_true", help="Simulate patch verification without permanent changes")
    parser.add_argument("--confirm", "--authorized", dest="authorized", action="store_true", help="Explicitly authorize source code modification")

    args = parser.parse_args()
    sys.exit(patch_and_reverify(
        target_file=args.target,
        test_cmd=args.test_cmd,
        scanner_script=args.scanner_script,
        non_interactive=args.non_interactive,
        allow_dirty=args.allow_dirty,
        dry_run=args.dry_run,
        authorized=args.authorized
    ))

if __name__ == "__main__":
    main()

