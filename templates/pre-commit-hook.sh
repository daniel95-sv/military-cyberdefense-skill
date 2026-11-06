#!/usr/bin/env bash
# DEFCON-1 Pre-Commit Defense Gate
# Copy this file to: .git/hooks/pre-commit and make it executable (chmod +x .git/hooks/pre-commit)
#
# MILITARY-GRADE POSTURE: This hook HARD-FAILS (blocks the commit) if required
# security tools are not installed. Install tools before committing:
#   - gitleaks: https://github.com/gitleaks/gitleaks#installing
#   - python3:  https://www.python.org/downloads/

echo "=========================================================="
echo " [DEFCON-1] PRE-COMMIT SECURITY & SECRETS AUDIT GATE      "
echo "=========================================================="

HOOK_FAILED=0

# 1. Require gitleaks — HARD FAIL if not installed
if ! command -v gitleaks &> /dev/null; then
    echo ""
    echo "[BLOCKED] 'gitleaks' is not installed. Install it before committing:"
    echo "          https://github.com/gitleaks/gitleaks#installing"
    echo "          brew install gitleaks  |  winget install gitleaks"
    exit 1
fi

echo "[*] Running Gitleaks on staged files..."
gitleaks protect --staged --verbose --redact
if [ $? -ne 0 ]; then
    echo ""
    echo "[-] [COMMIT BLOCKED] Hardcoded secrets detected in staged changes!"
    echo "    Remediate secrets or add allowed false positives to .gitleaks.toml"
    HOOK_FAILED=1
fi

# 2. Require Python 3 — HARD FAIL if not installed
PYTHON_BIN=""
if command -v python3 &> /dev/null; then
    PYTHON_BIN="python3"
elif command -v python &> /dev/null; then
    PYTHON_BIN="python"
else
    echo ""
    echo "[BLOCKED] Neither 'python3' nor 'python' was found. Install Python before committing:"
    echo "          https://www.python.org/downloads/"
    exit 1
fi

if [ ! -f "./scripts/check-security-baseline.py" ]; then
    echo "[WARN] check-security-baseline.py not found in ./scripts/. Skipping baseline scan."
else
    echo "[*] Running DEFCON-1 Baseline Scanner on modified files..."
    "$PYTHON_BIN" ./scripts/check-security-baseline.py . --diff
    if [ $? -ne 0 ]; then
        echo ""
        echo "[-] [COMMIT BLOCKED] Critical security defects found in modified files!"
        echo "    Fix defects before committing."
        HOOK_FAILED=1
    fi
fi

if [ $HOOK_FAILED -ne 0 ]; then
    exit 1
fi

echo "[+] [PASSED] Pre-commit security verification clean. Proceeding with commit."
exit 0
