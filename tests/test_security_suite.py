#!/usr/bin/env python3
"""
DEFCON-1 Automated Unit & Regression Test Suite.
Verifies all cyberdefense tools, SSOT integrity, baseline scanners,
FIM hashing, OSV supply chain parsing, and SARIF output compliance.
"""

import os
import sys
import json
import re
import tempfile
import unittest
from pathlib import Path

# Setup paths
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(TEST_DIR, ".."))
SCRIPTS_DIR = os.path.join(ROOT_DIR, "scripts")
RULES_FILE = os.path.join(ROOT_DIR, "rules", "security-rules.json")

sys.path.insert(0, SCRIPTS_DIR)
import importlib.util

def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

sync_val = load_module("sync_val", os.path.join(SCRIPTS_DIR, "sync-and-validate.py"))
sec_scan = load_module("sec_scan", os.path.join(SCRIPTS_DIR, "check-security-baseline.py"))
fim_scan = load_module("fim_scan", os.path.join(SCRIPTS_DIR, "check-file-integrity.py"))
osv_scan = load_module("osv_scan", os.path.join(SCRIPTS_DIR, "check-dependencies-osv.py"))

class TestSSOTIntegrity(unittest.TestCase):
    """Test Suite for Single Source of Truth (SSOT) schema and compilation."""

    def test_ssot_exists_and_loads(self):
        self.assertTrue(os.path.isfile(RULES_FILE), "rules/security-rules.json must exist")
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn("baseline_checks", data)
        self.assertIn("required_headers", data)
        self.assertIn("fingerprint_headers", data)

    def test_ssot_rule_compilation(self):
        ssot = sync_val.load_ssot()
        errors, rule_count = sync_val.validate_ssot_schema(ssot)
        self.assertEqual(len(errors), 0, f"SSOT schema validation failed: {errors}")
        self.assertGreaterEqual(rule_count, 28, "Expected at least 28 compiled baseline rules")

    def test_project_parity_zero_drift(self):
        ssot = sync_val.load_ssot()
        scanner_errs = sync_val.check_scanner_integration()
        headers_errs = sync_val.check_security_headers_sync(ssot)
        waf_errs = sync_val.check_cloudflare_waf_sync(ssot)
        gitleaks_errs = sync_val.check_gitleaks_sync(ssot)

        total_errs = scanner_errs + headers_errs + waf_errs + gitleaks_errs
        self.assertEqual(len(total_errs), 0, f"Parity drift detected: {total_errs}")


class TestSecurityBaselineScanner(unittest.TestCase):
    """Test Suite for Static Security Analysis (SAST)."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="defcon_test_")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_clean_file_passes(self):
        clean_file = os.path.join(self.temp_dir, "clean.py")
        with open(clean_file, "w", encoding="utf-8") as f:
            f.write("# Clean file\ndef add(a, b):\n    return a + b\n")

        sarif_out = os.path.join(self.temp_dir, "clean.sarif")
        code = sec_scan.scan_repository(self.temp_dir, sarif_output=sarif_out)
        self.assertEqual(code, 0, "Clean code must exit with 0")
        self.assertTrue(os.path.isfile(sarif_out), "SARIF report must be created")
        with open(sarif_out, "r", encoding="utf-8") as sf:
            sarif = json.load(sf)
        self.assertEqual(len(sarif["runs"][0]["results"]), 0)

    def test_detects_hardcoded_aws_key(self):
        bad_file = os.path.join(self.temp_dir, "leak.py")
        mock_key = "".join(["AK", "IA", "IOSFODNN7EXAMPLE"])
        with open(bad_file, "w", encoding="utf-8") as f:
            f.write(f"AWS_KEY = '{mock_key}'\n")

        sarif_out = os.path.join(self.temp_dir, "bad.sarif")
        code = sec_scan.scan_repository(self.temp_dir, sarif_output=sarif_out)
        self.assertEqual(code, 1, "Vulnerability must return exit code 1")
        with open(sarif_out, "r", encoding="utf-8") as sf:
            sarif = json.load(sf)
        results = sarif["runs"][0]["results"]
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0]["ruleId"], "SEC-002")


class TestFileIntegrityMonitor(unittest.TestCase):
    """Test Suite for File Integrity Monitoring (FIM)."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="defcon_fim_")
        self.test_file = os.path.join(self.temp_dir, "app.bin")
        with open(self.test_file, "w", encoding="utf-8") as f:
            f.write("BINARY_CODE_V1")
        self.manifest = os.path.join(self.temp_dir, "baseline.json")
        self.secret = "DEFCON_TEST_SECRET_KEY"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_fim_baseline_and_tamper_detection(self):
        # 1. Initialize
        fim_scan.init_baseline(self.temp_dir, self.manifest, secret=self.secret)
        self.assertTrue(os.path.isfile(self.manifest), "Manifest must exist")

        # 2. Verify clean state
        code = fim_scan.verify_baseline(self.temp_dir, self.manifest, secret=self.secret)
        self.assertEqual(code, 0, "Unchanged directory must verify with code 0")

        # 3. Tamper with file
        with open(self.test_file, "w", encoding="utf-8") as f:
            f.write("MALICIOUS_TAMPERED_PAYLOAD")

        # 4. Verify tampering detected
        code = fim_scan.verify_baseline(self.temp_dir, self.manifest, secret=self.secret)
        self.assertEqual(code, 1, "Tampered file must return exit code 1")


class TestSupplyChainAuditor(unittest.TestCase):
    """Test Suite for Google OSV Supply Chain Auditor."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="defcon_osv_")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_osv_empty_directory_exports_valid_sarif(self):
        sarif_path = os.path.join(self.temp_dir, "osv.sarif")
        # Run export_sarif directly
        osv_scan.export_sarif(sarif_path, self.temp_dir, [])
        self.assertTrue(os.path.isfile(sarif_path))
        with open(sarif_path, "r", encoding="utf-8") as sf:
            doc = json.load(sf)
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(len(doc["runs"][0]["results"]), 0)


if __name__ == "__main__":
    unittest.main()
