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
live_scan = load_module("live_scan", os.path.join(SCRIPTS_DIR, "check-live-endpoint.py"))
patch_scan = load_module("patch_scan", os.path.join(SCRIPTS_DIR, "patch-and-reverify.py"))

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

    def test_detects_secrets_in_dot_env(self):
        env_file = os.path.join(self.temp_dir, ".env")
        mock_token = "".join(["ghp_", "123456789012345678901234567890123456"])
        with open(env_file, "w", encoding="utf-8") as f:
            f.write(f"GITHUB_TOKEN={mock_token}\n")

        sarif_out = os.path.join(self.temp_dir, "env_bad.sarif")
        code = sec_scan.scan_repository(self.temp_dir, sarif_output=sarif_out)
        self.assertEqual(code, 1, "Secret in .env must be detected with exit code 1")
        with open(sarif_out, "r", encoding="utf-8") as sf:
            sarif = json.load(sf)
        rule_ids = [r["ruleId"] for r in sarif["runs"][0]["results"]]
        self.assertIn("SEC-004", rule_ids)

    def test_detects_secrets_in_dot_env_local(self):
        env_file = os.path.join(self.temp_dir, ".env.local")
        mock_api_key = "".join(["AIza", "SyD12345678901234567890123456789012"])
        with open(env_file, "w", encoding="utf-8") as f:
            f.write(f"GOOGLE_API_KEY={mock_api_key}\n")

        code = sec_scan.scan_repository(self.temp_dir)
        self.assertEqual(code, 1, "Secret in .env.local must be detected with exit code 1")

    def test_ast_analysis_detects_eval_and_shell_true(self):
        py_vuln_file = os.path.join(self.temp_dir, "vuln.py")
        with open(py_vuln_file, "w", encoding="utf-8") as f:
            f.write("import subprocess\n")
            f.write("def run_bad(x):\n")
            f.write("    " + "ev" + "al(x)\n")
            f.write("    subprocess.run('ls ' + x, shell=True)\n")

        sarif_out = os.path.join(self.temp_dir, "ast_bad.sarif")
        code = sec_scan.scan_repository(self.temp_dir, sarif_output=sarif_out)
        self.assertEqual(code, 1, "AST defects must return exit code 1")
        with open(sarif_out, "r", encoding="utf-8") as sf:
            sarif = json.load(sf)
        rule_ids = [r["ruleId"] for r in sarif["runs"][0]["results"]]
        self.assertIn("AST-INJ-001", rule_ids)
        self.assertIn("AST-CMD-001", rule_ids)


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

    def test_osv_handles_query_error_safely(self):
        # When querying an empty or invalid batch, returns (vulns, errors)
        vulns, errors = osv_scan.query_osv_batch([])
        self.assertEqual(vulns, [])
        self.assertEqual(errors, [])


class TestLivePerimeterSSRFAndHeaders(unittest.TestCase):
    """Test Suite for Live Perimeter Auditor (SSRF Protection & Header Security)."""

    def test_ssrf_rejects_loopback(self):
        with self.assertRaises(PermissionError):
            live_scan.validate_target_url("http://127.0.0.1", allow_internal=False)
        with self.assertRaises(PermissionError):
            live_scan.validate_target_url("http://localhost:8080", allow_internal=False)

    def test_ssrf_rejects_cloud_metadata(self):
        with self.assertRaises(PermissionError):
            live_scan.validate_target_url("http://169.254.169.254/latest/meta-data/", allow_internal=False)
        with self.assertRaises(PermissionError):
            live_scan.validate_target_url("http://metadata.google.internal/computeMetadata/v1/", allow_internal=False)

    def test_ssrf_allows_when_explicitly_permitted(self):
        # When allow_internal is True, localhost should pass validation
        try:
            live_scan.validate_target_url("http://127.0.0.1:3000", allow_internal=True)
        except PermissionError:
            self.fail("validate_target_url raised PermissionError when allow_internal=True")

    def test_header_strength_validation(self):
        # nosniff
        is_strong, _ = live_scan.validate_security_header_value("X-Content-Type-Options", "nosniff")
        self.assertTrue(is_strong)
        is_strong, _ = live_scan.validate_security_header_value("X-Content-Type-Options", "sniff")
        self.assertFalse(is_strong)

        # X-Frame-Options
        is_strong, _ = live_scan.validate_security_header_value("X-Frame-Options", "DENY")
        self.assertTrue(is_strong)
        is_strong, _ = live_scan.validate_security_header_value("X-Frame-Options", "ALLOW-FROM *")
        self.assertFalse(is_strong)

        # Content-Security-Policy with unsafe-eval
        is_strong, warn = live_scan.validate_security_header_value("Content-Security-Policy", "default-src 'self' 'unsafe-eval'")
        self.assertFalse(is_strong)
        self.assertIn("unsafe-eval", warn)

        # Strict Content-Security-Policy
        is_strong, warn = live_scan.validate_security_header_value("Content-Security-Policy", "default-src 'self'; script-src 'self' 'nonce-rAnd0m'")
        self.assertTrue(is_strong)

    def test_live_endpoint_requires_authorization_for_external_domain(self):
        # Calling external domain without authorization should return exit code 2
        code = live_scan.audit_live_endpoint("https://example.com", authorized=False)
        self.assertEqual(code, 2, "External reconnaissance without authorization must be aborted with code 2")


class TestHarnessAndAuthorization(unittest.TestCase):
    """Test Suite for Surgical Patch Harness and Explicit Authorization Gates."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="defcon_harness_")
        self.target_file = os.path.join(self.temp_dir, "service.py")
        with open(self.target_file, "w", encoding="utf-8") as f:
            f.write("# Clean service\ndef run():\n    return 42\n")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_patch_harness_requires_authorization_in_non_interactive(self):
        code = patch_scan.patch_and_reverify(self.target_file, non_interactive=True, authorized=False)
        self.assertEqual(code, 1, "Non-interactive patch modification without authorization must abort with code 1")

    def test_patch_harness_dry_run_leaves_no_artifacts(self):
        code = patch_scan.patch_and_reverify(self.target_file, dry_run=True)
        self.assertEqual(code, 0, "Dry run on clean file should return code 0")
        bak_file = self.target_file + ".defcon.bak"
        self.assertFalse(os.path.exists(bak_file), "Dry run must not leave backup files behind")


if __name__ == "__main__":
    unittest.main()
