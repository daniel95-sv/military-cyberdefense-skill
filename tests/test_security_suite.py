#!/usr/bin/env python3
"""
DEFCON-1 Automated Unit & Regression Test Suite.
Verifies all cyberdefense tools, SSOT integrity, baseline scanners,
FIM hashing, OSV supply chain parsing, SSRF perimeter defenses,
harness safe execution, and production templates.
"""

import os
import sys
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

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
    """Test Suite for Single Source of Truth (SSOT) schema, parities, and drift detection."""

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

    def test_ssot_schema_rejects_duplicate_ids(self):
        fake_ssot = {
            "baseline_checks": [
                {"id": "DUP-001", "category": "Secrets", "desc": "Check 1", "regex": "foo", "exts": [".py"], "severity": "HIGH"},
                {"id": "DUP-001", "category": "Secrets", "desc": "Check 2", "regex": "bar", "exts": [".py"], "severity": "HIGH"}
            ],
            "required_headers": [{"name": "H1", "description": "d1"}],
            "fingerprint_headers": ["Server"]
        }
        errs, count = sync_val.validate_ssot_schema(fake_ssot)
        self.assertTrue(any("Duplicate rule ID" in e for e in errs), "Duplicate rule ID must be flagged")


class TestSecurityBaselineScanner(unittest.TestCase):
    """Test Suite for Static Security Analysis (SAST) and AST checks."""

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

    def test_ast_analysis_detects_insecure_pickle_deserialization(self):
        py_pickle = os.path.join(self.temp_dir, "deser.py")
        with open(py_pickle, "w", encoding="utf-8") as f:
            f.write("import pickle\ndef load_data(raw):\n    return pickle.loads(raw)\n")

        sarif_out = os.path.join(self.temp_dir, "deser.sarif")
        code = sec_scan.scan_repository(self.temp_dir, sarif_output=sarif_out)
        self.assertEqual(code, 1, "pickle.loads must be flagged")
        with open(sarif_out, "r", encoding="utf-8") as sf:
            sarif = json.load(sf)
        rule_ids = [r["ruleId"] for r in sarif["runs"][0]["results"]]
        self.assertIn("AST-SER-001", rule_ids)

    def test_ast_analysis_detects_requests_verify_false(self):
        py_tls = os.path.join(self.temp_dir, "insecure_http.py")
        with open(py_tls, "w", encoding="utf-8") as f:
            f.write("import requests\ndef fetch(u):\n    return requests.get(u, verify=False)\n")

        code = sec_scan.scan_repository(self.temp_dir)
        self.assertEqual(code, 1, "requests verify=False must return exit code 1")

    def test_unreadable_file_fails_with_exit_code_2(self):
        clean_file = os.path.join(self.temp_dir, "clean.py")
        with open(clean_file, "w", encoding="utf-8") as f:
            f.write("print('clean')\n")

        original_open = open
        def mock_open_func(file, *args, **kwargs):
            if os.path.normpath(str(file)) == os.path.normpath(clean_file) and "r" in args:
                raise PermissionError("Access denied by OS mock")
            return original_open(file, *args, **kwargs)

        with patch("builtins.open", side_effect=mock_open_func):
            code = sec_scan.scan_repository(self.temp_dir)
            self.assertEqual(code, 2, "Unreadable files during audit must return exit code 2 (INCOMPLETE)")


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

    def test_fim_detects_new_and_deleted_files(self):
        fim_scan.init_baseline(self.temp_dir, self.manifest, secret=self.secret)

        # Create new untracked file
        untracked = os.path.join(self.temp_dir, "untracked.txt")
        with open(untracked, "w", encoding="utf-8") as f:
            f.write("UNAUTHORIZED_EXTRA_FILE")

        code = fim_scan.verify_baseline(self.temp_dir, self.manifest, secret=self.secret)
        self.assertEqual(code, 1, "New unauthorized file must return exit code 1")

        # Remove new file and delete original baseline file
        os.remove(untracked)
        os.remove(self.test_file)

        code = fim_scan.verify_baseline(self.temp_dir, self.manifest, secret=self.secret)
        self.assertEqual(code, 1, "Deleted baseline file must return exit code 1")

    def test_fim_unreadable_file_fails_init_with_code_2(self):
        with patch.object(fim_scan, "calculate_sha256", side_effect=PermissionError("Mock read error")):
            out_manifest = os.path.join(self.temp_dir, "incomplete_base.json")
            code = fim_scan.init_baseline(self.temp_dir, out_manifest)
            self.assertEqual(code, 2, "Unreadable files during init must return exit code 2 (INCOMPLETE)")
            self.assertFalse(os.path.exists(out_manifest), "Incomplete baseline must not be saved")

    def test_fim_unreadable_file_fails_verify_with_code_2(self):
        fim_scan.init_baseline(self.temp_dir, self.manifest, secret=self.secret)
        with patch.object(fim_scan, "calculate_sha256", side_effect=PermissionError("Mock read error")):
            code = fim_scan.verify_baseline(self.temp_dir, self.manifest, secret=self.secret)
            self.assertEqual(code, 2, "Unreadable files during verify must return exit code 2 (INCOMPLETE)")

    def test_fim_corrupted_manifest_fails_with_code_2(self):
        with open(self.manifest, "w", encoding="utf-8") as f:
            f.write("{NOT_VALID_JSON}")
        code = fim_scan.verify_baseline(self.temp_dir, self.manifest, secret=self.secret)
        self.assertEqual(code, 2, "Corrupted JSON manifest must return exit code 2")

    def test_fim_invalid_schema_fails_with_code_2(self):
        with open(self.manifest, "w", encoding="utf-8") as f:
            json.dump({"metadata": {}, "files": "not_a_dict"}, f)
        code = fim_scan.verify_baseline(self.temp_dir, self.manifest, secret=self.secret)
        self.assertEqual(code, 2, "Invalid schema must return exit code 2")

    def test_fim_path_traversal_in_manifest_fails_with_code_2(self):
        bad_manifest = {
            "metadata": {"generator": "DEFCON-1", "target": self.temp_dir, "file_count": 1},
            "files": {
                "../../etc/passwd": {"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "size": 100}
            }
        }
        with open(self.manifest, "w", encoding="utf-8") as f:
            json.dump(bad_manifest, f)
        code = fim_scan.verify_baseline(self.temp_dir, self.manifest)
        self.assertEqual(code, 2, "Path traversal in manifest must return exit code 2")

    def test_fim_hmac_mismatch_fails_with_code_2(self):
        fim_scan.init_baseline(self.temp_dir, self.manifest, secret=self.secret)
        # Verify with wrong secret
        code = fim_scan.verify_baseline(self.temp_dir, self.manifest, secret="WRONG_SECRET")
        self.assertEqual(code, 2, "HMAC signature mismatch must return exit code 2")

    def test_fim_secret_from_env_works(self):
        with patch.dict(os.environ, {"DEFCON_FIM_SECRET": self.secret}):
            fim_scan.init_baseline(self.temp_dir, self.manifest)
            code = fim_scan.verify_baseline(self.temp_dir, self.manifest)
            self.assertEqual(code, 0, "HMAC secret resolved from DEFCON_FIM_SECRET must succeed")


class TestSupplyChainAuditor(unittest.TestCase):
    """Test Suite for Google OSV Supply Chain Auditor and lockfile parsers."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="defcon_osv_")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_osv_empty_directory_exports_valid_sarif(self):
        sarif_path = os.path.join(self.temp_dir, "osv.sarif")
        osv_scan.export_sarif(sarif_path, self.temp_dir, [])
        self.assertTrue(os.path.isfile(sarif_path))
        with open(sarif_path, "r", encoding="utf-8") as sf:
            doc = json.load(sf)
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(len(doc["runs"][0]["results"]), 0)

    def test_osv_handles_query_error_safely(self):
        vulns, errors = osv_scan.query_osv_batch([])
        self.assertEqual(vulns, [])
        self.assertEqual(errors, [])

    def test_npm_v1_recursive_dependencies_parsed(self):
        npm_lock = {
            "name": "test-pkg",
            "version": "1.0.0",
            "lockfileVersion": 1,
            "dependencies": {
                "parent-dep": {
                    "version": "1.2.3",
                    "dependencies": {
                        "nested-child": {
                            "version": "4.5.6"
                        }
                    }
                }
            }
        }
        lock_path = os.path.join(self.temp_dir, "package-lock.json")
        with open(lock_path, "w", encoding="utf-8") as f:
            json.dump(npm_lock, f)

        pkgs = osv_scan.parse_package_lock(lock_path)
        pkg_names = {p["name"]: p["version"] for p in pkgs}
        self.assertIn("parent-dep", pkg_names)
        self.assertEqual(pkg_names["parent-dep"], "1.2.3")
        self.assertIn("nested-child", pkg_names)
        self.assertEqual(pkg_names["nested-child"], "4.5.6")

    def test_requirements_extras_and_unpinned_handling(self):
        req_content = (
            "celery[redis]==5.3.0\n"
            "cryptography==41.0.0; sys_platform == 'linux'\n"
            "fastapi>=0.100.0\n"
            "pydantic\n"
        )
        req_path = os.path.join(self.temp_dir, "requirements.txt")
        with open(req_path, "w", encoding="utf-8") as f:
            f.write(req_content)

        unpinned = []
        pkgs = osv_scan.parse_requirements_txt(req_path, unpinned_packages=unpinned)
        pkg_dict = {p["name"]: p["version"] for p in pkgs}
        self.assertIn("celery", pkg_dict, "Extras [redis] must be stripped from package name")
        self.assertEqual(pkg_dict["celery"], "5.3.0")
        self.assertIn("cryptography", pkg_dict)

        unpinned_names = [u["name"] for u in unpinned]
        self.assertIn("fastapi", unpinned_names)
        self.assertIn("pydantic", unpinned_names)

    def test_pom_xml_maven_parsing(self):
        pom_content = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <properties>
    <guava.version>32.0.0-jre</guava.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>${guava.version}</version>
    </dependency>
  </dependencies>
</project>"""
        pom_path = os.path.join(self.temp_dir, "pom.xml")
        with open(pom_path, "w", encoding="utf-8") as f:
            f.write(pom_content)

        pkgs = osv_scan.parse_pom_xml(pom_path)
        self.assertEqual(len(pkgs), 1)
        self.assertEqual(pkgs[0]["name"], "com.google.guava:guava")
        self.assertEqual(pkgs[0]["version"], "32.0.0-jre")
        self.assertEqual(pkgs[0]["ecosystem"], "Maven")

    def test_osv_query_batch_captures_network_failure(self):
        test_pkgs = [{"name": "lodash", "version": "4.17.20", "ecosystem": "npm"}]
        with patch("urllib.request.urlopen", side_effect=Exception("Connection refused")):
            vulns, errors = osv_scan.query_osv_batch(test_pkgs, retries=0)
            self.assertEqual(len(vulns), 0)
            self.assertEqual(len(errors), 1)
            self.assertIn("failed", errors[0])


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

    def test_ssrf_rejects_userinfo(self):
        with self.assertRaises(PermissionError):
            live_scan.validate_target_url("http://admin:secret@example.com", allow_internal=False)

    def test_ssrf_rejects_private_rf1918(self):
        with self.assertRaises(PermissionError):
            live_scan.validate_target_url("http://10.0.0.1", allow_internal=False)
        with self.assertRaises(PermissionError):
            live_scan.validate_target_url("http://192.168.1.1", allow_internal=False)
        with self.assertRaises(PermissionError):
            live_scan.validate_target_url("http://172.16.0.1", allow_internal=False)

    def test_ssrf_rejects_ipv4_mapped_ipv6(self):
        with self.assertRaises(PermissionError):
            live_scan.validate_target_url("http://[::ffff:127.0.0.1]", allow_internal=False)
        with self.assertRaises(PermissionError):
            live_scan.validate_target_url("http://[::ffff:192.168.1.1]", allow_internal=False)

    def test_ssrf_allows_when_explicitly_permitted(self):
        # When allow_internal is True, localhost should pass validation
        try:
            live_scan.validate_target_url("http://127.0.0.1:3000", allow_internal=True)
        except PermissionError:
            self.fail("validate_target_url raised PermissionError when allow_internal=True")

    def test_allow_internal_does_not_bypass_external_authorization(self):
        # Passing allow_internal=True must NEVER bypass --authorized requirement for external domains!
        code = live_scan.audit_live_endpoint("https://example.com", allow_internal=True, authorized=False)
        self.assertEqual(code, 2, "--allow-internal must not bypass explicit authorization for external domain")

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

    def test_pre_patch_test_failure_aborts(self):
        fail_cmd = f'"{sys.executable}" -c "import sys; sys.exit(1)"'
        code = patch_scan.patch_and_reverify(self.target_file, test_cmd=fail_cmd, non_interactive=True, authorized=True)
        self.assertEqual(code, 1, "Failing pre-patch baseline tests must abort harness with code 1")

    def test_patch_without_test_cmd_does_not_certify_regression(self):
        code = patch_scan.patch_and_reverify(self.target_file, non_interactive=True, authorized=True)
        self.assertEqual(code, 0, "Clean patch application returns code 0")


class TestProductionTemplates(unittest.TestCase):
    """Test Suite for Hardened Production Templates (Compose, K8s, Nginx, CI/CD)."""

    def test_docker_compose_redis_has_password_environment(self):
        import yaml
        compose_path = os.path.join(ROOT_DIR, "templates", "docker-compose.hardened.yml")
        with open(compose_path, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        redis_svc = doc["services"]["redis"]
        self.assertIn("environment", redis_svc, "Redis service must configure environment")
        env_vars = redis_svc["environment"]
        has_redis_pwd = any("REDIS_PASSWORD" in e for e in env_vars)
        self.assertTrue(has_redis_pwd, "Redis service must pass REDIS_PASSWORD in environment")

    def test_k8s_network_policies_coverage(self):
        import yaml
        k8s_path = os.path.join(ROOT_DIR, "templates", "k8s-network-policy.yaml")
        with open(k8s_path, "r", encoding="utf-8") as f:
            docs = list(yaml.safe_load_all(f))
        policy_names = {d["metadata"]["name"] for d in docs if d and "metadata" in d}
        self.assertIn("default-deny-all", policy_names)
        self.assertIn("allow-dns-egress", policy_names)
        self.assertIn("app-microsegmentation", policy_names)
        self.assertIn("postgres-microsegmentation", policy_names, "PostgreSQL ingress policy must be present")
        self.assertIn("redis-microsegmentation", policy_names, "Redis ingress policy must be present")

    def test_nginx_cloudflare_real_ip_configured(self):
        nginx_path = os.path.join(ROOT_DIR, "templates", "nginx.hardened.conf")
        with open(nginx_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("set_real_ip_from", content, "Nginx must configure trusted real IP ranges")
        self.assertIn("real_ip_header CF-Connecting-IP;", content, "Nginx must resolve CF-Connecting-IP")
        self.assertNotIn("Zero PII", content, "Nginx must not claim Zero PII while logging IPs")

    def test_github_actions_actions_pinned_by_sha(self):
        workflow_path = os.path.join(ROOT_DIR, ".github", "workflows", "defense-gate.yml")
        with open(workflow_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        for idx, line in enumerate(lines, start=1):
            if "uses:" in line and "actions/" in line or "uses:" in line and "aquasecurity/" in line:
                action_ref = line.split("uses:")[1].strip()
                if not action_ref.startswith("./"):
                    sha_part = action_ref.split("#")[0].strip().split("@")[-1]
                    self.assertEqual(len(sha_part), 40, f"Line {idx}: Action '{action_ref}' must be pinned to a full 40-char SHA commit")


if __name__ == "__main__":
    unittest.main()
