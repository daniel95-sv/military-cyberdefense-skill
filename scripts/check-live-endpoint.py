#!/usr/bin/env python3
"""
DEFCON-1 Live Endpoint & Perimeter Auditor (Inspired by Web-Check).
Performs non-invasive, live external reconnaissance on deployed URLs,
validating TLS quality, certificate expiration, security headers,
server fingerprint leaks, RFC 9116 security.txt, and DNS anti-spoofing (DMARC & SPF).
Uses only the Python standard library (zero external dependencies).
"""

import sys
import ssl
import socket
import json
import urllib.request
import urllib.parse
import urllib.error
import argparse
from datetime import datetime, timezone

FALLBACK_REQUIRED_HEADERS = [
    ("Strict-Transport-Security", "Enforces HTTPS and protects against SSL stripping"),
    ("X-Content-Type-Options", "Prevents MIME-sniffing attacks (must be 'nosniff')"),
    ("X-Frame-Options", "Prevents clickjacking framing (must be 'DENY' or 'SAMEORIGIN')"),
    ("Content-Security-Policy", "Enforces strict script and asset boundary execution"),
    ("Referrer-Policy", "Controls referrer leakage across origins"),
    ("Cross-Origin-Opener-Policy", "Isolates browsing context to protect against Spectre-style attacks"),
    ("Permissions-Policy", "Restricts browser hardware APIs (camera, microphone, geolocation)")
]

FALLBACK_FINGERPRINT_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Runtime",
    "X-Version"
]

FALLBACK_SENSITIVE_PROBES = [
    ("/.git/HEAD", "ref: refs/", "Exposed Git Repository (VCS Leak)"),
    ("/.env", "=", "Plaintext Environment Variables (.env Leak)")
]

def load_endpoint_rules():
    """Load perimeter rules from Single Source of Truth (rules/security-rules.json)."""
    import os
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(script_dir, "..", "rules", "security-rules.json"),
        os.path.join(script_dir, "security-rules.json")
    ]
    for p in candidates:
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                req_h = [(h["name"], h["description"]) for h in data.get("required_headers", [])]
                fg_h = data.get("fingerprint_headers", [])
                probes = [(pr["path"], pr["signature"], pr["alert"]) for pr in data.get("sensitive_perimeter_probes", [])]
                if req_h:
                    return req_h, fg_h, probes
            except Exception:
                pass
    return FALLBACK_REQUIRED_HEADERS, FALLBACK_FINGERPRINT_HEADERS, FALLBACK_SENSITIVE_PROBES

REQUIRED_HEADERS, FINGERPRINT_HEADERS, SENSITIVE_PROBES = load_endpoint_rules()

def check_tls_certificate(hostname: str, port: int = 443, timeout: int = 5):
    """Inspects live TLS certificate validity, expiration, issuer, and protocol version."""
    cert_info = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cert_info["version"] = ssock.version()
                cert_info["cipher"] = ssock.cipher()
                
                # Expiry check
                not_after_str = cert.get("notAfter")
                if not_after_str:
                    # Format: 'May 10 23:59:59 2026 GMT'
                    not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_remaining = (not_after - now).days
                    cert_info["days_remaining"] = days_remaining
                    cert_info["not_after"] = not_after_str
                    
                # Subject / Issuer
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                cert_info["issuer_org"] = issuer.get("organizationName", "Unknown Issuer")
    except Exception as e:
        cert_info["error"] = str(e)
    return cert_info

def audit_live_endpoint(url: str, timeout: int = 10, json_output: str = None):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or url
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    print("==========================================================")
    print(" [DEFCON-1] LIVE ENDPOINT & PERIMETER AUDITOR             ")
    print("==========================================================")
    print(f"Target URL: {url}\n")

    score = 100
    findings = []

    # 1. Transport & TLS Verification
    print("--- 1. Transport & TLS Protocol Verification ---")
    if parsed.scheme != "https":
        print("[-] [CRITICAL] Endpoint is serving unencrypted plain HTTP!")
        score -= 40
        findings.append("Insecure plain HTTP transport")
    else:
        print("[+] [TRANSPORT] HTTPS active.")
        tls_info = check_tls_certificate(hostname, port, timeout=min(5, timeout))
        if "error" in tls_info:
            print(f"[-] [WARN] TLS handshake check failed: {tls_info['error']}")
            score -= 10
            findings.append(f"TLS check error: {tls_info['error']}")
        else:
            proto_version = tls_info.get("version", "Unknown")
            print(f" [PASS] Protocol: {proto_version} | Cipher: {tls_info.get('cipher', ('', ''))[0]}")
            if proto_version in ("TLSv1", "TLSv1.1"):
                print(" [-] [CRITICAL] Obsolete & insecure TLS version in use!")
                score -= 25
                findings.append("Obsolete TLS version")
                
            days_left = tls_info.get("days_remaining")
            if days_left is not None:
                if days_left < 0:
                    print(f" [-] [CRITICAL] TLS certificate is EXPIRED! ({days_left} days ago)")
                    score -= 30
                    findings.append("Expired TLS certificate")
                elif days_left < 14:
                    print(f" [!] [WARN] TLS certificate expires soon ({days_left} days remaining)!")
                    score -= 5
                    findings.append(f"TLS certificate expires soon: {days_left} days")
                else:
                    print(f" [PASS] Certificate Valid: {days_left} days remaining (Issuer: {tls_info.get('issuer_org')})")

    # 2. HTTP Request & Headers Audit
    headers = {}
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "DEFCON-1-Live-Auditor/2.0 (+https://github.com/google-antigravity)"}
        )
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            print(f"\n[+] [STATUS] HTTP Response: {resp.status} {resp.reason}")
    except urllib.error.HTTPError as e:
        headers = {k.lower(): v for k, v in e.headers.items()}
        print(f"\n[!] [STATUS] HTTP Error Response: {e.code} (Auditing response headers anyway)")
    except Exception as e:
        print(f"[-] [FATAL] Connection failed: {e}")
        return 1

    print("\n--- 2. Evaluating Military-Grade HTTP Security Headers ---")
    for hdr_name, desc in REQUIRED_HEADERS:
        val = headers.get(hdr_name.lower())
        if val:
            print(f" [PASS] {hdr_name}: {val[:60]}...")
        else:
            print(f" [FAIL] {hdr_name} MISSING ({desc})")
            score -= 8
            findings.append(f"Missing header: {hdr_name}")

    print("\n--- 3. Checking for Server Fingerprint Leaks ---")
    leaks_found = 0
    for f_hdr in FINGERPRINT_HEADERS:
        val = headers.get(f_hdr.lower())
        if val:
            print(f" [WARN] Leaked Server Fingerprint: {f_hdr} = '{val}'")
            leaks_found += 1
            score -= 5
            findings.append(f"Leaked fingerprint: {f_hdr}")

    if leaks_found == 0:
        print(" [PASS] Zero server fingerprinting headers detected.")

    # 4. RFC 9116 security.txt Verification
    print("\n--- 4. Checking RFC 9116 (/.well-known/security.txt) ---")
    sec_url = urllib.parse.urljoin(url, "/.well-known/security.txt")
    try:
        sec_req = urllib.request.Request(
            sec_url,
            headers={"User-Agent": "DEFCON-1-Live-Auditor/2.0"}
        )
        with urllib.request.urlopen(sec_req, timeout=min(5, timeout)) as sec_resp:
            content = sec_resp.read().decode("utf-8", errors="ignore")
            if "Contact:" in content:
                print(f" [PASS] RFC 9116 security.txt discovered and validated at: {sec_url}")
            else:
                print(" [WARN] security.txt exists but lacks mandatory 'Contact:' field.")
                score -= 3
    except Exception:
        print(" [INFO] No /.well-known/security.txt found at target.")
        score -= 2

    # 5. SpiderFoot-Inspired EASM: Perimeter Sensitive Exposure Check
    print("\n--- 5. SpiderFoot EASM: Exposed Sensitive Perimeter Files ---")
    sensitive_probes = SENSITIVE_PROBES
    for path, signature, alert in sensitive_probes:
        probe_url = urllib.parse.urljoin(url, path)
        try:
            p_req = urllib.request.Request(
                probe_url,
                headers={"User-Agent": "DEFCON-1-Live-Auditor/2.0"}
            )
            with urllib.request.urlopen(p_req, timeout=min(5, timeout)) as p_resp:
                if p_resp.status == 200:
                    body = p_resp.read().decode("utf-8", errors="ignore")
                    if signature in body:
                        print(f" [-] [CRITICAL DEFCON-1] {alert} detected at: {probe_url}")
                        score -= 50
                        findings.append(f"Exposed perimeter file: {path}")
                    else:
                        print(f" [PASS] {path} returned 200 but signature not matched.")
        except Exception:
            print(f" [PASS] {path} protected / not accessible (expected).")

    # 6. Subdomain Takeover & Dangling Cloud Resource Signatures
    print("\n--- 6. Subdomain Takeover & Dangling CNAME Fingerprints ---")
    takeover_signatures = [
        ("NoSuchBucket", "Dangling AWS S3 Bucket"),
        ("There isn't a GitHub Pages site here", "Dangling GitHub Pages CNAME"),
        ("No such app", "Dangling Heroku Application"),
        ("404 Web Site not found", "Dangling Azure App Service")
    ]
    try:
        req_page = urllib.request.Request(url, headers={"User-Agent": "DEFCON-1-Live-Auditor/2.0"})
        with urllib.request.urlopen(req_page, timeout=min(5, timeout)) as page_resp:
            page_body = page_resp.read().decode("utf-8", errors="ignore")
            takeover_detected = False
            for sig, provider in takeover_signatures:
                if sig in page_body:
                    print(f" [-] [CRITICAL DEFCON-1] Potential Subdomain Takeover: {provider} signature '{sig}' found!")
                    score -= 40
                    findings.append(f"Subdomain takeover risk: {provider}")
                    takeover_detected = True
            if not takeover_detected:
                print(" [PASS] Zero dangling cloud provider / takeover signatures detected.")
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="ignore")
        takeover_detected = False
        for sig, provider in takeover_signatures:
            if sig in err_body:
                print(f" [-] [CRITICAL DEFCON-1] Subdomain Takeover Detected: {provider} signature in HTTP {e.code} error!")
                score -= 40
                findings.append(f"Subdomain takeover risk: {provider}")
                takeover_detected = True
        if not takeover_detected:
            print(f" [PASS] HTTP {e.code} response does not match known takeover signatures.")
    except Exception:
        print(" [INFO] Could not re-evaluate response body for takeover signatures.")

    # 7. DNS Email Spoofing & Phishing Defense (DMARC & SPF via DoH)
    print("\n--- 7. DNS Email Anti-Spoofing & Phishing Defense (DMARC & SPF) ---")
    domain = parsed.hostname
    is_ip_or_local = False
    if domain:
        import ipaddress
        try:
            ipaddress.ip_address(domain)
            is_ip_or_local = True
        except ValueError:
            if domain in ("localhost", "127.0.0.1", "::1") or domain.endswith(".local") or domain.endswith(".internal"):
                is_ip_or_local = True

    if is_ip_or_local:
        print(f" [INFO] Target '{domain}' is an IP or local host. Skipping public DNS DMARC/SPF verification.")
    elif domain:
        domain_parts = domain.split(".")
        if len(domain_parts) >= 3 and domain_parts[-2] in ("co", "com", "org", "net", "edu", "gov") and len(domain_parts[-1]) == 2:
            root_domain = ".".join(domain_parts[-3:])
        elif len(domain_parts) >= 2:
            root_domain = ".".join(domain_parts[-2:])
        else:
            root_domain = domain
        
        # A. DMARC Verification
        doh_url_dmarc = f"https://dns.google/resolve?name=_dmarc.{root_domain}&type=TXT"
        try:
            doh_req = urllib.request.Request(doh_url_dmarc, headers={"Accept": "application/dns-json", "User-Agent": "DEFCON-1-Live-Auditor/2.0"})
            with urllib.request.urlopen(doh_req, timeout=min(5, timeout)) as doh_resp:
                dns_data = json.loads(doh_resp.read().decode("utf-8"))
                answers = [a.get("data", "") for a in dns_data.get("Answer", [])]
                dmarc_record = next((a for a in answers if "v=DMARC1" in a), None)
                if dmarc_record:
                    if "p=reject" in dmarc_record or "p=quarantine" in dmarc_record:
                        print(f" [PASS] Hardened DMARC Policy Active: {dmarc_record[:70]}...")
                    else:
                        print(f" [WARN] Permissive DMARC Policy (p=none): {dmarc_record[:70]}... (Spoofing risk)")
                        score -= 5
                        findings.append("Permissive DMARC policy")
                else:
                    print(f" [WARN] No DMARC TXT record found at _dmarc.{root_domain} (Email spoofing risk)")
                    score -= 5
                    findings.append("Missing DMARC record")
        except Exception:
            print(" [INFO] DNS-over-HTTPS DMARC query could not complete.")

        # B. SPF Verification
        doh_url_spf = f"https://dns.google/resolve?name={root_domain}&type=TXT"
        try:
            doh_req_spf = urllib.request.Request(doh_url_spf, headers={"Accept": "application/dns-json", "User-Agent": "DEFCON-1-Live-Auditor/2.0"})
            with urllib.request.urlopen(doh_req_spf, timeout=min(5, timeout)) as doh_spf_resp:
                dns_spf_data = json.loads(doh_spf_resp.read().decode("utf-8"))
                spf_answers = [a.get("data", "") for a in dns_spf_data.get("Answer", [])]
                spf_record = next((a for a in spf_answers if "v=spf1" in a), None)
                if spf_record:
                    if "-all" in spf_record:
                        print(f" [PASS] Strict SPF Policy Active (-all): {spf_record[:70]}...")
                    elif "~all" in spf_record:
                        print(f" [WARN] SoftFail SPF Policy Active (~all): {spf_record[:70]}...")
                        score -= 2
                    else:
                        print(f" [WARN] Permissive SPF Policy: {spf_record[:70]}... (Spoofing risk)")
                        score -= 4
                        findings.append("Permissive SPF policy")
                else:
                    print(f" [WARN] No SPF TXT record found for {root_domain}")
                    score -= 3
                    findings.append("Missing SPF record")
        except Exception:
            print(" [INFO] DNS-over-HTTPS SPF query could not complete.")

    # 8. Final Score & Rating
    final_score = max(0, score)
    print("\n==========================================================")
    print(f" LIVE PERIMETER AUDIT COMPLETE: Score {final_score}/100")
    print("==========================================================")

    if json_output:
        report = {
            "target": url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "score": final_score,
            "findings": findings,
            "headers_evaluated": list(headers.keys())
        }
        with open(json_output, "w", encoding="utf-8") as jf:
            json.dump(report, jf, indent=2)
        print(f"[JSON] Audit report exported to: {json_output}")

    if final_score >= 85:
        print(" STATUS: DEFCON-5 (EXCELLENT). Hardened perimeter configuration.")
        return 0
    elif final_score >= 60:
        print(" STATUS: DEFCON-3 (MODERATE RISK). Review missing headers.")
        return 1
    else:
        print(" STATUS: DEFCON-1 (CRITICAL RISK). Remediation strictly required.")
        return 2

def main():
    parser = argparse.ArgumentParser(
        description="DEFCON-1 Live Endpoint & Perimeter Auditor (Inspired by Web-Check)",
        epilog="Example: python check-live-endpoint.py https://example.com --json report.json"
    )
    parser.add_argument("url", nargs="?", help="Target URL or domain to audit (e.g., https://example.com)")
    parser.add_argument("--url", dest="url_opt", help="Target URL or domain (alternative to positional argument)")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP request timeout in seconds (default: 10)")
    parser.add_argument("--json", dest="json_output", help="Optional path to export JSON audit report")

    args = parser.parse_args()
    target_url = args.url or args.url_opt

    if not target_url:
        parser.print_help()
        sys.exit(1)

    sys.exit(audit_live_endpoint(target_url, timeout=args.timeout, json_output=args.json_output))

if __name__ == "__main__":
    main()
