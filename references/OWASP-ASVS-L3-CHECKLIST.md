# OWASP ASVS Level 3 Verification Checklist

> [!NOTE]
> This is a **curated critical-controls subset** of OWASP ASVS Level 3, covering the highest-impact requirements for mission-critical software. The complete ASVS L3 standard contains ~300 requirements. Refer to the [official OWASP ASVS specification](https://owasp.org/www-project-application-security-verification-standard/) for the full list.

The **OWASP Application Security Verification Standard (ASVS) Level 3** is the highest level of security verification, reserved for mission-critical software, military applications, healthcare, and high-value financial systems.

Use this checklist during Phase 5 of the defensive workflow to certify a project's security posture.

---

| Category | Check ID | Defense Verification Requirement | Status |
| :--- | :--- | :--- | :--- |
| **V1: Architecture** | 1.1.1 | Threat model documented using STRIDE or MITRE ATT&CK. | [ ] |
| | 1.1.2 | Explicit trust boundaries defined between all system components. | [ ] |
| | 1.1.3 | Principle of Least Privilege (PoLP) enforced across all services. | [ ] |
| **V2: Authentication** | 2.1.1 | Anti-brute-force rate limiting with progressive delay or lockout. | [ ] |
| | 2.1.2 | MFA / FIDO2 / WebAuthn supported for all administrative access. | [ ] |
| | 2.1.3 | Password storage uses Argon2id (RFC 9106) with memory hardness. | [ ] |
| **V3: Session Mgmt** | 3.1.1 | Session tokens have 128+ bits of cryptographic entropy. | [ ] |
| | 3.1.2 | Cookies use `__Host-` prefix, `Secure`, `HttpOnly`, `SameSite=Strict`. | [ ] |
| | 3.1.3 | Server-side invalidation immediately upon logout. | [ ] |
| **V4: Access Control** | 4.1.1 | Authorization checked on every API call (centralized PEP). | [ ] |
| | 4.1.2 | Multi-tenant isolation verified (no IDOR / BOLA vulnerabilities). | [ ] |
| | 4.1.3 | Direct object references use UUIDv4 or encrypted tokens, not sequential IDs. | [ ] |
| **V5: Validation** | 5.1.1 | Strict schema validation with reject-by-default on all endpoints. | [ ] |
| | 5.1.2 | Parameterized queries used for 100% of SQL/NoSQL interactions. | [ ] |
| | 5.1.3 | HTML output contextually encoded to neutralize XSS vectors. | [ ] |
| **V6: Cryptography** | 6.1.1 | AES-256-GCM or ChaCha20-Poly1305 for all data at rest. | [ ] |
| | 6.1.2 | Hardware-backed keystores (StrongBox/Secure Enclave/TPM/Vault) used. | [ ] |
| | 6.1.3 | Cryptographic random number generator used for all IVs, nonces, and tokens. | [ ] |
| **V7: Error & Logs** | 7.1.1 | Generic user-facing errors returned; stack traces suppressed in production. | [ ] |
| | 7.1.2 | Zero PII, tokens, or passwords logged to storage or console. | [ ] |
| | 7.1.3 | Log injection (CRLF) prevented via input sanitization before logging. | [ ] |
| **V8: Data Protection** | 8.1.1 | Sensitive memory zeroized immediately after cryptographic operations. | [ ] |
| | 8.1.2 | Client caching disabled for sensitive responses (`Cache-Control: no-store`). | [ ] |
| **V9: Communications** | 9.1.1 | TLS 1.3 enforced; legacy SSL/TLS 1.0/1.1 completely disabled. | [ ] |
| | 9.1.2 | SPKI certificate pinning implemented on mobile/desktop clients. | [ ] |
| | 9.1.3 | HSTS with `preload` and `includeSubDomains` active. | [ ] |
| **V10: Malicious Code**| 10.1.1 | Dynamic code execution (`eval`, `Function()`, `exec`) strictly banned. | [ ] |
| | 10.1.2 | Anti-tamper, Frida detection, and root/jailbreak checks enabled. | [ ] |
| **V11: Business Logic**| 11.1.1 | Race conditions prevented via database-level transactional locks. | [ ] |
| | 11.1.2 | State machines strictly enforce sequential workflow steps. | [ ] |
| **V12: File Uploads** | 12.1.1 | File uploads validate magic bytes (not just extension or MIME header). | [ ] |
| | 12.1.2 | Files stored outside webroot or on isolated S3/GCS buckets without execute rights. | [ ] |
| **V13: API Security** | 13.1.1 | CORS configured with explicit origin allowlist; no wildcard with credentials. | [ ] |
| | 13.1.2 | API rate limiting active at edge (WAF) and application layer. | [ ] |
| **V14: Configuration** | 14.1.1 | Content Security Policy (CSP Level 3) active with nonces. | [ ] |
| | 14.1.2 | All default vendor passwords and demo accounts removed. | [ ] |
| | 14.1.3 | Automated secret scanning active in pre-commit and CI/CD pipelines. | [ ] |

