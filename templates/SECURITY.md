# Security Policy & Vulnerability Disclosure

This project adheres to **DEFCON-1 Military-Grade Cyberdefense Standards**. We treat the security and privacy of our systems and users with the highest level of priority.

---

## 1. Supported Versions

Only the latest active release branch receives proactive security patches:

| Version | Supported | Security SLA |
| :--- | :--- | :--- |
| **Current Main (`v2.x`)** | :white_check_mark: Yes | Critical: < 24h / High: < 72h |
| **Prior Release (`v1.x`)**| :warning: Critical Only | Critical: < 48h |
| **Legacy (< v1.0)** | :x: No | Unsupported |

---

## 2. Reporting a Vulnerability

**DO NOT report security vulnerabilities via public GitHub issues, discussions, or pull requests.**

If you believe you have discovered a vulnerability, follow this responsible disclosure procedure:

1. **Direct Communication:** Send an encrypted email to our security team at:
   `security@yourdomain.com`
2. **PGP Encryption:** Please encrypt your email using our official Security PGP Key:
   ```text
   -----BEGIN PGP PUBLIC KEY BLOCK-----
   Comment: DEFCON-1 Security Operations PGP Key
   [Insert your public PGP Key block here]
   -----END PGP PUBLIC KEY BLOCK-----
   ```
3. **Report Contents:** Include the following information to facilitate immediate reproduction:
   - Specific component or endpoint affected.
   - Severity and potential impact (Confidentiality, Integrity, Availability).
   - Step-by-step reproduction instructions or safe proof of concept (PoC).
   - Any proposed patch or mitigation.

---

## 3. Our Commitment & SLA

- **Initial Triage:** Within **24 hours** of receipt.
- **Vulnerability Confirmation & Impact Rating:** Within **48 hours**.
- **Fix & Verification:** We will deploy a patch through our **Surgical Patch & Re-Verification Harness** before public disclosure.
- **Coordinated Disclosure:** We adhere to a 90-day coordinated disclosure timeline, or earlier upon mutual agreement once the patch is rolled out.

---

## 4. Safe Harbor

Any research conducted in good faith according to this policy is considered authorized. We will not pursue legal action against researchers who:
- Do not exploit the vulnerability beyond what is strictly necessary to prove existence.
- Do not access, modify, or exfiltrate another user's data.
- Avoid disruption to production systems or denial of service (DoS).

---

## 5. Out of Scope

The following activities are **explicitly out of scope** and will not be treated as authorized security research:
- **Denial of Service (DoS/DDoS):** Any test designed to overwhelm, degrade, or disrupt availability of our services.
- **Social Engineering:** Phishing, vishing, or any attempt to manipulate our employees or contractors.
- **Physical Attacks:** Attempting to gain physical access to our infrastructure, offices, or hardware.
- **Testing on Accounts You Do Not Own:** Any testing against accounts, data, or systems belonging to other users or organizations.
- **Automated Scanners Without Prior Approval:** Running automated vulnerability scanners at scale against our production infrastructure without written authorization.

> [!NOTE]
> If you discover a vulnerability that falls outside this policy, please still reach out via our secure contact. We review all reports in good faith.

