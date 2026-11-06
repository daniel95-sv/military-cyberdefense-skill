# Multi-Platform Defense & System Hardening

This specification defines mandatory, platform-specific defensive controls required to achieve military-grade resilience across Web, Mobile, Desktop, and Cloud/API backends.

---

## 1. Web Applications & Frontend Defense

### A. Military-Grade HTTP Security Headers Baseline
Every response from web servers or reverse proxies (Cloudflare, Nginx, Caddy, Next.js) must include:

```http
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), display-capture=()
Content-Security-Policy: default-src 'none'; script-src 'self' 'nonce-{RANDOM_CRYPTO_NONCE}'; style-src 'self' 'nonce-{RANDOM_CRYPTO_NONCE}'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' https://api.yourdomain.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests; block-all-mixed-content;
```

### B. Client-Side Injection & Memory Defense
- **Zero Inline Scripts:** Disallow all inline `<script>` tags without a cryptographic nonce or hash. Never use `unsafe-inline` or `unsafe-eval`.
- **Trusted Types API:** Enforce browser-level sanitization using the W3C Trusted Types API (`require-trusted-types-for 'script'`).
- **DOM Sanitization:** If rich HTML rendering is strictly required, wrap all user-supplied markup through DOMPurify with strict profile configuration:
  ```typescript
  import DOMPurify from 'dompurify';
  const cleanHtml = DOMPurify.sanitize(untrustedInput, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
    ALLOWED_ATTR: ['href'],
    FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed'],
    FORBID_ATTR: ['onerror', 'onload', 'onclick']
  });
  ```
- **Subresource Integrity (SRI):** Any asset loaded from external CDNs must be pinned with SHA-384 or SHA-512 hashes (`integrity="sha384-..." crossorigin="anonymous"`).

---

## 2. Android Application Hardening

### A. AndroidManifest.xml Security Lockdown
```xml
<application
    android:allowBackup="false"
    android:fullBackupContent="false"
    android:networkSecurityConfig="@xml/network_security_config"
    android:usesCleartextTraffic="false"
    android:requestLegacyExternalStorage="false"
    android:hardwareAccelerated="true">
    
    <!-- All internal activities, services, receivers MUST be exported="false" -->
    <activity
        android:name=".MainActivity"
        android:exported="true">
        <intent-filter>
            <action android:name="android.intent.action.MAIN" />
            <category android:name="android.intent.category.LAUNCHER" />
        </intent-filter>
    </activity>

    <activity
        android:name=".InternalSecretActivity"
        android:exported="false" />
</application>
```

### B. Network Security Configuration (`res/xml/network_security_config.xml`)
Disallow cleartext HTTP and enforce certificate pinning:
```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <domain-config>
        <domain includeSubdomains="true">api.yourdomain.com</domain>
        <pin-set expiration="2027-01-01">
            <!-- Primary Certificate Pin -->
            <pin digest="SHA-256">7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=</pin>
            <!-- Backup Certificate Pin -->
            <pin digest="SHA-256">47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

### C. Screen Protection (`FLAG_SECURE`)
Prevent screen recording, screenshots, and task switcher snapshots of sensitive screens:
```kotlin
override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    window.setFlags(
        WindowManager.LayoutParams.FLAG_SECURE,
        WindowManager.LayoutParams.FLAG_SECURE
    )
}
```

---

## 3. Apple (iOS / iPadOS / macOS) Hardening

- **App Transport Security (ATS):** Do not add `NSAllowsArbitraryLoads = YES` under any circumstances. Cleartext HTTP is completely banned.
- **App Attest & DeviceCheck:** Verify device integrity and genuine app installation with Apple App Attest service before granting API access.
- **Anti-Debugging on Launch:** Prevent runtime attachment via GDB/LLDB in production builds:
  ```c
  #include <sys/types.h>
  #include <sys/ptrace.h>

  void disable_debuggers(void) {
  #ifndef DEBUG
      ptrace(PT_DENY_ATTACH, 0, 0, 0);
  #endif
  }
  ```
- **Keychain Storage:** Enforce `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` so encrypted data cannot be migrated to other devices via iCloud/iTunes backups.

---

## 4. Desktop (Electron / Tauri / Native) Hardening

### A. Electron Defense Rules (OWASP Electron Checklist)
1. `contextIsolation: true` (MANDATORY).
2. `nodeIntegration: false` (MANDATORY).
3. `sandbox: true` (MANDATORY).
4. `webSecurity: true` (Never disable).
5. Intercept and validate all navigation and window creation:
   ```javascript
   app.on('web-contents-created', (event, contents) => {
     contents.on('will-navigate', (event, navigationUrl) => {
       const parsedUrl = new URL(navigationUrl);
       if (parsedUrl.origin !== 'https://yourdomain.com') {
         event.preventDefault(); // Block unauthorized external navigation
       }
     });
     contents.setWindowOpenHandler(({ url }) => {
       return { action: 'deny' }; // Block popups and window creation
     });
   });
   ```

### B. Native Binaries (C/C++, Rust, Go)
- **ASLR (Address Space Layout Randomization):** Mandatory (`-fPIE -pie`).
- **Stack Canaries / Buffer Overflow Protection:** `-fstack-protector-strong` or `-fstack-protector-all`.
- **NX / DEP (Data Execution Prevention):** Mark stack and heap as non-executable.
- **Control Flow Guard (CFG) / SafeStack:** Active.
- **Strip Symbols:** Remove debug tables, symbols, and function names in release builds (`strip --strip-all`).

---

## 5. Backend, APIs & Cloud Defense

### A. Strict Input Validation (Deny-by-Default)
Every API endpoint must parse requests using strict schema validators (Zod, Pydantic, or TypeBox) before any logic runs:
```typescript
import { z } from 'zod';

const UpdateProfileSchema = z.object({
  username: z.string().alphanumeric().min(3).max(30),
  email: z.string().email().max(100),
  age: z.number().int().min(18).max(120)
}).strict(); // CRITICAL: Reject extra/unrecognized parameters (prevents Mass Assignment)
```

### B. Parameterized SQL & ORM Protection
Never concatenate strings or format raw SQL queries:
```typescript
// PROHIBITED (SQL Injection)
await db.query(`SELECT * FROM users WHERE email = '${email}'`);

// MANDATORY: Parameterized query
await db.query('SELECT * FROM users WHERE email = $1', [email]);
```

### C. Rate Limiting, Brute-Force & DoS Mitigation
- **Tier 1 (Edge / WAF):** Cloudflare Rate Limiting rules (e.g., max 10 requests per minute on `/auth/*` endpoints).
- **Tier 2 (Application Layer):** Redis-backed sliding window rate limiter per IP, per user ID, and per API key:
  - Account login: 5 attempts per 15 minutes.
  - Password reset: 3 requests per hour.
  - General API: 100 requests per minute.

### D. Server-Side Request Forgery (SSRF) Defense
Whenever the server fetches a user-supplied URL (e.g. webhooks, link previews, file downloads):
1. **Block Private & Cloud Metadata IP Ranges:** Validate IP addresses after DNS resolution. Reject:
   - Loopback: `127.0.0.0/8`, `::1`
   - Private networks (RFC 1918): `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
   - Link-local & Cloud Metadata: `169.254.169.254`, `fd00::/8`
2. **Mitigate DNS Rebinding:** Pin the resolved IP address and connect directly to the verified IP, passing the host header manually.
3. **Disable Unsafe Protocols:** Allow only `https:` schemes. Explicitly reject `file://`, `gopher://`, `ftp://`, `ldap://`.

### E. Path Traversal & Arbitrary File Access Defense
Never concatenate untrusted file names directly into disk operations:
```typescript
import path from 'node:path';

export function resolveSafePath(baseDir: string, userFilename: string): string {
  // 1. Strip null bytes and normalize
  const cleanFilename = userFilename.replace(/\0/g, '');
  const resolvedPath = path.resolve(baseDir, cleanFilename);

  // 2. Enforce strict directory confinement
  if (!resolvedPath.startsWith(path.resolve(baseDir) + path.sep)) {
    throw new SecurityException('Path traversal attempt detected');
  }
  return resolvedPath;
}
```

---

## 6. Container, Docker & Infrastructure-as-Code (IaC) Defense (Aqua Trivy Baseline)

In cloud-native deployments, containers and orchestrators (Kubernetes / Docker Compose) are common escalation paths. Following the **Aqua Security Trivy** hardening standards:

### A. Rootless Container Lockdown
Never run containerized workloads as `root` (UID 0). Compromising a root container allows kernel exploitation and host escape.
- Create an explicit unprivileged user and switch to it in the Dockerfile:
  ```dockerfile
  RUN addgroup -g 10001 -S appgroup && \
      adduser -u 10001 -S appuser -G appgroup
  USER 10001:10001
  ```

### B. Distroless & Multi-Stage Production Builds
Attackers cannot execute shell scripts or reverse engineering tools if those tools are not present in the runtime image:
1. **Multi-Stage Builds:** Compile and package in a heavy builder stage; copy only the compiled static binary/dist folder into a minimal final stage.
2. **Distroless or Minimal Alpine:** Use `gcr.io/distroless/static-debian12` or `alpine:3.20` with zero package managers (`apk`, `apt`), zero compilers, and zero shell (`/bin/sh`) in the production container.
3. **Pinned Base Image Digests:** Never use mutable tags like `:latest`. Pin by cryptographic SHA-256 digest:
   ```dockerfile
   FROM node:22-alpine@sha256:d8396c21e3f898f8045610ec1...
   ```

### C. Kernel Capability Dropping & Immutable Filesystem (Docker Compose / K8s)
```yaml
services:
  api:
    image: myorg/api:v1.0.0
    read_only: true # Make root filesystem immutable
    security_opt:
      - no-new-privileges:true # Prevent SUID privilege escalation
    cap_drop:
      - ALL # Drop all Linux kernel capabilities
    cap_add:
      - NET_BIND_SERVICE # Re-add only if binding privileged port < 1024
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=64m # Ephemeral writable scratch without execution rights
```

### D. Zero Docker Socket Mounting
Mounting `/var/run/docker.sock` inside any container grants that container root-level control over the entire host daemon. It is strictly prohibited.

### E. Cloud Security Posture Management (CSPM) & Multi-Cloud Hardening (Prowler Doctrine)
Following the **Prowler** multi-cloud benchmark across AWS, GCP, Azure, and Kubernetes:

1. **Cloud Identity & Access Management (IAM):**
   - **Zero Wildcards:** Strictly forbid IAM policies granting `"Action": "*"` with `"Resource": "*"`. All permissions must be scoped to specific API verbs and ARNs.
   - **Root Account Lockdown:** Never create active access keys for AWS root or GCP owner accounts. Mandate hardware FIDO2 MFA on root.
   - **Credential Hygiene:** Automatically deactivate IAM access keys unused for $>90$ days.

2. **Cloud Storage & Data Perimeter:**
   - **S3 / Cloud Storage Public Access Block:** Enforce account-level S3 Public Access Block (`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`). Never permit `acl = "public-read"`.
   - **Default Encryption:** Mandate KMS customer-managed keys (CMK) or AES-256 server-side encryption across all S3 buckets, EBS volumes, and RDS databases.

3. **Network Security Groups (Firewall Lockdown):**
   - **Zero Inbound 0.0.0.0/0 on Management Ports:** Security groups must never permit unrestricted public ingress to Port 22 (SSH), Port 3389 (RDP), or database ports (3306, 5432, 27017, 6379). Access must be restricted to private VPCs or Bastion/VPN endpoints.

4. **Kubernetes (K8s) Pod Security Standards (Restricted Profile):**
   - Disallow `privileged: true` and `allowPrivilegeEscalation: true`.
   - Prohibit sharing host namespaces (`hostPID: true`, `hostNetwork: true`, `hostIPC: true`).
   - Mandate resource limits (CPU/Memory) on all containers to prevent noisy-neighbor DoS.

---

## 7. External Attack Surface Management (EASM) & Perimeter Defense (SpiderFoot Doctrine)

In real-world intrusions, attackers rarely strike hardened production portals directly. They exploit **forgotten assets, shadow IT, and perimeter misconfigurations**. Following the SpiderFoot reconnaissance doctrine, applications must defend their external attack surface against:

### A. Subdomain Takeover & Dangling CNAME Mitigation
- **Attack Vector:** An organization creates a DNS record pointing `docs.company.com` to an AWS S3 bucket, GitHub Pages, or Heroku app. When the cloud resource is deleted but the DNS CNAME record remains, an attacker provisions that exact bucket/app name on the cloud provider, claiming complete control of the subdomain with a trusted SSL certificate.
- **Mandatory Defenses:**
  1. **Continuous Dangling CNAME Audits:** Query all DNS CNAME records automatically. Verify that every target resolves to an active, internally owned asset.
  2. **Synchronized Infrastructure De-provisioning:** Enforce Terraform/IaC destruction pipelines that delete DNS entries **prior** to terminating the underlying cloud resources.
  3. **Monitor Error Pages:** Scan all subdomains for provider error signatures (`NoSuchBucket`, `There isn't a GitHub Pages site here`, `No such app`, `404 Web Site not found`).

### B. Perimeter VCS & Sensitive Path Lockdown
- **Attack Vector:** Web servers misconfigured to expose `/.git/HEAD` allow attackers to clone entire source repositories (including past commits and hardcoded secrets) via tools like `git-dumper`. Exposing `/.env` immediately leaks runtime credentials.
- **Mandatory Defenses:**
  1. **Edge/WAF Block Rules:** Configure reverse proxies (Cloudflare, Nginx, Caddy) to unconditionally return HTTP 403 or 404 for sensitive path patterns:
     ```nginx
     location ~ /\.(git|env|svn|htaccess|docker) {
         deny all;
         return 404;
     }
     ```
  2. **Automated Live Probe Verification:** Execute `python scripts/check-live-endpoint.py https://target.domain` on post-deployment pipelines to confirm that `/.git/HEAD` and `/.env` return access denied.

### C. DNS Hygiene & Email Anti-Spoofing (DMARC, SPF & DNSSEC)
- **Attack Vector:** Missing or permissive email authentication policies allow attackers to send spoofed phishing emails appearing to originate from `admin@yourdomain.com` or `ceo@yourdomain.com`.
- **Mandatory Defenses:**
  1. **Enforce Strict DMARC Policy:** Deploy `_dmarc.yourdomain.com` TXT record with `p=reject` (reject fraudulent emails):
     ```text
     v=DMARC1; p=reject; sp=reject; adkim=r; aspf=r; pct=100; rua=mailto:dmarc-reports@yourdomain.com
     ```
  2. **SPF Hard Fail:** Terminate SPF records with `-all` (hard fail) rather than `~all` (soft fail).
  3. **Disable DNS Zone Transfers (AXFR):** Authoritative DNS nameservers must reject AXFR zone transfers from untrusted public IPs to prevent attackers from mapping the internal network topology.

