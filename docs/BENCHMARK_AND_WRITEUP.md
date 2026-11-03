# ReconForge Engineering Architecture & Technical Postmortem

## 1. Executive Summary & Purpose

ReconForge was conceived to solve a recurring operational friction in offensive security workflows: running reconnaissance and surface mapping on client targets typically requires configuring external toolchains (`subfinder`, `assetfinder`, `httpx`), managing external binary PATHs, and manually correlating output files into reports.

Our goal was to build a **native Node.js reconnaissance and service-probing engine** (requiring no external Go or Python binaries) paired with a real-time reactive desktop GUI, while strictly safeguarding the researcher's host environment against Server-Side Request Forgery (SSRF), DNS rebinding, and cross-origin scanner hijacking.

---

## 2. Architecture & Pipeline Design

ReconForge uses a **dual-stage discovery pipeline** separating non-intrusive intelligence gathering from active host verification:

```text
[ Target FQDN ]
       │
       ▼
[ Stage 1: Scope Validation ] ─── RFC 1035 & IDN Punycode Syntax Checker
       │
       ▼
[ Stage 2 & 3: Passive OSINT ] ── crt.sh (Strict TLS) + AlienVault OTX + HackerTarget
       │                         Dual-stack Canary DNS Probes (IPv4 + IPv6)
       ▼
[ Stage 4: Wildcard Filter ] ──── Discard speculative guesses; preserve CT cryptographic records
       │
       ▼
[ Stage 5: Active Probing ] ───── Connect-Time SSRF Socket Guard (lookup hook)
       │                         HTTP/HTTPS dual-stack status, latency, headers
       │                         Dangling CNAME Takeover Heuristics (per-resource DNS)
       ▼
[ Stage 6: Export & Visuals ] ── Markdown report, summary.txt, alive.txt, Canvas Topology
```

---

## 3. What We Broke and How We Fixed It (Engineering Postmortem)

During our iterative hardening process, we uncovered and systematically eliminated five critical failure modes:

### Issue A: Outbound TOCTOU DNS Rebinding (SSRF)
- **What Was Broken**: Initially, we resolved domain names to IPs in a pre-flight check before issuing `http.request`. A malicious DNS server returning a short TTL could return a benign IP (`8.8.8.8`) on the first query, followed by AWS Instance Metadata (`169.254.169.254`) or loopback (`127.0.0.1`) on the actual HTTP request.
- **Root Cause**: Time-of-Check to Time-of-Use (TOCTOU) separation between DNS validation and TCP socket connection.
- **The Fix**: We wired a custom `lookup` hook (`lookup: ssrfSafeLookup`) directly into `http.request`. This hook runs inside Node's native socket establishment pipeline, verifying *every* returned `A` and `AAAA` record against a comprehensive `net.BlockList` before the TCP SYN packet leaves the host. We also added explicit pre-connection socket guards for direct IP literals (`http://169.254.169.254`), where Node's client skips DNS `lookup`.

### Issue B: IPv6 Encapsulation & String Prefix Matching
- **What Was Broken**: Our early SSRF filter used string-prefix checks (`startsWith('127.')`, `=== '::ffff:127.0.0.1'`). This permitted bypasses using alternative loopback addresses (such as `::ffff:127.0.0.2`), NAT64 well-known prefixes (`64:ff9b::7f00:1`), and 6to4 encapsulation (`2002:7f00:1::1`).
- **Root Cause**: IPv6 allows multiple valid textual representations for identical addresses, rendering string comparison fundamentally flawed.
- **The Fix**: We replaced string checks with bitwise unwrapping functions (`unwrapEmbeddedIPv4`, `expandIPv6ToWords`). All encapsulated IPv4 addresses are unwrapped to their canonical 32-bit forms and validated against dedicated `net.BlockList` subnets. Malformed or unparseable inputs fail closed and are blocked immediately.

### Issue C: Wildcard Over-Pruning
- **What Was Broken**: When a target domain had a wildcard DNS zone (`*.target.com`), our initial implementation discarded any discovered host whose IP matched the wildcard IP. This caused severe false negatives: legitimate production subdomains hosted behind the same load balancer or CDN as the wildcard were mistakenly dropped.
- **The Fix**: We decoupled dictionary discovery from cryptographic evidence. Speculative wordlist guesses matching wildcard canary responses are discarded; however, records discovered via Certificate Transparency logs (`crt.sh`) or passive DNS indexes are preserved and individually probed for HTTP responsiveness and distinctive headers.

### Issue D: Subdomain Takeover Signal Calibration
- **What Was Broken**: Dead CNAMEs pointing to `*.amazonaws.com` (such as decommissioned ELBs) were reported as "Critical S3 Takeovers". Furthermore, checking NXDOMAIN on shared anycast providers (like GitHub Pages or S3) yielded false assumptions, while resolver timeouts (`ESERVFAIL`) produced phantom takeover warnings.
- **The Fix**:
  1. Implemented a tightened regional S3 regex (`/^(?:[a-z0-9.-]+\.)?s3(?:(?:\.[a-z0-9-]+)?|-website[.-][a-z0-9-]+|-(?:[a-z]{2,}-[a-z]+-\d+))?\.amazonaws\.com$/i`) that explicitly excludes ELB domains and arbitrary prefixes like `s3-evil.amazonaws.com`.
  2. Added a `perResourceDns: true/false` flag to `TAKEOVER_SERVICES`: NXDOMAIN target checks are *only* executed for providers that de-register DNS records upon resource teardown (AWS Elastic Beanstalk, Azure Web App, Azure Traffic Manager). Shared anycast platforms rely exclusively on HTTP status and response-body fingerprinting.
  3. Resolver errors other than genuine `ENOTFOUND` (such as `ESERVFAIL` or `ETIMEOUT`) are ignored.

### Issue E: Inbound DNS Rebinding & Cross-Origin Scanner Hijacking
- **What Was Broken**: The local server bound to `0.0.0.0` with wildcard CORS headers, allowing external websites visited by the researcher to issue unauthorized scan requests against internal infrastructure.
- **Root Cause**: Trusting ambient local network requests without validating origins, host headers, or request intent.
- **The Fix**:
  1. Defaulted listener to `127.0.0.1` (configurable via `HOST`).
  2. Enforced strict exact-origin matching (`ALLOWED_ORIGINS`), eliminating arbitrary cloud subdomains and removing `credentials: true`.
  3. Added an Inbound `Host` header validation middleware (`isValidHostHeader`) that returns `403 Forbidden` on unexpected host headers.
  4. Required a cryptographically random per-session token (`x-reconforge-session`) verified via `crypto.timingSafeEqual` on all mutating scan triggers (`POST /api/recon/start`).
  5. Implemented a concurrency throttle (`MAX_CONCURRENT_RUNNING = 3`) returning `429 Too Many Requests` when saturated, strictly protecting running scans from resource starvation or LRU eviction.

---

## 4. Evaluation Methodology: Establishing Ground Truth

In offensive tooling and asset discovery, measuring true precision and recall requires establishing an authoritative **ground truth**.

### Why Third-Party Public Domains Do Not Provide Ground Truth
Comparing tool outputs on arbitrary third-party domains (such as bug bounty scopes or public sites) only measures **source overlap**, not true recall:
- **Unknown Total Population**: Without authoritative zone records, the total set of existing subdomains is unknown ($TP + FN$).
- **Unresolvable Records**: Passive sources frequently index historical DNS records or expired certificates that no longer resolve. Labeling an unresolvable passive record as either a "true positive" or a "false positive" without authoritative zone context is methodologically invalid.
- **Authorization Boundaries**: While passive intelligence gathering (Stages 1–3) queries public logs, active service probing (Stage 5) transmits direct HTTP/HTTPS requests to discovered endpoints. Active probing must only be performed against assets you own or have explicit, written authorization to test.

### Recommended Ground Truth Testing Protocol
To rigorously evaluate discovery precision and recall, security teams should execute benchmarks against an owned, authoritative DNS zone:

1. **Controlled Zone Setup**: Configure an authoritative DNS zone (e.g., `test-zone.net`) with known, pre-determined asset categories:
   - 20 static `A` / `AAAA` production records.
   - 5 wildcard-matching test subdomains under `*.wildcard.test-zone.net`.
   - 3 intentional dangling CNAME records pointing to NXDOMAIN targets across both per-resource providers (e.g. AWS Elastic Beanstalk) and anycast providers.
   - At least 2 certificates pre-logged to Certificate Transparency (e.g. via Let's Encrypt staging/production).
2. **Measurement Criteria**:
   - **Precision**: $\frac{\text{True Active Subdomains Discovered}}{\text{Total Subdomains Reported by Engine}}$
   - **Recall**: $\frac{\text{Configured Zone Assets Discovered}}{\text{Total Known Configured Zone Assets}}$
   - **Wildcard Resilience**: Number of bogus/non-existent wildcard labels incorrectly elevated to verified active assets.
3. **Reproducibility**: Run automated test runs across multiple independent DNS resolvers (`1.1.1.1`, `8.8.8.8`, local recursive), capturing full raw JSON output files and network trace logs.

---

## 5. Verification & Test Evidence

The codebase includes an automated unit test suite executed via Node's native test runner (`node:test` and `node:assert/strict`):

```bash
npm test
```

### Verified Test Invariants (13/13 Passing)

```text
✔ sanitizeDomain - normalizes raw user inputs
✔ isValidDomain - strictly validates FQDNs and Punycode IDNs
✔ Invariant: isValidDomain rejects IP literals so Node never skips lookup hook
✔ isPrivateOrReservedIp - fails closed on invalid input and blocks all SSRF vectors
✔ classifyIpRisk - accurately classifies internal IP ranges with tiered severities
✔ isTokenValid - performs constant-time cryptographic token verification
✔ storeScan and getScan - implements true LRU cache and preserves running scans
✔ isValidHostHeader - protects against inbound DNS rebinding
✔ isAllowedOrigin - exact matching blocks arbitrary subdomains and attacker origins
✔ detectWildcardDNS - tests both IPv4 and IPv6 canary addresses
✔ checkTakeoverRisk - verified per-resource cloud services, regional S3 regex, and NXDOMAIN logic
✔ Live Express API tests: Host header rebinding protection, read routes, session tokens & 429 throttle
✔ Live SSRF defense: verifies connection-time hook blocks loopback and local server receives 0 hits
```

### Continuous Integration (CI)
A multi-version GitHub Actions workflow (`.github/workflows/ci.yml`) runs on every commit and pull request across active LTS Node.js versions (**Node.js 22.x and 24.x**), validating:
1. Exact dependency resolution via `npm ci` from the committed `package-lock.json`.
2. Clean execution of the full unit test suite via `npm test`.
3. Complete production asset compilation via `npm run build`.

---

## 6. Summary

ReconForge v2.1 eliminates the need for managing external Go or Python binary dependencies for routine reconnaissance workflows. By implementing native OSINT harvesting, dual-stack canary wildcard detection, connect-time SSRF socket defenses, and verified per-resource takeover heuristics, ReconForge provides a secure and verifiable asset discovery pipeline.
