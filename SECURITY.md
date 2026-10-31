# Security Policy & Threat Model

ReconForge is an automated subdomain reconnaissance and active service probing engine designed for authorized penetration testing, bug bounty hunting, and attack surface management. Because network scanners actively probe target infrastructure, they inherently touch sensitive network boundaries and must defend against weaponized DNS responses, SSRF (Server-Side Request Forgery), DNS rebinding, and uncontrolled query loops.

---

## 1. Threat Model & Mitigations

### 1.1 Server-Side Request Forgery (SSRF) & Cloud IMDS Theft

#### The Attack Vector
When actively probing discovered subdomains via HTTP/HTTPS (`probeLiveHost`), an adversary controlling DNS records for a target domain (or a malicious user scanning their own rogue domain) could configure a subdomain's `A` or `AAAA` record to point to:
1. **Cloud Instance Metadata Service (IMDS)**: `169.254.169.254` (AWS EC2, GCP metadata, Azure instance metadata).
2. **Local Loopback**: `127.0.0.1` or `127.0.0.0/8`, `::1`, `0:0:0:0:0:0:0:1`, `::`.
3. **Internal RFC 1918 & Reserved Subnets**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10` (CGNAT), `0.0.0.0/8`, `192.0.0.0/24`, `198.18.0.0/15`, `224.0.0.0/4` (Multicast), `240.0.0.0/4`.
4. **IPv6 Private & Link-Local Ranges**: `fc00::/7` (Unique Local Addresses), `fe80::/10` (Link-Local Unicast), `ff00::/8` (Multicast).
5. **IPv4-Mapped IPv6 Bypasses**: `::ffff:127.0.0.1`, `::ffff:169.254.169.254`, or hex equivalents (`::ffff:7f00:0001`).

#### ReconForge Mitigation
ReconForge implements a defense-in-depth architecture using Node.js's native `net.BlockList`:
1. **Subnet Parsing & Normalization**: Address strings are parsed and evaluated directly against binary CIDR subnets rather than naive prefix string matching. IPv4-mapped IPv6 addresses (`::ffff:`) are automatically unmapped and evaluated against IPv4 rules.
2. **Connect-Time DNS Rebinding Defense**: To eliminate the check-then-use (TOCTOU) gap where a DNS server might return a public IP during pre-check and `127.0.0.1` during the socket connection, `safeHttpRequest` passes a custom `lookup` function directly to `http.request` / `https.request`. Every resolved `A` and `AAAA` address is validated at socket establishment time. If any address falls within the blocklist, the connection is aborted immediately (`ERR_SSRF_BLOCKED`) before any TCP SYN or TLS handshake.

---

### 1.2 Differentiated TLS Verification Policy

- **Strict TLS for OSINT Intelligence APIs**: When querying external threat intelligence APIs (`crt.sh`, `AlienVault OTX`, `HackerTarget`), ReconForge enforces strict TLS verification (`rejectUnauthorized: true`). This prevents on-path man-in-the-middle attackers from injecting fraudulent subdomains into your assessment pipeline.
- **Lenient TLS for Target Probing**: When actively probing target services, ReconForge configures the probe client with `rejectUnauthorized: false`. Valid target applications with self-signed, staging, or expired certificates are accurately discovered and fingerprinted without prematurely dropping the asset.

---

### 1.3 Wildcard DNS Handling & False-Positive Elimination

#### The Vulnerability
If an organization configures a wildcard DNS record (`*.target.com IN A 192.0.2.1`), queries for non-existent subdomains resolve successfully. Without wildcard handling, common prefix dictionary guessing returns 100% false positives, and passive DNS hits under the wildcard zone flood the results with identical IPs.

#### ReconForge Mitigation
1. **Automated Wildcard Pre-Check**: Before dictionary resolution, ReconForge tests a cryptographically randomized label (`_wildcard_check_<random>.<domain>`).
2. **Dictionary Bypass**: If a wildcard record is detected, high-frequency prefix guessing is bypassed automatically.
3. **Passive Hit Filtering**: Passive records collected from certificate logs and OSINT feeds are resolved against the detected wildcard IP set. Records that resolve exclusively to wildcard IPs are filtered to ensure only verified, distinct services are probed.

---

### 1.4 Dangling CNAME Takeover Verification

ReconForge actively resolves DNS `CNAME` records using `dns.resolveCname` for candidate subdomains.
- **Confirmed Vulnerability**: If a subdomain's CNAME record explicitly points to an external cloud provider (e.g. `*.github.io`, `*.s3.amazonaws.com`, `*.herokudns.com`, `*.zendesk.com`, `*.myshopify.com`) AND the HTTP response matches the unclaimed service error signature, it is reported as a confirmed takeover risk with remediation steps.
- **Unconfirmed / Possible Risk**: If the HTTP response body matches an error signature but no CNAME record is resolved (or does not point to the expected provider domain), it is labeled honestly as "Possible" with a reduced severity rating.

---

### 1.5 Host Binding, CORS Origin Lockdown & DoS Prevention

- **Host Binding**: Configurable via `process.env.HOST` (defaults to `0.0.0.0` in containerized/preview environments, configurable to `127.0.0.1` for standalone local deployment).
- **Strict CORS Policy**: CORS origins are restricted to local addresses (`localhost`, `127.0.0.1`) and authorized preview origins. Unauthorized cross-origin requests from arbitrary websites are rejected.
- **Bounded Request Limits & Deadlines**: Every HTTP request in `safeHttpRequest` enforces an overall deadline timer (with `req.destroy()`) and per-call response byte limits (`maxBytes`: 15MB for large Certificate Transparency JSON, 150KB for live host HTML inspection) to prevent slowloris dripping attacks and out-of-memory crashes.
- **Scan History Eviction**: In-memory scan state is capped at 30 entries using bounded LRU eviction to prevent memory exhaustion during long-running sessions.

---

## 2. Responsible Disclosure Policy

If you discover a security vulnerability within ReconForge:
1. Please report it privately by opening a security advisory or contacting the maintainer directly.
2. Provide a reproduction script or proof of concept.
3. We will respond within 48 hours and work with you on a coordinated fix.

---

## 3. Permitted & Authorized Use

ReconForge performs active network requests (DNS queries and HTTP/HTTPS GET requests) during stage 5. **You must only scan domain names you own or have explicit written permission to assess under an authorized bug bounty program or penetration testing engagement.**
