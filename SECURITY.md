# Security Policy & Threat Model

ReconForge is an automated attack surface reconnaissance and service probing engine designed for authorized penetration testing, bug bounty assessments, and attack surface management. Because network scanners actively probe target infrastructure, they operate on sensitive network boundaries and must defend against weaponized DNS responses, Server-Side Request Forgery (SSRF), DNS rebinding, and cross-origin hijacking.

---

## 1. Threat Model & Mitigations

### 1.1 Server-Side Request Forgery (SSRF) & Cloud Metadata Defense

#### The Attack Vector
When actively probing discovered subdomains via HTTP/HTTPS, an adversary controlling DNS records for a target domain (or a malicious user scanning an adversarial domain) could configure a subdomain's `A` or `AAAA` record to point to:
1. **Cloud Instance Metadata Service (IMDS)**: `169.254.169.254` (AWS EC2, GCP metadata, Azure instance metadata).
2. **Local Loopback**: `127.0.0.1`, `127.0.0.0/8`, `::1`, `0:0:0:0:0:0:0:1`, `::`.
3. **Internal RFC 1918 & Reserved Subnets**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10` (CGNAT), `0.0.0.0/8`, `192.0.0.0/24`, `198.18.0.0/15`, `224.0.0.0/4` (Multicast), `240.0.0.0/4`.
4. **IPv6 Private & Link-Local Ranges**: `fc00::/7` (Unique Local Addresses), `fe80::/10` (Link-Local Unicast), `ff00::/8` (Multicast).
5. **Cross-Protocol & Encapsulated Bypasses**:
   - IPv4-Mapped IPv6: `::ffff:127.0.0.1`, `::ffff:7f00:1`
   - IPv4-Compatible IPv6: `::127.0.0.1`, `::7f00:1`
   - NAT64 Well-Known Prefix: `64:ff9b::127.0.0.1`, `64:ff9b::7f00:1` (RFC 6052)
   - 6to4 Anycast Encapsulation: `2002:7f00:1::1` (RFC 3056)

#### ReconForge Mitigation
ReconForge implements multi-layer defense in depth:
1. **Fail-Closed IP Parsing**: Address strings are parsed and evaluated directly against binary CIDR subnets using Node.js's native `net.BlockList`. Any unparseable string, malformed address, or garbage input fails closed (`isPrivateOrReservedIp` returns `true` / blocked).
2. **Full IPv6 Encapsulation Decoding**: Decoders unwrap IPv4-mapped, IPv4-compatible, NAT64, and 6to4 encapsulation formats, extracting the embedded 32-bit IPv4 address and validating it against IPv4 private ranges.
3. **Connect-Time DNS Rebinding Defense**: To eliminate the check-then-use (TOCTOU) gap where a DNS server returns a public IP during pre-check and `127.0.0.1` during socket connection, `safeHttpRequest` passes a custom `lookup` function directly to `http.request` / `https.request`. Every resolved `A` and `AAAA` address is validated at socket establishment time. If any address falls within the blocklist, the connection is aborted immediately (`ERR_SSRF_BLOCKED`) before any TCP SYN packet is transmitted.
4. **Direct IP Literal Interception**: Because Node's HTTP client skips DNS `lookup` hooks when the URL hostname is an IP literal, `safeHttpRequest` validates IP literals before socket creation.

---

### 1.2 Differentiated TLS Verification Policy

- **Strict TLS for OSINT Intelligence APIs**: When querying external threat intelligence APIs (`crt.sh`, `AlienVault OTX`, `HackerTarget`), ReconForge enforces strict TLS verification (`rejectUnauthorized: true`). This prevents on-path man-in-the-middle attackers from injecting fraudulent subdomains into your assessment pipeline.
- **Lenient TLS for Target Probing**: When actively probing target services, ReconForge configures the probe client with `rejectUnauthorized: false`. Valid target applications with self-signed, staging, or expired certificates are accurately discovered and fingerprinted without prematurely dropping the asset.

---

### 1.3 Dual-Stack Wildcard DNS & Passive Record Preservation

#### The Problem
When a wildcard DNS record exists (`*.target.com IN A 192.0.2.1`), non-existent labels resolve to the wildcard IP. Naive dictionary guessing produces 100% false positives. However, dropping passive hits whose IP matches the wildcard IP is a critical mistake: passive records from Certificate Transparency (CT) or passive DNS telemetry represent authentic historical proof of host existence (often sharing a CDN or load balancer IP with the wildcard catch-all).

#### ReconForge Mitigation
1. **Dual-Stack Canary Probing**: ReconForge queries randomized canary labels (`_wildcard_v4_<rand>.<domain>` and `_wildcard_v6_<rand>.<domain>`) across both IPv4 and IPv6 resolvers to detect IPv4 and IPv6 wildcards.
2. **Selective Dictionary Bypass**: When wildcard DNS is active, high-frequency dictionary prefix guessing is bypassed to prevent false-positive floods.
3. **Passive Record Preservation**: All verified passive records (CT logs and OSINT feeds) are preserved and probed, with wildcard IPs annotated during inspection.

---

### 1.4 Subdomain Takeover Detection & NXDOMAIN Verification

ReconForge traverses DNS `CNAME` chains using `dns.resolveCname` and evaluates risk against known cloud provider signatures (AWS S3, GitHub Pages, Heroku, Zendesk, Shopify, Surge):
- **Likely Subdomain Takeover**:
  1. *Dangling CNAME to NXDOMAIN*: A subdomain's CNAME target resolves to `ENOTFOUND` / NXDOMAIN. The external resource does not exist in DNS and can be registered by an attacker.
  2. *CNAME Match + Provider Error Fingerprint*: A subdomain's CNAME ends with an authentic provider suffix (`.github.io`, `.s3.amazonaws.com`) AND the HTTP response matches the unclaimed service error fingerprint.
- **Potential / Unconfirmed**: If an HTTP body matches an error string but no CNAME points to the provider, it is labeled as "Potential" with low severity.
- **Strict Suffix Matching**: Evaluates CNAME targets using `endsWith()` rather than substring matching (`includes()`), preventing bypasses like `x.github.io.attacker.net`.
- **Ethical Boundary**: Real confirmation requires claiming the third-party asset on the cloud platform, which constitutes unauthorized modification and is strictly prohibited during scanning.

---

### 1.5 Inbound DNS Rebinding, Localhost Binding & Session Protection

- **Localhost Default Binding**: Network listeners default to `127.0.0.1` (`server.js` and `vite.config.js`), ensuring the daemon is inaccessible to other devices on the local area network (configurable via `HOST` env var).
- **Inbound Host Header Validation**: All `/api` routes validate the incoming `Host` header against an explicit list of authorized local and preview hosts. Requests with arbitrary hostnames (such as an attacker-controlled domain rebinding to `127.0.0.1`) are rejected with `403 Forbidden`, preventing inbound DNS rebinding against the local daemon.
- **Exact-Match CORS Policy**: CORS origins are restricted to exact-match authorized origins (`process.env.ALLOWED_ORIGINS`). `credentials: false` is enforced since no session cookies are used.
- **Per-Session Token Anti-CSRF Defense**: Mutating endpoints (`POST /api/recon/start`) require a cryptographically random session token (`x-reconforge-session`) validated with constant-time comparison (`crypto.timingSafeEqual`). Note that `SESSION_TOKEN` is specifically designed as an in-browser anti-CSRF / Cross-Origin Scanner Hijacking defense to prevent malicious websites visited by the user from triggering scans on the local daemon; it is not a multi-tenant user authentication system. When `HOST=0.0.0.0` or running in a container, `GET /api/session` is reachable on the configured listening interface.
- **Classified Internal IP Leak Reporting**: Subdomains in public DNS resolving to private IP space are categorized and reported by range (loopback as informational, RFC 1918 / IPv6 ULA as medium, IMDS as high, and CGNAT/multicast as low).

---

## 2. Known Limitations

Like all L7 and DNS-based security assessment tools, ReconForge operates within defined boundaries:

1. **Layer 7 HTTP Scope**: Active service probing operates exclusively on HTTP and HTTPS (ports 80 and 443). Non-HTTP network services (e.g. SSH, SMTP, RDP, databases, or raw TCP/UDP listeners) are not port-scanned.
2. **Upstream Resolver Trust**: DNS resolution relies on system-configured recursive resolvers (`/etc/resolv.conf`). Poisoned or tampering upstream recursive resolvers are outside the application's verification perimeter.
3. **Out-of-Band Cloud Takeovers**: Certain modern cloud platforms require out-of-band verification tokens (e.g. TXT verification records) to claim dangling resources. A dangling CNAME indicates high risk, but takeover feasibility depends on provider-specific claim policies.
4. **Third-Party OSINT Rate Limits**: Passive intelligence gathering depends on public external APIs (`crt.sh`, AlienVault OTX, HackerTarget) which may enforce temporary rate limits or latency spikes.

---

## 3. Architecture & Technical Rationale

For in-depth design discussions, technical rationale, and answers to core security engineering questions (including DNS rebinding TOCTOU analysis, why CORS does not stop LAN neighbors, and why passive records under wildcard zones represent authentic cryptographic evidence), please refer to:

👉 **[docs/DESIGN_NOTES.md](docs/DESIGN_NOTES.md)**

---

## 4. Responsible Disclosure Policy

If you discover a security vulnerability within ReconForge:
1. Please report it privately by opening a security advisory or contacting the maintainer directly.
2. Provide a reproduction script or proof of concept.
3. We will respond within 48 hours and work with you on a coordinated fix.

---

## 5. Permitted & Authorized Use

ReconForge performs active network requests (DNS queries and HTTP/HTTPS GET requests). **You must only scan domain names you own or have explicit written permission to assess under an authorized bug bounty program or penetration testing engagement.**
