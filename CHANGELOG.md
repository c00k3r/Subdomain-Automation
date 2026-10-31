# Changelog

All notable changes to ReconForge are documented in this file adhering to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and [Semantic Versioning](https://semver.org/).

---

## [2.1.0] - 2026-10-31

### Added
- **Native Node.js Scanning Engine**: Standalone zero-Go engine eliminating external binary prerequisites while maintaining direct HTTP/DNS query speed.
- **Interactive Web Interface**: Single-page application built with React, Tailwind CSS, and HTML5 Canvas topology visualization.
- **Real-Time SSE Streaming**: Optimized event stream delivering step-by-step terminal logs as delta events and real-time asset discovery metrics.
- **True LRU Scan Storage**: In-memory scan cache with bounded LRU eviction (max 30 scans) that refreshes recency on access and never evicts running scans.
- **Exportable VAPT Artifacts**: Automated disk export of `subdomains.txt`, `alive.txt`, `summary.txt`, and formatted markdown `report.md`.

### Security Hardening & Threat Model Alignment
- **Fail-Closed SSRF Defense**: Updated IP evaluation engine to fail closed on malformed, unparseable, or garbage inputs (`isPrivateOrReservedIp`).
- **Connect-Time SSRF Defense**: Intercepts DNS resolutions at TCP socket connect time (`lookup` hook in `http.request`) to eliminate TOCTOU rebinding attacks against cloud metadata (`169.254.169.254`) and internal subnets.
- **IPv6 Decoders**: Added binary word decoders for IPv4-mapped IPv6 (`::ffff:/96`), IPv4-compatible IPv6 (`::/96`), NAT64 Well-Known Prefix (`64:ff9b::/96`, RFC 6052), and 6to4 Anycast encapsulation (`2002::/16`, RFC 3056) to eliminate cross-protocol SSRF bypasses.
- **Inbound DNS Rebinding Defense**: Implemented strict `Host` header validation middleware (`isValidHostHeader`) across all `/api` endpoints, blocking malicious web clients from rebinding local daemon ports.
- **Localhost Default Binding**: Defaulted network listeners in `server.js` and `vite.config.js` to `127.0.0.1` (configurable via `HOST` env var).
- **Exact-Match CORS Policy**: Replaced regex origin matching with strict exact-origin matching (`ALLOWED_ORIGINS`), removed wildcard subdomains, and dropped `credentials: true`.
- **Timing-Safe Session Token Authentication**: Generated cryptographically random per-session tokens (`x-reconforge-session`) validated with `crypto.timingSafeEqual` to prevent Cross-Origin Scanner Hijacking.
- **Direct IP-Literal Protection**: Added socket-level guards in `safeHttpRequest` for direct IP literals where Node's client skips DNS `lookup`.
- **Live SSRF Test Suite**: Integrated real loopback probe tests verifying that local mock servers receive 0 incoming requests when probed.

### Recon Engine Corrections & Heuristics
- **Dual-Stack Wildcard Detection**: Upgraded canary probing in `detectWildcardDNS` to generate separate IPv4 and IPv6 canary labels, catching IPv6-only wildcard zones.
- **Passive Record Preservation**: Refactored Stage 4 pipeline to preserve all cryptographic Certificate Transparency and passive DNS hits under wildcard zones, skipping only speculative dictionary guesses.
- **Per-Resource Subdomain Takeover Detection**: Traverses CNAME chains, tests targets against exact provider suffixes, and verifies true NXDOMAIN (`ENOTFOUND`) on per-resource cloud services (AWS Elastic Beanstalk, Azure Web App, Azure Traffic Manager, Fastly, Ghost, GitHub Pages, Amazon S3).
- **Classified Internal IP Reporting**: Differentiates internal/reserved IPs by range with accurate severity tiers (loopback as INFO 'Localhost / Loopback Mapping', RFC 1918 & IPv6 ULA as MEDIUM, cloud IMDS / link-local as HIGH, CGNAT & multicast as LOW).

---

## [2.0.0] - 2026-07-30

### Added
- **Classic Bash CLI Reconnaissance Pipeline**: Standalone script suite (`recon.sh`, `functions.sh`, `config.sh`) for headless Linux terminal environments.
- **Multi-Tool Orchestration**: Automated workflow chaining Subfinder, Assetfinder, and Httpx.
- **Terminal Visuals**: Rich ANSI color-coded banners, step indicators, and live execution logging.
- **Artifact Generation**: Disk export of `subdomains.txt`, `alive.txt`, `summary.txt`, and formatted markdown reports.
