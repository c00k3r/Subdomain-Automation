# Changelog

All notable changes to ReconForge are documented in this file adhering to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and [Semantic Versioning](https://semver.org/).

---

## [2.1.0] - 2026-10-31

### Security Hardening & Threat Model Alignment

- **Fail-Closed SSRF Defense**: Updated IP evaluation engine to fail closed on malformed, unparseable, or garbage inputs (`isPrivateOrReservedIp`).
- **IPv6 Decoders**: Added binary word decoders for IPv4-mapped IPv6 (`::ffff:/96`), IPv4-compatible IPv6 (`::/96`), NAT64 Well-Known Prefix (`64:ff9b::/96`, RFC 6052), and 6to4 Anycast encapsulation (`2002::/16`, RFC 3056) to eliminate cross-protocol SSRF bypasses.
- **Inbound DNS Rebinding Defense**: Implemented strict `Host` header validation middleware (`isValidHostHeader`) across all `/api` endpoints, blocking malicious web clients from rebinding local daemon ports.
- **Localhost Default Binding**: Defaulted network listeners in `server.js` and `vite.config.js` to `127.0.0.1` (configurable via `HOST` env var).
- **Exact-Match CORS Policy**: Replaced regex origin matching with strict exact-origin matching (`ALLOWED_ORIGINS`), removed wildcard subdomains, and dropped `credentials: true`.
- **Session Token Authentication**: Generated cryptographically random per-session tokens (`x-reconforge-session`) required on scan triggers to prevent Cross-Origin Scanner Hijacking.
- **Direct IP-Literal Protection**: Added socket-level guards in `safeHttpRequest` for direct IP literals where Node's client skips DNS `lookup`.
- **Live SSRF Test Suite**: Integrated real loopback probe tests verifying that local mock servers receive 0 incoming requests when probed.

### Recon Engine Corrections & Heuristics

- **Dual-Stack Wildcard Detection**: Upgraded canary probing in `detectWildcardDNS` to generate separate IPv4 and IPv6 canary labels, catching IPv6-only wildcard zones.
- **Passive Record Preservation**: Refactored Stage 4 pipeline to preserve all cryptographic Certificate Transparency and passive DNS hits under wildcard zones, skipping only speculative dictionary guesses.
- **Subdomain Takeover NXDOMAIN Verification**: Replaced naive body matching with multi-CNAME chain traversal and NXDOMAIN target resolution (`targetResolverFn`). Phrased findings into calibrated certainty tiers ("Likely Subdomain Takeover" vs "Potential Signature Match").
- **Strict Suffix Matching**: Replaced `includes()` with `endsWith()` on CNAME suffixes to prevent sub-string false positives.
- **Internal IP Leak Reporting**: Tagged public DNS records resolving to private RFC 1918 addresses as dedicated security findings with remediation guidance and dig proof-of-concept commands.

---

## [2.0.0] - 2026-10-25

### Added

- **Native Node.js Scanning Engine**: Zero-Go runtime eliminating external binary prerequisites while maintaining direct HTTP/DNS query speed.
- **Interactive Web Interface**: Single-page application built with React, Tailwind CSS, and HTML5 Canvas topology visualization.
- **Real-Time SSE Streaming**: Live event streaming displaying step-by-step console logs, discovered subdomains, and probe metrics in real time.
- **Connect-Time SSRF Defense**: Intercepts DNS resolutions at TCP socket connect time (`lookup` hook in `http.request`) to eliminate TOCTOU rebinding attacks against cloud metadata (`169.254.169.254`) and internal subnets.
- **Multi-Source OSINT Pipeline**: Integrates `crt.sh` Certificate Transparency, AlienVault OTX, and HackerTarget passive feeds with automated deduplication.
- **Exportable VAPT Artifacts**: Automated disk generation of `subdomains.txt`, `alive.txt`, `summary.txt`, and formatted markdown `report.md`.
- **Historical Scan Storage**: In-memory scan manager with bounded LRU eviction (max 30 scans) to prevent memory leaks during long-running engagements.
