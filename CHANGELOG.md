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
- **Scan Concurrency Throttle**: Added `MAX_CONCURRENT_RUNNING = 3` limit on `POST /api/recon/start` returning `429 Too Many Requests` when saturated, strictly protecting active scans from resource starvation or LRU cache eviction.
- **Dual-Stack Wildcard Detection**: Upgraded canary probing in `detectWildcardDNS` to generate separate IPv4 and IPv6 canary labels, catching IPv6-only wildcard zones.
- **Passive Record Preservation**: Refactored Stage 4 pipeline to preserve all cryptographic Certificate Transparency and passive DNS hits under wildcard zones, skipping only speculative dictionary guesses.
- **Regional & Dual-Stack S3 Takeover Coverage**: Extended S3 takeover detection with regional and dual-stack regex (`/^(?:[a-z0-9.-]+\.)?s3(?:\.dualstack)?(?:(?:\.[a-z0-9-]+)+|-website[.-][a-z0-9-]+|-(?:[a-z]{2,}-[a-z]+-\d+))?\.amazonaws\.com$/i`) while strictly filtering out ELB domains.
- **Per-Resource Subdomain Takeover Detection**: Added `perResourceDns: true/false` flags to ensure target NXDOMAIN (`ENOTFOUND`) resolution is only evaluated for providers that de-register DNS records upon resource release (AWS Elastic Beanstalk, Azure Web App, Azure Traffic Manager), while shared anycast providers rely on response fingerprinting.
- **BlockList IP Classification**: Differentiates internal/reserved IPs by range using dedicated `net.BlockList` instances with embedded IPv4 unwrapping (`unwrapEmbeddedIPv4`), ensuring `::ffff:127.0.0.2` and other encodings accurately map to their appropriate severity tiers (loopback as INFO, RFC 1918 & IPv6 ULA as MEDIUM, cloud IMDS / link-local as HIGH, CGNAT & multicast as LOW).
- **Split Host Telemetry**: Separated live target reporting into HTTP-responding (`httpLive`), DNS-resolving only (`dnsOnly`), and blocked internal (`blockedInternal`), eliminating deceptive 100% live statistics on large multi-service domains.
- **Permission-Gated Stage 5 Probing**: Added explicit user permission checkbox in UI (`allowActiveProbing`) required before sending live HTTP requests to target infrastructure. Relabeled presets to "Example public targets" and clarified passive (zero target packets) vs active probing boundaries.
- **Dependency Injected Workflow Runner**: Refactored server into `createApp({ runWorkflow })` eliminating test-only `NODE_ENV === 'test'` branching in route handlers and enabling automated end-to-end tests with mocked workflow execution.
- **Engineering Postmortem Documentation**: Refactored benchmark section into `docs/ENGINEERING_POSTMORTEM.md` outlining an objective future test zone validation protocol without ungrounded metric claims.

---

## [2.0.0] - 2026-07-30

### Added
- **Classic Bash CLI Reconnaissance Pipeline**: Standalone script suite (`recon.sh`, `functions.sh`, `config.sh`) for headless Linux terminal environments.
- **Multi-Tool Orchestration**: Automated workflow chaining Subfinder, Assetfinder, and Httpx.
- **Terminal Visuals**: Rich ANSI color-coded banners, step indicators, and live execution logging.
- **Artifact Generation**: Disk export of `subdomains.txt`, `alive.txt`, `summary.txt`, and formatted markdown reports.
