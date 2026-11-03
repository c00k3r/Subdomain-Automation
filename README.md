# ReconForge -- Subdomain Reconnaissance & Active Service Probing (v2.1)

[![CI Test & Build](https://github.com/reconforge/reconforge/actions/workflows/ci.yml/badge.svg)](https://github.com/reconforge/reconforge/actions/workflows/ci.yml)
[![Node.js](https://img.shields.io/badge/node-%3E%3D22.0.0-brightgreen.svg)](https://nodejs.org/)
[![Dependabot](https://img.shields.io/badge/dependabot-enabled-blue.svg)](.github/dependabot.yml)

An automated attack surface mapping and service probing suite for security researchers, bug bounty hunters, and penetration testers.

ReconForge features a **dual-engine architecture**:
1. **Native Node.js Engine & Desktop GUI**: A standalone, zero-Go-dependency engine featuring an interactive React (JSX) dashboard, HTML5 Canvas topology graph, real-time ANSI terminal streaming via Server-Sent Events (SSE), fail-closed SSRF defenses (`net.BlockList` + connect-time lookup), inbound DNS rebinding protection (Host header validation), and takeover risk detection with CNAME NXDOMAIN verification.
2. **Classic Bash CLI Pipeline**: The standalone script suite (`recon.sh`, `functions.sh`, `config.sh`) for headless terminal environments orchestrating standard Linux tools (`subfinder`, `assetfinder`, `httpx`).

---

## Technical Pipeline: Passive Enumeration & Active Probing

ReconForge separates non-intrusive public intelligence gathering from active host verification:

| Stage | Operation | Classification | Description |
| :--- | :--- | :--- | :--- |
| **01** | Scope & Resolver Check | Active Pre-flight | Validates domain format (RFC 1035 + Punycode IDN) and verifies system network resolver responsiveness. |
| **02** | Certificate Transparency | Passive | Mines public TLS certificate issuance logs via `crt.sh` JSON API (enforcing strict TLS verification and 15MB buffer) without sending any network traffic to the target domain. |
| **03** | Passive Feeds & Threat Intel | Passive | Collects recorded hostnames from AlienVault OTX Passive DNS and HackerTarget search index. Probes random canary labels (`_wildcard_v4_<hex>.<target>` and `_wildcard_v6_<hex>.<target>`) across IPv4 and IPv6 to detect wildcard DNS zones. |
| **04** | Normalization & Wildcard Filter | Local Processing | Strips wildcards, normalizes casing, validates FQDN syntax, dedupes all discovered targets, bypasses speculative dictionary guessing under wildcard zones, and preserves all verified cryptographic passive records. |
| **05** | HTTP/TLS Service Probing | Active Probing | Performs dual-stack IPv4/IPv6 resolution, measures genuine DNS latency, applies **fail-closed SSRF filters with connect-time DNS rebinding defense** (blocking cloud IMDS `169.254.169.254`, loopbacks, CGNAT, multicast, IPv6 ULA/link-local, IPv4-mapped, NAT64, 6to4, and direct IP literals), reports internal RFC 1918 DNS leaks, tests HTTPS/HTTP responsiveness, detects web server software, extracts page titles, and analyzes dangling CNAME records for subdomain takeover risks via NXDOMAIN target verification. |
| **06** | Report Compilation | Artifacts | Exports structured Markdown reports (`report.md`), summary statistics (`summary.txt`), raw target lists (`subdomains.txt`, `alive.txt`), and audit logs (`recon.log`). |

---

## Security & Threat Model

Unlike basic scanners that blindly curl resolved addresses, ReconForge actively protects the host environment:
- **SSRF & Cloud Metadata Mitigation**: Implements Node's native `net.BlockList` to block `169.254.169.254` (AWS/GCP/Azure IMDS), loopbacks (`127.0.0.0/8`, `::1`, `0:0:0:0:0:0:0:1`, `::`), RFC 1918 subnets, `100.64.0.0/10`, `192.0.0.0/24`, `198.18.0.0/15`, `224.0.0.0/4`, `fc00::/7`, `fe80::/10`, IPv4-mapped IPv6 (`::ffff:`), NAT64 (`64:ff9b::/96`), 6to4 (`2002::/16`), and IPv4-compatible (`::/96`) addresses with fail-closed validation.
- **DNS Rebinding (TOCTOU) Defense**: Connect-time DNS validation via custom `lookup` in `http.request` ensures that both `A` and `AAAA` records are validated at socket creation time before TCP handshakes occur. Direct IP literals are also intercepted before socket creation.
- **Inbound DNS Rebinding & Daemon Security**: Binds to `127.0.0.1` by default, validates incoming `Host` headers on `/api` routes, enforces exact-match CORS origins (`credentials: false`), and mandates cryptographically random per-session tokens (`x-reconforge-session`) on scan creation.
- **Differentiated TLS Verification**: Strict TLS (`rejectUnauthorized: true`) for external OSINT threat intelligence APIs to prevent on-path injection, paired with lenient TLS (`rejectUnauthorized: false`) exclusively for target host discovery to inspect self-signed or expired certificates.
- **Wildcard DNS Handling**: Bypasses dictionary guessing under wildcard zones while preserving all verified passive records from Certificate Transparency and passive DNS.
- **Subdomain Takeover Verification**: Queries DNS `CNAME` records via `dns.resolveCname`, checks for NXDOMAIN on CNAME targets, strictly evaluates suffixes via `endsWith()`, and classifies findings into calibrated "Likely" and "Potential" certainty tiers.

For in-depth threat modeling and limitations, see [SECURITY.md](SECURITY.md). For deep technical rationale, see [docs/DESIGN_NOTES.md](docs/DESIGN_NOTES.md). For engineering architecture and technical postmortem, see [docs/BENCHMARK_AND_WRITEUP.md](docs/BENCHMARK_AND_WRITEUP.md).

---

## Project Structure

```text
ReconForge/
├── server.js               # Native Node.js engine, SSRF firewall, API routes & SSE streaming
├── docs/
│   ├── DESIGN_NOTES.md     # Security design notes & architecture rationale
│   └── BENCHMARK_AND_WRITEUP.md # Engineering architecture & postmortem writeup
├── test/
│   └── sanity.test.js      # Unit tests for domain sanitizer, Punycode, SSRF filter, wildcard DNS, CNAME
├── src/
│   ├── main.jsx            # React 19 root entry (pure JSX, no TypeScript)
│   ├── App.jsx             # Dual-channel state manager (SSE + interval fallback)
│   ├── index.css           # Tailwind CSS v4 design system
│   └── components/
│       ├── Navbar.jsx          # Quick target presets & desktop controls
│       ├── ScannerHero.jsx     # Clean target domain input & authorization notice
│       ├── ScanProgress.jsx    # Real-time multi-stage progress & auto-redirect
│       ├── ScanWorkflow.jsx    # Visual 6-step pipeline status tracker
│       ├── ResultsView.jsx     # Tabbed attack surface analysis workspace
│       ├── TopologyGraph.jsx   # Interactive HTML5 Canvas constellation map
│       ├── RiskScanner.jsx     # Subdomain takeover signatures & High-Value Targets (HVT)
│       ├── LiveHostsTable.jsx  # HTTP/HTTPS status, latency, IP, tech stack & search
│       ├── SubdomainsTable.jsx # Clean FQDN search, prefix badges, clipboard export
│       ├── ReportsViewer.jsx   # Live tabbed Markdown, summary, and log inspector
│       └── TerminalLog.jsx     # Real-time ANSI color-coded execution console
├── start-app.bat           # 1-Click launcher for Windows (opens in app mode)
├── start-app.sh            # 1-Click launcher for Linux / macOS / Kali
├── package.json            # Scripts & minimal dependencies (Express, React, Lucide)
├── vite.config.js          # Vite build configuration
├── config.sh               # Original CLI colors and terminal banner
├── functions.sh            # Original CLI modular bash functions
├── recon.sh                # Original CLI pipeline orchestrator
├── SECURITY.md             # Threat model, SSRF mitigations & disclosure policy
└── CHANGELOG.md            # Version release notes
```

---

## How to Run on Your PC as an App

ReconForge runs locally on your PC without publishing anything to the web.

### Prerequisites

- **Node.js** (v22 or higher): [nodejs.org](https://nodejs.org/)

---

### Option 1: 1-Click Launcher (Recommended)

#### On Windows:
Double-click **`start-app.bat`**. It installs dependencies if needed and launches ReconForge in a dedicated, distraction-free desktop window (using Edge or Chrome app mode with no browser tabs or address bar).

#### On Linux / macOS / Kali:
```bash
chmod +x start-app.sh
./start-app.sh
```

---

### Option 2: Manual Terminal Run

```bash
# 1. Install dependencies
npm install

# 2. Run unit tests
npm test

# 3. Start local server
npm run dev
```

Navigate to `http://localhost:3000` in your browser.

To launch as a desktop window:
- **Windows**: `start msedge --app=http://localhost:3000` or `start chrome --app=http://localhost:3000`
- **Linux**: `google-chrome --app=http://localhost:3000`
- **macOS**: `/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --app=http://localhost:3000`

---

### Option 3: Original Bash CLI Mode

For headless terminal recon on Linux/WSL with external Go binaries installed:
```bash
chmod +x recon.sh
./recon.sh -d target.com
```

Outputs will be saved in `output/target.com/` and `reports/target.com/report.md`.

---

## Running Unit Tests

ReconForge includes a unit test suite using Node's native test runner (`node:test` and `node:assert`):

```bash
npm test
```

This verifies:
1. `sanitizeDomain` input normalization (stripping protocols, paths, trailing ports, and query strings).
2. `isValidDomain` RFC 1035 and Internationalized Domain Name (IDN / Punycode `xn--...`) validation.
3. `isPrivateOrReservedIp` SSRF mitigation blocking Cloud IMDS (`169.254.169.254`), loopbacks (`127.0.0.1`, `::1`, `0:0:0:0:0:0:0:1`, `::`), IPv6 ULA/link-local (`fc00::/7`, `fe80::/10`), multicast/benchmarks (`224.0.0.1`, `198.18.0.1`, `192.0.0.1`), and IPv4-mapped IPv6 (`::ffff:127.0.0.1`) while allowing valid public IPs.
4. `detectWildcardDNS` offline deterministic wildcard evaluation.
5. `checkTakeoverRisk` CNAME target verification before claiming takeover.

---

## Disclaimer & Authorized Use

This tool is designed for security assessments against targets you own or are explicitly authorized to test under written permission or public bug bounty program rules. Always adhere to responsible testing practices.
