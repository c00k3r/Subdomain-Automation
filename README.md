# ReconForge -- Subdomain Reconnaissance & Active Service Probing (v2.0)

A high-performance reconnaissance and attack surface mapping suite for security researchers, bug bounty hunters, and penetration testers.

ReconForge features a **dual-engine architecture**:
1. **Native Node.js Engine & Desktop GUI**: A standalone, zero-Go-dependency engine featuring an interactive React (JSX) dashboard, 60fps HTML5 Canvas topology graph, real-time ANSI terminal streaming via Server-Sent Events (SSE), built-in SSRF defenses, and takeover risk detection.
2. **Classic Bash CLI Pipeline**: The original standalone script suite (`recon.sh`, `functions.sh`, `config.sh`) for headless terminal environments orchestrating standard Linux tools (`subfinder`, `assetfinder`, `httpx`).

---

## Technical Pipeline: Passive Enumeration & Active Probing

ReconForge separates non-intrusive public intelligence gathering from active host verification:

| Stage | Operation | Classification | Description |
| :--- | :--- | :--- | :--- |
| **01** | Scope & Wildcard Check | Active Pre-flight | Validates domain format (RFC 1035 + Punycode IDN), tests resolver connectivity, and resolves random canary labels (`_wildcard_check_<hex>.<target>`) to detect wildcard DNS zones. |
| **02** | Certificate Transparency | Passive | Mines public TLS certificate issuance logs via `crt.sh` JSON API without sending any network traffic to the target domain. |
| **03** | Passive Feeds & Threat Intel | Passive | Collects recorded hostnames from AlienVault OTX Passive DNS and HackerTarget search index. Bypasses dictionary guessing if wildcard DNS was detected. |
| **04** | Normalization & Deduplication | Local Processing | Strips wildcards, normalizes casing, validates FQDN syntax, and dedupes all discovered targets. |
| **05** | HTTP/TLS Service Probing | Active Probing | Performs dual-stack IPv4/IPv6 resolution, measures genuine DNS latency, applies strict **SSRF filters** (blocking cloud IMDS `169.254.169.254` and private subnets), tests HTTPS/HTTP responsiveness, detects web server software, extracts page titles, and analyzes dangling CNAME takeover patterns. |
| **06** | Report Compilation | Artifacts | Exports structured Markdown reports (`report.md`), summary statistics (`summary.txt`), raw target lists (`subdomains.txt`, `alive.txt`), and audit logs (`recon.log`). |

---

## Security & Threat Model

Unlike basic scanners that blindly curl resolved addresses, ReconForge actively protects the host environment:
- **SSRF & Cloud Metadata Mitigation**: Automatically intercepts queries resolving to `169.254.169.254` (AWS/GCP/Azure IMDS), loopback (`127.0.0.0/8`), and RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), dropping outbound sockets before TCP handshakes occur.
- **Wildcard DNS Flood Prevention**: Prevents false-positive dictionary floods by verifying NXDOMAIN behavior first.
- **Untrusted TLS Resilience**: Uses an HTTPS agent with `rejectUnauthorized: false` during stage 5 so internal hosts with self-signed or expired certs are not dropped prematurely.

For in-depth analysis and the security policy, see [SECURITY.md](SECURITY.md).

---

## Project Structure

```text
ReconForge/
├── server.js               # Native Node.js engine, SSRF firewall, API routes & SSE streaming
├── test/
│   └── sanity.test.js      # Unit tests for domain sanitizer, Punycode, SSRF filter, wildcard DNS
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
│       ├── TopologyGraph.jsx   # Interactive 60fps HTML5 Canvas constellation map
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

- **Node.js** (v18 or higher): [nodejs.org](https://nodejs.org/)

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
3. `isPrivateOrReservedIp` SSRF mitigation blocking Cloud IMDS (`169.254.169.254`), loopbacks (`127.0.0.1`), and RFC 1918 subnets while allowing valid public IPs.
4. `detectWildcardDNS` DNS probe handling.

---

## Disclaimer & Authorized Use

This tool is designed for security assessments against targets you own or are explicitly authorized to test under written permission or public bug bounty program rules. Always adhere to responsible testing practices.
