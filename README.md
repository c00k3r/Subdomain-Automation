# ReconForge -- Passive Subdomain Recon Automation App (v2.0)

A modular passive reconnaissance application for bug bounty hunters, penetration testers, and cybersecurity researchers. 

ReconForge automates passive subdomain enumeration, deduplication, live host detection, and reporting through a local interactive **React (JSX) GUI** and a **Node.js automation engine**, backed by the original modular Bash scripts.

---

## What's New in v2.0 (GUI & JSX Architecture)

- **Pure React (JSX) Frontend**: Built using modern JavaScript JSX with Tailwind CSS (no TypeScript compilation complexity).
- **Interactive Terminal Streaming**: Live ANSI color-coded terminal emulator displaying each stage with real-time Server-Sent Events (SSE).
- **Automated 6-Step Recon Engine**:
  1. `[1/6]` Check Dependencies & Network Engine
  2. `[2/6]` Subfinder Module (Certificate Transparency via crt.sh API)
  3. `[3/6]` Assetfinder Module (AlienVault OTX passive DNS & resolver)
  4. `[4/6]` Merge & Deduplicate (equivalent to Unix `sort -u`)
  5. `[5/6]` Live Hosts Module (concurrent HTTP/HTTPS probe, status code, latency, server banner, page title)
  6. `[6/6]` Summary, Markdown Report & Audit Log generation
- **Discovered Subdomains Table**: Instant substring search, prefix tags, one-click copy, and `subdomains.txt` download.
- **Live Hosts Table**: Status code categorization (2xx Success, 3xx Redirect, 4xx Client, 5xx Server, DNS only) and direct link openers.
- **In-App Report Viewer**: Inspect and export `report.md`, `summary.txt`, `recon.log`, `subdomains.txt`, and `alive.txt`.
- **Recon History**: Keeps track of previous target scans and includes quick presets (`hackerone.com`, `owasp.org`, etc.).

---

## Project Structure

```text
subdomain-recon/
├── server.js               # Node.js backend & passive recon execution engine
├── index.html              # HTML entry point (loads /src/main.jsx)
├── start-app.bat           # 1-Click launcher for Windows (opens as standalone window)
├── start-app.sh            # 1-Click launcher for Linux / macOS
├── package.json            # Node.js dependencies & scripts
├── vite.config.js          # Vite config
├── src/
│   ├── main.jsx            # React root entry (JSX)
│   ├── App.jsx             # Main dashboard component (JSX)
│   ├── index.css           # Terminal styles & Tailwind CSS
│   └── components/
│       ├── Navbar.jsx          # Header with target presets
│       ├── TerminalLog.jsx     # ANSI color parser & real-time log window
│       ├── ScanWorkflow.jsx    # Visual 6-step progress pipeline
│       ├── SubdomainsTable.jsx # Subdomains filter & export
│       ├── LiveHostsTable.jsx  # Live HTTP probe status & latency
│       ├── ReportsViewer.jsx   # Tabbed report inspector (.md, .txt, .log)
│       └── HistorySidebar.jsx  # Recent scan sessions
├── config.sh               # Original CLI colors and banner
├── functions.sh            # Original CLI modular functions
├── recon.sh                # Original CLI pipeline orchestrator
├── output/                 # Output directory for subdomains, alive, and summary
├── reports/                # Output directory for markdown reports
└── logs/                   # Output directory for recon.log
```

---

## How to Run on Your PC as an App (Not a Website)

You can run ReconForge locally on your computer completely offline/privately as a desktop window without publishing it to the web.

### Prerequisites

You only need **Node.js** (v18 or higher) installed on your system:
- **Windows / Mac**: Download from [nodejs.org](https://nodejs.org/) (LTS recommended).
- **Linux (Debian/Ubuntu/Kali)**:
  ```bash
  sudo apt update && sudo apt install nodejs npm
  ```

---

### Method 1: 1-Click Launcher (Fastest)

#### On Windows:
1. Double-click **`start-app.bat`**.
2. It will install dependencies if needed, boot the local server, and launch ReconForge in a dedicated, distraction-free desktop window (using Edge or Chrome app mode, with no browser URL bar or tabs).

#### On Linux / macOS / Kali:
1. Make the script executable:
   ```bash
   chmod +x start-app.sh
   ```
2. Run it:
   ```bash
   ./start-app.sh
   ```
3. A native window will open running ReconForge locally.

---

### Method 2: Manual Terminal Run

1. Open your terminal in the project folder:
   ```bash
   cd Subdomain-Automation
   ```

2. Install dependencies (only needed once):
   ```bash
   npm install
   ```

3. Start the application:
   ```bash
   npm run dev
   ```

4. Launch it as an app window:
   - **Windows**:
     ```cmd
     start msedge --app=http://localhost:3000
     ```
     or
     ```cmd
     start chrome --app=http://localhost:3000
     ```
   - **Linux / Kali**:
     ```bash
     google-chrome --app=http://localhost:3000
     ```
   - **macOS**:
     ```bash
     /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --app=http://localhost:3000
     ```

*(Tip: In Google Chrome or Microsoft Edge, you can also navigate to `http://localhost:3000`, click the three-dot menu `⋮` → **Save and share** → **Install ReconForge as app** or **Create shortcut → Open as window** to pin it to your Taskbar or Desktop like a native app).*

---

### Method 3: Running Pure CLI (Original Bash Scripts)

If you prefer running solely in the command line on Linux or WSL:

```bash
chmod +x recon.sh
./recon.sh -d target.com
```

Outputs will be saved in:
- `output/target.com/subdomains.txt`
- `output/target.com/alive.txt`
- `output/target.com/summary.txt`
- `reports/target.com/report.md`
- `logs/recon.log`

---

## Disclaimer

This tool is intended strictly for passive reconnaissance against domains you own or are explicitly authorized to test (e.g., in-scope bug bounty programs).

---

## Author

**Mrityunjay**  
Cybersecurity Student | VAPT Enthusiast
