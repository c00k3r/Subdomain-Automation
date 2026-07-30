# ReconForge -- Passive Subdomain Recon Automation Tool

A modular Bash-based passive reconnaissance tool for bug bounty hunters, penetration testers, and cybersecurity enthusiasts.

The tool automates passive subdomain enumeration, live host detection, reporting, and logging using ProjectDiscovery tools.

---

## Features

- Passive subdomain enumeration using **Subfinder**
- Additional enumeration using **Assetfinder**
- Automatic duplicate removal
- Live host detection using **Httpx**
- Markdown report generation
- Scan summary generation
- Scan logging
- Organized output directory structure
- Modular Bash architecture

---

## Technologies Used

- Bash
- Subfinder
- Assetfinder
- Httpx
- Linux / WSL

---

## Project Structure

```text
subdomain-recon/

├── config.sh
├── functions.sh
├── recon.sh
├── README.md
├── LICENSE
├── logs/
├── reports/
└── output/
```

---

## Requirements

Install the required tools:

### Subfinder

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### Httpx

```bash
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### Assetfinder

```bash
go install github.com/tomnomnom/assetfinder@latest
```

---

## Usage

Run:

```bash
./recon.sh -d hackerone.com
```

---

## Output

After a successful scan:

```text
output/
└── hackerone.com/
    ├── subdomains.txt
    ├── alive.txt
    └── summary.txt
```

Reports:

```text
reports/
└── hackerone.com/
    └── report.md
```

Logs:

```text
logs/
└── recon.log
```

---

## Example Workflow

```
Target Domain
      │
      ▼
 Subfinder
      │
      ▼
 Assetfinder
      │
      ▼
 Merge Results
      │
      ▼
 Remove Duplicates
      │
      ▼
 Httpx
      │
      ▼
 Reports + Logs
```

---

## Current Features

- [x] Passive Enumeration
- [x] Multi-tool Enumeration
- [x] Live Host Detection
- [x] Markdown Reports
- [x] Summary Reports
- [x] Scan Logging
- [x] Modular Architecture

---

## Roadmap

- [ ] Amass Integration
- [ ] DNS Resolution
- [ ] Port Scanning
- [ ] Technology Detection
- [ ] Screenshot Capture
- [ ] Wayback URL Collection
- [ ] JSON Export
- [ ] Parallel Execution
- [ ] Docker Support

---

## License

MIT License

---

## Author

**Mrityunjay**

Cybersecurity Student | VAPT Enthusiast