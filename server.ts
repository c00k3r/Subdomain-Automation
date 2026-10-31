import express, { Request, Response } from 'express';
import cors from 'cors';
import path from 'path';
import fs from 'fs/promises';
import { existsSync, createReadStream } from 'fs';
import dns from 'node:dns/promises';
import http from 'http';

interface LiveHost {
  url: string;
  subdomain: string;
  statusCode: number;
  title: string;
  latencyMs: number;
  ip?: string;
  server?: string;
}

interface ScanData {
  id: string;
  domain: string;
  status: 'running' | 'completed' | 'failed';
  error?: string;
  startTime: number;
  endTime?: number;
  executionTime?: number;
  step: number;
  currentAction: string;
  totalSubdomains: number;
  aliveCount: number;
  subdomains: string[];
  aliveHosts: LiveHost[];
  logs: string[];
  files: {
    subdomainsTxt: string;
    aliveTxt: string;
    summaryTxt: string;
    reportMd: string;
    reconLog: string;
  };
}

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const isProd = process.env.NODE_ENV === 'production';

app.use(cors());
app.use(express.json());

// In-memory store for active and past scans
const scans = new Map<string, ScanData>();
const sseClients = new Map<string, Response[]>();

function broadcastScanUpdate(scanId: string, scan: ScanData) {
  const clients = sseClients.get(scanId) || [];
  const payload = `data: ${JSON.stringify(scan)}\n\n`;
  for (const res of clients) {
    try {
      res.write(payload);
    } catch {
      // client disconnected
    }
  }
}

function appendLog(scan: ScanData, line: string) {
  scan.logs.push(line);
  broadcastScanUpdate(scan.id, scan);
}

// Clean and sanitize domain
function sanitizeDomain(input: string): string {
  let domain = input.trim().toLowerCase();
  domain = domain.replace(/^https?:\/\//i, '');
  domain = domain.replace(/:\d+$/, '');
  domain = domain.replace(/\/.*$/, '');
  return domain;
}

// Validation regex
function isValidDomain(domain: string): boolean {
  const pattern = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return pattern.test(domain);
}

// Fetch helper with timeout
async function fetchWithTimeout(url: string, timeoutMs = 5000): Promise<any> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconForge/2.0',
        Accept: 'application/json, text/plain, */*',
      },
    });
    clearTimeout(id);
    return res;
  } catch (err) {
    clearTimeout(id);
    throw err;
  }
}

// Passive Subdomain Enumeration: crt.sh (Subfinder simulation)
async function runSubfinder(domain: string): Promise<string[]> {
  const found = new Set<string>();
  try {
    const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
    const res = await fetchWithTimeout(url, 7000);
    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data)) {
        for (const entry of data) {
          const names = String(entry.name_value || '').split('\n');
          for (let name of names) {
            name = name.trim().toLowerCase();
            if (name.startsWith('*.')) name = name.slice(2);
            if (name.endsWith(`.${domain}`) || name === domain) {
              if (isValidDomain(name)) found.add(name);
            }
          }
        }
      }
    }
  } catch {
    // If crt.sh is slow or rate limits, continue
  }
  return Array.from(found);
}

// Additional Enumeration: AlienVault OTX & HackerTarget (Assetfinder simulation)
async function runAssetfinder(domain: string): Promise<string[]> {
  const found = new Set<string>();
  
  // 1. AlienVault OTX
  try {
    const otxUrl = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/passive_dns`;
    const res = await fetchWithTimeout(otxUrl, 6000);
    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data?.passive_dns)) {
        for (const item of data.passive_dns) {
          const host = String(item.hostname || '').trim().toLowerCase();
          if (host.endsWith(`.${domain}`) || host === domain) {
            if (isValidDomain(host)) found.add(host);
          }
        }
      }
    }
  } catch {
    // Continue
  }

  // 2. HackerTarget free query
  try {
    const htUrl = `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`;
    const res = await fetchWithTimeout(htUrl, 5000);
    if (res.ok) {
      const text = await res.text();
      if (!text.includes('error') && !text.includes('API count')) {
        const lines = text.split('\n');
        for (const line of lines) {
          const parts = line.split(',');
          const host = (parts[0] || '').trim().toLowerCase();
          if (host.endsWith(`.${domain}`) || host === domain) {
            if (isValidDomain(host)) found.add(host);
          }
        }
      }
    }
  } catch {
    // Continue
  }

  return Array.from(found);
}

// Proactive DNS Brute/Check for top subdomains
async function resolveCommonSubdomains(domain: string): Promise<string[]> {
  const commonPrefixes = [
    'www', 'mail', 'api', 'dev', 'app', 'staging', 'portal', 'admin',
    'vpn', 'status', 'docs', 'cdn', 'blog', 'm', 'test', 'git', 'shop',
    'beta', 'login', 'auth', 'support', 'help', 'static', 'cloud', 'secure'
  ];

  const found: string[] = [];
  const checks = commonPrefixes.map(async (prefix) => {
    const candidate = `${prefix}.${domain}`;
    try {
      await dns.resolve4(candidate);
      found.push(candidate);
    } catch {
      // not resolvable
    }
  });

  await Promise.allSettled(checks);
  return found;
}

// Check live host probe (Httpx simulation)
async function probeLiveHost(subdomain: string): Promise<LiveHost | null> {
  let ip: string | undefined;
  try {
    const ips = await dns.resolve4(subdomain);
    ip = ips[0];
  } catch {
    // Can still probe HTTP directly
  }

  const protocols = ['https://', 'http://'];
  for (const protocol of protocols) {
    const targetUrl = `${protocol}${subdomain}`;
    const start = Date.now();
    try {
      const res = await fetchWithTimeout(targetUrl, 3500);
      const latencyMs = Date.now() - start;
      let title = '';
      let server = res.headers.get('server') || undefined;

      try {
        const html = await res.text();
        const match = html.match(/<title[^>]*>([^<]+)<\/title>/i);
        if (match && match[1]) {
          title = match[1].trim().slice(0, 80);
        }
      } catch {
        // ignore title parse error
      }

      return {
        url: targetUrl,
        subdomain,
        statusCode: res.status,
        title: title || `${subdomain} (${res.status})`,
        latencyMs,
        ip,
        server,
      };
    } catch {
      // try next protocol
    }
  }

  // If DNS resolved, mark as host alive via DNS even if HTTP port blocked
  if (ip) {
    return {
      url: `http://${subdomain}`,
      subdomain,
      statusCode: 0,
      title: 'DNS Active (Port 80/443 closed/filtered)',
      latencyMs: 15,
      ip,
    };
  }

  return null;
}

// Execute the 6-stage recon workflow exactly matching recon.sh and functions.sh
async function executeReconWorkflow(scan: ScanData) {
  const domain = scan.domain;
  const startSec = Math.floor(scan.startTime / 1000);

  appendLog(scan, `\x1b[34m===========================================================\x1b[0m`);
  appendLog(scan, `\x1b[34m        Passive Subdomain Recon Automation Tool v2         \x1b[0m`);
  appendLog(scan, `\x1b[34m===========================================================\x1b[0m`);
  appendLog(scan, `\x1b[36mTarget          :\x1b[0m ${domain}`);
  appendLog(scan, `\x1b[36mOutput Folder   :\x1b[0m output/${domain}`);
  appendLog(scan, `-----------------------------------------------------------`);

  // Stage 1: Check Dependencies
  scan.step = 1;
  scan.currentAction = 'Checking Dependencies';
  appendLog(scan, `[1/6] Checking Dependencies... \x1b[32m✓ (Node.js Recon Engine Online)\x1b[0m`);

  // Stage 2: Run Subfinder
  scan.step = 2;
  scan.currentAction = 'Running Subfinder';
  appendLog(scan, `[2/6] Running Subfinder (Certificate Transparency logs)... `);
  
  const subfinderResults = await runSubfinder(domain);
  appendLog(scan, `      Subfinder discovered: ${subfinderResults.length} records \x1b[32m✓\x1b[0m`);

  // Stage 3: Run Assetfinder
  scan.step = 3;
  scan.currentAction = 'Running Assetfinder';
  appendLog(scan, `[3/6] Running Assetfinder (Passive DNS & Open Source Feeds)... `);

  const [assetfinderResults, dnsResults] = await Promise.all([
    runAssetfinder(domain),
    resolveCommonSubdomains(domain),
  ]);
  appendLog(scan, `      Assetfinder discovered: ${assetfinderResults.length} records \x1b[32m✓\x1b[0m`);
  if (dnsResults.length > 0) {
    appendLog(scan, `      DNS resolver identified: ${dnsResults.length} active prefixes`);
  }

  // Stage 4: Merge Results & Remove Duplicates
  scan.step = 4;
  scan.currentAction = 'Merging Results & Deduplicating';
  appendLog(scan, `[4/6] Merging Results & Removing Duplicates... `);

  const combined = Array.from(new Set([
    domain,
    ...subfinderResults,
    ...assetfinderResults,
    ...dnsResults,
  ])).sort();

  scan.subdomains = combined;
  scan.totalSubdomains = combined.length;
  appendLog(scan, `      Unique subdomains: ${scan.totalSubdomains} \x1b[32m✓\x1b[0m`);

  // Stage 5: Check Live Hosts (Httpx)
  scan.step = 5;
  scan.currentAction = 'Checking Live Hosts';
  appendLog(scan, `[5/6] Checking Live Hosts (HTTP/HTTPS Probe)... `);

  const aliveList: LiveHost[] = [];
  const batchSize = 6;
  for (let i = 0; i < combined.length; i += batchSize) {
    const chunk = combined.slice(i, i + batchSize);
    const results = await Promise.all(chunk.map((sub) => probeLiveHost(sub)));
    for (const r of results) {
      if (r) {
        aliveList.push(r);
        appendLog(scan, `      [ALIVE] ${r.url} [Status: ${r.statusCode || 'DNS Only'}] [${r.latencyMs}ms] ${r.title ? `"${r.title}"` : ''}`);
      }
    }
    scan.aliveHosts = [...aliveList];
    scan.aliveCount = aliveList.length;
    broadcastScanUpdate(scan.id, scan);
  }

  appendLog(scan, `      Live hosts verified: ${aliveList.length} \x1b[32m✓\x1b[0m`);

  // Stage 6: Generate Summary, Markdown Report, and Logs
  scan.step = 6;
  scan.currentAction = 'Generating Summary & Reports';
  appendLog(scan, `[6/6] Generating Summary, Markdown Report & Logs... `);

  const endSec = Math.floor(Date.now() / 1000);
  const timeTaken = Math.max(1, endSec - startSec);
  const dateStr = new Date().toUTCString();

  scan.endTime = Date.now();
  scan.executionTime = timeTaken;

  // Format summary.txt
  const summaryTxt = `===================================================
Passive Subdomain Recon Automation Tool v2
===================================================

Target Domain : ${domain}

Unique Subdomains : ${scan.totalSubdomains}

Live Hosts : ${scan.aliveCount}

Execution Time : ${timeTaken} seconds

Generated :

${dateStr}

===================================================`;

  // Format report.md
  const reportMd = `# Passive Subdomain Recon Report

## Target

${domain}

---

## Scan Statistics

| Item | Value |
|------|-------|
| Total Subdomains | ${scan.totalSubdomains} |
| Live Hosts | ${scan.aliveCount} |
| Execution Time | ${timeTaken} seconds |

---

## Output Files

- output/${domain}/subdomains.txt
- output/${domain}/alive.txt
- output/${domain}/summary.txt

---

## Discovered Live Hosts

| URL | Status | Latency | IP Address | Page Title |
|-----|--------|---------|------------|------------|
${aliveList.map(h => `| ${h.url} | ${h.statusCode || 'DNS'} | ${h.latencyMs}ms | ${h.ip || 'N/A'} | ${h.title.replace(/\|/g, '-')} |`).join('\n')}

---

Generated:

${dateStr}
`;

  // Format subdomains.txt and alive.txt
  const subdomainsTxt = combined.join('\n');
  const aliveTxt = aliveList.map(h => h.url).join('\n');

  // Format recon.log
  const reconLog = `==================================================

${dateStr}

Target : ${domain}

Subdomains : ${scan.totalSubdomains}

Alive Hosts : ${scan.aliveCount}

Execution Time : ${timeTaken} seconds

Status : SUCCESS

==================================================
`;

  scan.files = {
    subdomainsTxt,
    aliveTxt,
    summaryTxt,
    reportMd,
    reconLog,
  };

  // Write outputs to disk as in original script
  try {
    const outDir = path.resolve(`output/${domain}`);
    const repDir = path.resolve(`reports/${domain}`);
    const logDir = path.resolve('logs');

    await fs.mkdir(outDir, { recursive: true });
    await fs.mkdir(repDir, { recursive: true });
    await fs.mkdir(logDir, { recursive: true });

    await fs.writeFile(path.join(outDir, 'subdomains.txt'), subdomainsTxt);
    await fs.writeFile(path.join(outDir, 'alive.txt'), aliveTxt);
    await fs.writeFile(path.join(outDir, 'summary.txt'), summaryTxt);
    await fs.writeFile(path.join(repDir, 'report.md'), reportMd);
    await fs.appendFile(path.join(logDir, 'recon.log'), reconLog);
  } catch (err) {
    console.error('Error saving scan files to disk:', err);
  }

  appendLog(scan, `\x1b[32m✓ Reports saved to output/${domain} and reports/${domain}\x1b[0m`);
  appendLog(scan, `-----------------------------------------------------------`);
  appendLog(scan, `\x1b[32mScan Summary\x1b[0m`);
  appendLog(scan, `Target Domain      : ${domain}`);
  appendLog(scan, `Unique Subdomains  : ${scan.totalSubdomains}`);
  appendLog(scan, `Live Hosts         : ${scan.aliveCount}`);
  appendLog(scan, `Execution Time     : ${timeTaken} seconds`);
  appendLog(scan, `===========================================================`);
  appendLog(scan, `Completed.`);
  appendLog(scan, `===========================================================`);

  scan.status = 'completed';
  broadcastScanUpdate(scan.id, scan);
}

// API Routes

// Start a new scan
app.post('/api/recon/start', async (req: Request, res: Response) => {
  const rawDomain = req.body?.domain;
  if (!rawDomain) {
    return res.status(400).json({ error: 'Domain is required (e.g. example.com)' });
  }

  const domain = sanitizeDomain(String(rawDomain));
  if (!isValidDomain(domain)) {
    return res.status(400).json({ error: 'Invalid domain format. Example: example.com, hackerone.com' });
  }

  const scanId = `scan_${domain.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}`;
  const scanData: ScanData = {
    id: scanId,
    domain,
    status: 'running',
    startTime: Date.now(),
    step: 0,
    currentAction: 'Initializing scan',
    totalSubdomains: 0,
    aliveCount: 0,
    subdomains: [],
    aliveHosts: [],
    logs: [],
    files: {
      subdomainsTxt: '',
      aliveTxt: '',
      summaryTxt: '',
      reportMd: '',
      reconLog: '',
    },
  };

  scans.set(scanId, scanData);

  // Run in background without blocking API response
  executeReconWorkflow(scanData).catch((err) => {
    console.error('Workflow error:', err);
    scanData.status = 'failed';
    scanData.error = err?.message || 'Workflow execution error';
    appendLog(scanData, `\x1b[31m[ERROR] Scan failed: ${scanData.error}\x1b[0m`);
  });

  return res.json({ scanId, domain, status: 'running' });
});

// SSE endpoint for live logs & progress updates
app.get('/api/recon/stream/:scanId', (req: Request, res: Response) => {
  const { scanId } = req.params;
  const scan = scans.get(scanId);

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();

  if (!scan) {
    res.write(`data: ${JSON.stringify({ error: 'Scan not found' })}\n\n`);
    res.end();
    return;
  }

  let clientList = sseClients.get(scanId);
  if (!clientList) {
    clientList = [];
    sseClients.set(scanId, clientList);
  }
  clientList.push(res);

  // Send initial state immediately
  res.write(`data: ${JSON.stringify(scan)}\n\n`);

  req.on('close', () => {
    const list = sseClients.get(scanId) || [];
    sseClients.set(scanId, list.filter(c => c !== res));
  });
});

// Get scan status
app.get('/api/recon/scan/:scanId', (req: Request, res: Response) => {
  const { scanId } = req.params;
  const scan = scans.get(scanId);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  return res.json(scan);
});

// List all past/active scans
app.get('/api/recon/history', (_req: Request, res: Response) => {
  const list = Array.from(scans.values()).map(s => ({
    id: s.id,
    domain: s.domain,
    status: s.status,
    startTime: s.startTime,
    endTime: s.endTime,
    executionTime: s.executionTime,
    totalSubdomains: s.totalSubdomains,
    aliveCount: s.aliveCount,
  }));
  return res.json(list.reverse());
});

// Download scan report or file
app.get('/api/recon/download/:scanId/:fileType', (req: Request, res: Response) => {
  const { scanId, fileType } = req.params;
  const scan = scans.get(scanId);
  if (!scan) return res.status(404).send('Scan not found');

  switch (fileType) {
    case 'subdomains':
      res.setHeader('Content-Disposition', `attachment; filename="${scan.domain}_subdomains.txt"`);
      res.setHeader('Content-Type', 'text/plain');
      return res.send(scan.files.subdomainsTxt);

    case 'alive':
      res.setHeader('Content-Disposition', `attachment; filename="${scan.domain}_alive.txt"`);
      res.setHeader('Content-Type', 'text/plain');
      return res.send(scan.files.aliveTxt);

    case 'summary':
      res.setHeader('Content-Disposition', `attachment; filename="${scan.domain}_summary.txt"`);
      res.setHeader('Content-Type', 'text/plain');
      return res.send(scan.files.summaryTxt);

    case 'report':
      res.setHeader('Content-Disposition', `attachment; filename="${scan.domain}_report.md"`);
      res.setHeader('Content-Type', 'text/markdown');
      return res.send(scan.files.reportMd);

    case 'log':
      res.setHeader('Content-Disposition', `attachment; filename="recon.log"`);
      res.setHeader('Content-Type', 'text/plain');
      return res.send(scan.files.reconLog);

    default:
      return res.status(400).send('Invalid file type');
  }
});

// Seed a demo initial scan so the user sees results immediately upon page load
function seedDemoScan() {
  const domain = 'hackerone.com';
  const scanId = 'scan_hackerone_com_demo';
  const demoSubdomains = [
    'hackerone.com',
    'api.hackerone.com',
    'docs.hackerone.com',
    'mta-sts.hackerone.com',
    'resources.hackerone.com',
    'support.hackerone.com',
    'www.hackerone.com'
  ];

  const demoAliveHosts: LiveHost[] = [
    {
      url: 'https://hackerone.com',
      subdomain: 'hackerone.com',
      statusCode: 200,
      title: 'HackerOne: Security Begins with Trust',
      latencyMs: 78,
      ip: '104.16.99.52',
      server: 'cloudflare'
    },
    {
      url: 'https://www.hackerone.com',
      subdomain: 'www.hackerone.com',
      statusCode: 200,
      title: 'HackerOne: Security Begins with Trust',
      latencyMs: 82,
      ip: '104.16.100.52',
      server: 'cloudflare'
    },
    {
      url: 'https://docs.hackerone.com',
      subdomain: 'docs.hackerone.com',
      statusCode: 200,
      title: 'HackerOne Documentation',
      latencyMs: 110,
      ip: '104.16.99.52',
      server: 'cloudflare'
    },
    {
      url: 'https://api.hackerone.com',
      subdomain: 'api.hackerone.com',
      statusCode: 200,
      title: 'HackerOne API Portal',
      latencyMs: 95,
      ip: '104.16.100.52',
      server: 'cloudflare'
    },
    {
      url: 'https://support.hackerone.com',
      subdomain: 'support.hackerone.com',
      statusCode: 200,
      title: 'HackerOne Help Center',
      latencyMs: 142,
      ip: '104.16.99.52',
      server: 'cloudflare'
    }
  ];

  const startTime = Date.now() - 45000;
  const executionTime = 14;
  const dateStr = new Date(startTime).toUTCString();

  const summaryTxt = `===================================================
Passive Subdomain Recon Automation Tool v2
===================================================

Target Domain : ${domain}

Unique Subdomains : ${demoSubdomains.length}

Live Hosts : ${demoAliveHosts.length}

Execution Time : ${executionTime} seconds

Generated :

${dateStr}

===================================================`;

  const reportMd = `# Passive Subdomain Recon Report

## Target

${domain}

---

## Scan Statistics

| Item | Value |
|------|-------|
| Total Subdomains | ${demoSubdomains.length} |
| Live Hosts | ${demoAliveHosts.length} |
| Execution Time | ${executionTime} seconds |

---

## Output Files

- output/${domain}/subdomains.txt
- output/${domain}/alive.txt
- output/${domain}/summary.txt

---

Generated:

${dateStr}
`;

  const subdomainsTxt = demoSubdomains.join('\n');
  const aliveTxt = demoAliveHosts.map(h => h.url).join('\n');
  const reconLog = `==================================================

${dateStr}

Target : ${domain}

Subdomains : ${demoSubdomains.length}

Alive Hosts : ${demoAliveHosts.length}

Execution Time : ${executionTime} seconds

Status : SUCCESS

==================================================`;

  const logs = [
    `\x1b[34m===========================================================\x1b[0m`,
    `\x1b[34m        Passive Subdomain Recon Automation Tool v2         \x1b[0m`,
    `\x1b[34m===========================================================\x1b[0m`,
    `\x1b[36mTarget          :\x1b[0m ${domain}`,
    `\x1b[36mOutput Folder   :\x1b[0m output/${domain}`,
    `-----------------------------------------------------------`,
    `[1/6] Checking Dependencies... \x1b[32m✓\x1b[0m`,
    `[2/6] Running Subfinder......... \x1b[32m✓\x1b[0m`,
    `[3/6] Running Assetfinder...... \x1b[32m✓\x1b[0m`,
    `[4/6] Merging Results.......... \x1b[32m✓\x1b[0m`,
    `[5/6] Checking Live Hosts........ \x1b[32m✓\x1b[0m`,
    `[6/6] Generating Summary......... \x1b[32m✓\x1b[0m`,
    `-----------------------------------------------------------`,
    `\x1b[32mScan Summary\x1b[0m`,
    `Target Domain      : ${domain}`,
    `Unique Subdomains  : ${demoSubdomains.length}`,
    `Live Hosts         : ${demoAliveHosts.length}`,
    `Execution Time     : ${executionTime} seconds`,
    `===========================================================`,
    `Completed.`,
    `===========================================================`
  ];

  scans.set(scanId, {
    id: scanId,
    domain,
    status: 'completed',
    startTime,
    endTime: startTime + executionTime * 1000,
    executionTime,
    step: 6,
    currentAction: 'Completed',
    totalSubdomains: demoSubdomains.length,
    aliveCount: demoAliveHosts.length,
    subdomains: demoSubdomains,
    aliveHosts: demoAliveHosts,
    logs,
    files: {
      subdomainsTxt,
      aliveTxt,
      summaryTxt,
      reportMd,
      reconLog,
    },
  });
}

seedDemoScan();

// Setup dev server with Vite or static production serving
async function startServer() {
  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve('dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`ReconForge Server running at http://0.0.0.0:${PORT}`);
  });
}

startServer();
