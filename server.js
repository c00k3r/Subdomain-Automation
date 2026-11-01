import express from 'express';
import cors from 'cors';
import path from 'path';
import fs from 'fs/promises';
import dns from 'node:dns/promises';
import dnsNative from 'node:dns';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import { performance } from 'node:perf_hooks';

const app = express();
const PORT = Number(process.env.PORT) || 3000;
// Default to 127.0.0.1 for local desktop security; allow 0.0.0.0 only when explicitly configured or in containerized runtimes
const BIND_HOST = process.env.HOST || (process.env.K_SERVICE ? '0.0.0.0' : '127.0.0.1');
const isProd = process.env.NODE_ENV === 'production';

// Inbound DNS Rebinding Defense: Strictly validate Host headers on local & preview interfaces
const ALLOWED_HOSTS = new Set([
  'localhost',
  'localhost:3000',
  'localhost:5173',
  '127.0.0.1',
  '127.0.0.1:3000',
  '127.0.0.1:5173',
]);

const rawEnvHosts = [
  process.env.ALLOWED_HOSTS,
  process.env.NG_ALLOWED_HOSTS,
].filter(Boolean).join(',');

for (const h of rawEnvHosts.split(',').map(s => s.trim().toLowerCase()).filter(Boolean)) {
  ALLOWED_HOSTS.add(h);
}

export function isValidHostHeader(hostHeader) {
  if (!hostHeader || typeof hostHeader !== 'string') return false;
  const clean = hostHeader.trim().toLowerCase();
  const hostWithoutPort = clean.split(':')[0];
  return ALLOWED_HOSTS.has(clean) || ALLOWED_HOSTS.has(hostWithoutPort);
}

// Strict CORS Policy: Exact match against ALLOWED_ORIGINS and authorized local/preview endpoints
// Drop credentials: true since ReconForge does not use session cookies
const DEFAULT_ALLOWED_ORIGINS = new Set([
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'http://localhost:5173',
  'http://127.0.0.1:5173',
]);

const rawEnvOrigins = [
  process.env.ALLOWED_ORIGINS,
].filter(Boolean).join(',');

for (const o of rawEnvOrigins.split(',').map(s => s.trim().toLowerCase().replace(/\/+$/, '')).filter(Boolean)) {
  DEFAULT_ALLOWED_ORIGINS.add(o);
}

// Ingest runtime preview URL if provided by hosting environment
const runtimeUrl = process.env.APP_URL || process.env.PUBLIC_URL;
if (runtimeUrl) {
  try {
    const u = new URL(runtimeUrl);
    ALLOWED_HOSTS.add(u.host.toLowerCase());
    ALLOWED_HOSTS.add(u.hostname.toLowerCase());
    DEFAULT_ALLOWED_ORIGINS.add(u.origin.toLowerCase());
  } catch {
    // ignore
  }
}

export function isAllowedOrigin(origin) {
  // Allow non-browser requests (CLI, curl, server-to-server)
  if (!origin) return true;
  const clean = String(origin).trim().toLowerCase().replace(/\/+$/, '');
  return DEFAULT_ALLOWED_ORIGINS.has(clean);
}

app.use(cors({
  origin: (origin, callback) => {
    if (isAllowedOrigin(origin)) {
      callback(null, true);
    } else {
      callback(null, false);
    }
  },
  credentials: false, // Explicitly false
}));

app.use(express.json());

// Inbound DNS Rebinding Protection Middleware: Validates Host header on all /api routes
app.use('/api', (req, res, next) => {
  const host = req.headers.host;
  if (!isValidHostHeader(host)) {
    return res.status(403).json({
      error: 'Forbidden: Invalid Host header (Inbound DNS Rebinding protection)',
    });
  }
  next();
});

// Cryptographically random per-session token to defeat Cross-Origin Scanner Hijacking
export const SESSION_TOKEN = crypto.randomBytes(24).toString('hex');

export function isTokenValid(token) {
  if (!token || typeof token !== 'string') return false;
  const a = Buffer.from(token);
  const b = Buffer.from(SESSION_TOKEN);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

app.get('/api/session', (_req, res) => {
  res.json({ token: SESSION_TOKEN });
});

// In-memory store for active and past user scans with true LRU eviction (never evicting running scans)
export const MAX_SCANS = 30;
export const MAX_CONCURRENT_RUNNING = 3;
export const scans = new Map();
const sseClients = new Map();

export function getScan(scanId) {
  const scan = scans.get(scanId);
  if (scan) {
    // Refresh recency in Map (LRU)
    scans.delete(scanId);
    scans.set(scanId, scan);
  }
  return scan;
}

export function storeScan(scanId, scanData) {
  if (scans.has(scanId)) {
    scans.delete(scanId);
  } else if (scans.size >= MAX_SCANS) {
    // Find oldest completed or failed scan to evict; running scans are strictly protected from LRU eviction
    let evictedKey = null;
    for (const [key, scan] of scans.entries()) {
      if (scan.status !== 'running') {
        evictedKey = key;
        break;
      }
    }
    if (evictedKey) {
      scans.delete(evictedKey);
      const clients = sseClients.get(evictedKey) || [];
      for (const client of clients) {
        try { client.end(); } catch {}
      }
      sseClients.delete(evictedKey);
    }
  }
  scans.set(scanId, scanData);
}

function broadcastScanUpdate(scanId, scan) {
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

function appendLog(scan, line) {
  scan.logs.push(line);
  // Send delta log event to active SSE clients instead of re-serializing the entire scan object
  const clients = sseClients.get(scan.id) || [];
  const payload = `data: ${JSON.stringify({ type: 'log', line })}\n\n`;
  for (const res of clients) {
    try {
      res.write(payload);
    } catch {
      // client disconnected
    }
  }
}

// Clean and sanitize domain input
export function sanitizeDomain(input) {
  let domain = String(input || '').trim().toLowerCase();
  domain = domain.replace(/^https?:\/\//i, '');
  domain = domain.replace(/\/.*$/, '');
  domain = domain.replace(/:\d+$/, '');
  return domain;
}

// RFC 1035 + Punycode (IDN) compliant validation
export function isValidDomain(domain) {
  if (!domain || typeof domain !== 'string') return false;
  const d = domain.trim().toLowerCase();
  if (d.length > 253) return false;
  // Regex supporting ASCII and IDN Punycode labels (e.g. xn--...)
  const pattern = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,}|xn--[a-zA-Z0-9-]{2,})$/;
  return pattern.test(d);
}

// ============================================================================
// SSRF Defense Engine: BlockList Covering IPv4/IPv6 CIDRs & Rebinding Mitigations
// ============================================================================
const ipBlockList = new net.BlockList();

// IPv4 Loopback (127.0.0.0/8)
ipBlockList.addSubnet('127.0.0.0', 8, 'ipv4');
// Cloud Instance Metadata Service (IMDS) / Link-local (169.254.0.0/16)
ipBlockList.addSubnet('169.254.0.0', 16, 'ipv4');
// RFC 1918 Private networks
ipBlockList.addSubnet('10.0.0.0', 8, 'ipv4');
ipBlockList.addSubnet('172.16.0.0', 12, 'ipv4');
ipBlockList.addSubnet('192.168.0.0', 16, 'ipv4');
// Carrier Grade NAT (100.64.0.0/10)
ipBlockList.addSubnet('100.64.0.0', 10, 'ipv4');
// Current network / Zero address (0.0.0.0/8)
ipBlockList.addSubnet('0.0.0.0', 8, 'ipv4');
// IETF Protocol Assignments (192.0.0.0/24)
ipBlockList.addSubnet('192.0.0.0', 24, 'ipv4');
// Inter-network benchmark testing (198.18.0.0/15)
ipBlockList.addSubnet('198.18.0.0', 15, 'ipv4');
// Multicast (224.0.0.0/4)
ipBlockList.addSubnet('224.0.0.0', 4, 'ipv4');
// Reserved for future use (240.0.0.0/4)
ipBlockList.addSubnet('240.0.0.0', 4, 'ipv4');
// Broadcast
ipBlockList.addAddress('255.255.255.255', 'ipv4');

// IPv6 Loopback & Unspecified
ipBlockList.addAddress('::1', 'ipv6');
ipBlockList.addAddress('::', 'ipv6');
// IPv6 Unique Local Address (fc00::/7 covers fc00::/8 and fd00::/8)
ipBlockList.addSubnet('fc00::', 7, 'ipv6');
// IPv6 Link-Local Unicast (fe80::/10 covers fe80..febf)
ipBlockList.addSubnet('fe80::', 10, 'ipv6');
// IPv6 Multicast (ff00::/8)
ipBlockList.addSubnet('ff00::', 8, 'ipv6');

// Granular BlockLists for RFC Range Classification
const loopbackBlockList = new net.BlockList();
loopbackBlockList.addSubnet('127.0.0.0', 8, 'ipv4');
loopbackBlockList.addAddress('::1', 'ipv6');

const imdsBlockList = new net.BlockList();
imdsBlockList.addSubnet('169.254.0.0', 16, 'ipv4');
imdsBlockList.addSubnet('fe80::', 10, 'ipv6');

const rfc1918BlockList = new net.BlockList();
rfc1918BlockList.addSubnet('10.0.0.0', 8, 'ipv4');
rfc1918BlockList.addSubnet('172.16.0.0', 12, 'ipv4');
rfc1918BlockList.addSubnet('192.168.0.0', 16, 'ipv4');
rfc1918BlockList.addSubnet('fc00::', 7, 'ipv6');

const cgnatBlockList = new net.BlockList();
cgnatBlockList.addSubnet('100.64.0.0', 10, 'ipv4');

const reservedBlockList = new net.BlockList();
reservedBlockList.addSubnet('224.0.0.0', 4, 'ipv4');
reservedBlockList.addSubnet('240.0.0.0', 4, 'ipv4');
reservedBlockList.addSubnet('0.0.0.0', 8, 'ipv4');
reservedBlockList.addSubnet('192.0.0.0', 24, 'ipv4');
reservedBlockList.addSubnet('198.18.0.0', 15, 'ipv4');
reservedBlockList.addAddress('255.255.255.255', 'ipv4');
reservedBlockList.addAddress('::', 'ipv6');
reservedBlockList.addSubnet('ff00::', 8, 'ipv6');

// Helper: Expands an IPv6 address into 8 16-bit integer words
export function expandIPv6ToWords(ipStr) {
  let str = String(ipStr || '').toLowerCase();
  const lastColon = str.lastIndexOf(':');
  if (lastColon !== -1) {
    const tail = str.slice(lastColon + 1);
    if (tail.includes('.')) {
      const parts = tail.split('.');
      if (parts.length === 4 && parts.every(p => /^\d+$/.test(p))) {
        const b0 = parseInt(parts[0], 10);
        const b1 = parseInt(parts[1], 10);
        const b2 = parseInt(parts[2], 10);
        const b3 = parseInt(parts[3], 10);
        if (b0 <= 255 && b1 <= 255 && b2 <= 255 && b3 <= 255) {
          const hex1 = ((b0 << 8) | b1).toString(16);
          const hex2 = ((b2 << 8) | b3).toString(16);
          str = str.slice(0, lastColon + 1) + hex1 + ':' + hex2;
        }
      }
    }
  }

  const halves = str.split('::');
  if (halves.length > 2) return null;
  let words = [];
  if (halves.length === 2) {
    const left = halves[0] ? halves[0].split(':').filter(Boolean).map(x => parseInt(x, 16)) : [];
    const right = halves[1] ? halves[1].split(':').filter(Boolean).map(x => parseInt(x, 16)) : [];
    const fillCount = 8 - (left.length + right.length);
    if (fillCount < 0) return null;
    const middle = new Array(fillCount).fill(0);
    words = [...left, ...middle, ...right];
  } else {
    words = str.split(':').map(x => parseInt(x, 16));
  }
  if (words.length !== 8 || words.some(w => isNaN(w) || w < 0 || w > 0xffff)) {
    return null;
  }
  return words;
}

// Helper: Unwraps embedded IPv4 from IPv4-mapped, IPv4-compatible, NAT64, or 6to4 encapsulation
export function unwrapEmbeddedIPv4(clean) {
  const ver = net.isIP(clean);
  if (ver === 4) return clean;
  if (ver === 6) {
    const words = expandIPv6ToWords(clean);
    if (!words) return null;
    // 1. IPv4-Mapped IPv6 (::ffff:0:0/96)
    if (words[0] === 0 && words[1] === 0 && words[2] === 0 && words[3] === 0 && words[4] === 0 && words[5] === 0xffff) {
      return `${words[6] >> 8}.${words[6] & 0xff}.${words[7] >> 8}.${words[7] & 0xff}`;
    }
    // 2. IPv4-Compatible IPv6 (::0:0/96)
    if (words[0] === 0 && words[1] === 0 && words[2] === 0 && words[3] === 0 && words[4] === 0 && words[5] === 0) {
      if ((words[6] === 0 && words[7] === 0) || (words[6] === 0 && words[7] === 1)) return null;
      return `${words[6] >> 8}.${words[6] & 0xff}.${words[7] >> 8}.${words[7] & 0xff}`;
    }
    // 3. NAT64 Well-Known Prefix (64:ff9b::/96)
    if (words[0] === 0x0064 && words[1] === 0xff9b && words[2] === 0 && words[3] === 0 && words[4] === 0 && words[5] === 0) {
      return `${words[6] >> 8}.${words[6] & 0xff}.${words[7] >> 8}.${words[7] & 0xff}`;
    }
    // 4. 6to4 Anycast / Encapsulation (2002::/16)
    if (words[0] === 0x2002) {
      return `${words[1] >> 8}.${words[1] & 0xff}.${words[2] >> 8}.${words[2] & 0xff}`;
    }
  }
  return null;
}

// Evaluates an IP against RFC ranges.
// CRITICAL: FAILS CLOSED. Any unparseable string, garbage, null, or invalid IP returns true (blocked).
export function isPrivateOrReservedIp(ip) {
  if (!ip || typeof ip !== 'string') return true; // Fail closed
  const clean = ip.trim().toLowerCase();

  const ver = net.isIP(clean);
  if (ver === 0) {
    // Fail closed: malformed or unparseable IP input is rejected
    return true;
  }

  const v4 = unwrapEmbeddedIPv4(clean);
  if (v4) {
    return ipBlockList.check(v4, 'ipv4');
  }

  if (ver === 6) {
    const words = expandIPv6ToWords(clean);
    if (!words) {
      return true; // Fail closed
    }
    return ipBlockList.check(clean, 'ipv6');
  }

  return true; // Fail closed
}

// Custom connect-time lookup: closes TOCTOU check-then-use DNS rebinding gap
export function ssrfSafeLookup(hostname, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }

  dnsNative.lookup(hostname, { all: true, ...options }, (err, addresses) => {
    if (err) return callback(err);
    if (!addresses || addresses.length === 0) {
      return callback(new Error(`DNS resolution returned no addresses for ${hostname}`));
    }

    // Connect-time validation: check every resolved address (A and AAAA)
    for (const record of addresses) {
      const addr = typeof record === 'string' ? record : record.address;
      if (isPrivateOrReservedIp(addr)) {
        const ssrfError = new Error(`SSRF blocked: ${hostname} resolved to reserved address ${addr}`);
        ssrfError.code = 'ERR_SSRF_BLOCKED';
        return callback(ssrfError);
      }
    }

    if (options && options.all) {
      return callback(null, addresses);
    }
    const first = addresses[0];
    return callback(null, first.address, first.family);
  });
}

// Safe HTTP/HTTPS request with overall hard deadline, per-call maxBytes, and explicit TLS policy
export function safeHttpRequest(targetUrl, {
  timeoutMs = 5000,
  overallDeadlineMs = 8000,
  maxBytes = 150 * 1024, // 150KB default for web inspections
  rejectUnauthorized = true, // Strict TLS by default for 3rd party APIs
} = {}) {
  return new Promise((resolve, reject) => {
    let parsedUrl;
    try {
      parsedUrl = new URL(targetUrl);
    } catch (e) {
      return reject(e);
    }

    const isHttps = parsedUrl.protocol === 'https:';
    const client = isHttps ? https : http;

    // Defense against direct IP literals: Node's http.request skips lookup when host is an IP literal.
    // Ensure IP literals are validated and blocked immediately before connection.
    const hostname = parsedUrl.hostname;
    if (net.isIP(hostname) && isPrivateOrReservedIp(hostname)) {
      const ssrfError = new Error(`SSRF blocked: IP literal ${hostname} is a reserved address`);
      ssrfError.code = 'ERR_SSRF_BLOCKED';
      return reject(ssrfError);
    }

    let finished = false;
    let deadlineTimer = null;

    const cleanup = () => {
      finished = true;
      if (deadlineTimer) clearTimeout(deadlineTimer);
    };

    deadlineTimer = setTimeout(() => {
      if (!finished) {
        cleanup();
        req.destroy(new Error(`Overall request deadline exceeded (${overallDeadlineMs}ms)`));
      }
    }, overallDeadlineMs);

    const req = client.request(
      parsedUrl,
      {
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconForge/2.1',
          Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
        timeout: timeoutMs,
        rejectUnauthorized,
        lookup: ssrfSafeLookup, // Connect-time DNS rebinding defense
      },
      (res) => {
        let data = '';
        let bytesRead = 0;
        res.setEncoding('utf8');

        res.on('data', (chunk) => {
          bytesRead += Buffer.byteLength(chunk, 'utf8');
          if (bytesRead > maxBytes) {
            cleanup();
            req.destroy(new Error(`Response size limit exceeded (> ${maxBytes} bytes)`));
            return;
          }
          data += chunk;
        });

        res.on('end', () => {
          cleanup();
          resolve({
            statusCode: res.statusCode || 0,
            headers: res.headers,
            body: data,
          });
        });
      }
    );

    req.on('timeout', () => {
      cleanup();
      req.destroy();
      reject(new Error(`Connection idle timeout (${timeoutMs}ms)`));
    });

    req.on('error', (err) => {
      cleanup();
      reject(err);
    });

    req.end();
  });
}

// 1. Certificate Transparency Logs via crt.sh API (Strict TLS & 15MB buffer)
async function queryCrtSh(domain) {
  const records = new Set();
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
  try {
    const res = await safeHttpRequest(url, {
      timeoutMs: 7000,
      overallDeadlineMs: 12000,
      maxBytes: 15 * 1024 * 1024,
      rejectUnauthorized: true,
    });
    if (res.statusCode === 200) {
      const data = JSON.parse(res.body);
      if (Array.isArray(data)) {
        for (const entry of data) {
          const names = String(entry.name_value || '').split('\n');
          for (let name of names) {
            name = name.trim().toLowerCase();
            if (name.startsWith('*.')) name = name.slice(2);
            if (name.endsWith(`.${domain}`) || name === domain) {
              if (isValidDomain(name)) records.add(name);
            }
          }
        }
      }
      return { records: Array.from(records), error: null };
    } else {
      return { records: [], error: `HTTP ${res.statusCode} status from crt.sh` };
    }
  } catch (err) {
    return { records: [], error: err.message || 'Request timeout' };
  }
}

// 2. Passive DNS via AlienVault OTX (Strict TLS & 5MB buffer)
async function queryAlienVaultOTX(domain) {
  const records = new Set();
  const url = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/passive_dns`;
  try {
    const res = await safeHttpRequest(url, {
      timeoutMs: 6000,
      overallDeadlineMs: 10000,
      maxBytes: 5 * 1024 * 1024,
      rejectUnauthorized: true,
    });
    if (res.statusCode === 200) {
      const data = JSON.parse(res.body);
      if (Array.isArray(data?.passive_dns)) {
        for (const item of data.passive_dns) {
          const host = String(item.hostname || '').trim().toLowerCase();
          if (host.endsWith(`.${domain}`) || host === domain) {
            if (isValidDomain(host)) records.add(host);
          }
        }
      }
      return { records: Array.from(records), error: null };
    } else {
      return { records: [], error: `HTTP ${res.statusCode}` };
    }
  } catch (err) {
    return { records: [], error: err.message || 'Timeout' };
  }
}

// 3. Passive Host Search via HackerTarget (Strict TLS)
async function queryHackerTarget(domain) {
  const records = new Set();
  const url = `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`;
  try {
    const res = await safeHttpRequest(url, {
      timeoutMs: 5000,
      overallDeadlineMs: 8000,
      maxBytes: 2 * 1024 * 1024,
      rejectUnauthorized: true,
    });
    if (res.statusCode === 200) {
      const text = res.body.trim();
      if (text.startsWith('API count exceeded') || text.startsWith('No records found') || text.startsWith('error check your search')) {
        return { records: [], error: text.slice(0, 50) };
      }

      const lines = text.split('\n');
      for (const line of lines) {
        const parts = line.split(',');
        const host = (parts[0] || '').trim().toLowerCase();
        if (host.endsWith(`.${domain}`) || host === domain) {
          if (isValidDomain(host)) records.add(host);
        }
      }
      return { records: Array.from(records), error: null };
    }
    return { records: [], error: `HTTP ${res.statusCode}` };
  } catch (err) {
    return { records: [], error: err.message || 'Timeout' };
  }
}

// 4. Wildcard DNS Pre-Check: Probes random canary labels on both IPv4 and IPv6 to catch v4/v6 wildcards
export async function detectWildcardDNS(
  domain,
  resolver4Fn = dns.resolve4,
  resolver6Fn = dns.resolve6
) {
  const randomSuffix = crypto.randomBytes(4).toString('hex');
  const testHost4 = `_wildcard_v4_${randomSuffix}.${domain}`;
  const testHost6 = `_wildcard_v6_${randomSuffix}.${domain}`;
  const wildcardIps = [];

  try {
    const ips4 = await resolver4Fn(testHost4);
    if (Array.isArray(ips4) && ips4.length > 0) {
      wildcardIps.push(...ips4);
    }
  } catch {
    // Expected behavior: NXDOMAIN / ENOTFOUND
  }

  try {
    const ips6 = await resolver6Fn(testHost6);
    if (Array.isArray(ips6) && ips6.length > 0) {
      wildcardIps.push(...ips6);
    }
  } catch {
    // Expected behavior: NXDOMAIN / ENOTFOUND
  }

  return {
    hasWildcard: wildcardIps.length > 0,
    wildcardIps: Array.from(new Set(wildcardIps)),
  };
}

// 5. Active DNS dictionary checking for high-frequency prefixes (only run if NO wildcard DNS)
async function resolveCommonSubdomains(domain) {
  const commonPrefixes = [
    'www', 'mail', 'api', 'dev', 'app', 'staging', 'portal', 'admin',
    'vpn', 'status', 'docs', 'cdn', 'blog', 'm', 'test', 'git', 'shop',
    'beta', 'login', 'auth', 'support', 'help', 'static', 'cloud', 'secure'
  ];

  const found = [];
  const checks = commonPrefixes.map(async (prefix) => {
    const candidate = `${prefix}.${domain}`;
    try {
      await dns.resolve4(candidate);
      found.push(candidate);
    } catch {
      // non-existent
    }
  });

  await Promise.allSettled(checks);
  return found;
}

// Categorize subdomains for offensive security triage
function categorizeSubdomain(subdomain) {
  const s = subdomain.toLowerCase();
  if (/(?:^|\.)(?:auth|login|sso|vpn|portal|identity|keycloak|okta|access|idp)(?:\.|$)/.test(s)) return 'auth';
  if (/(?:^|\.)(?:api|v[0-9]|graphql|gateway|rest|grpc|backend|services?)(?:\.|$)/.test(s)) return 'api';
  if (/(?:^|\.)(?:dev|staging|stage|test|qa|internal|corp|uat|sandbox|demo|preprod)(?:\.|$)/.test(s)) return 'staging';
  if (/(?:^|\.)(?:s3|cdn|assets|static|storage|bucket|media|img)(?:\.|$)/.test(s)) return 'cloud';
  return 'general';
}

// Technology stack fingerprinting from response headers and body
function fingerprintTechStack(headers = {}, body = '') {
  const tech = new Set();
  const server = String(headers['server'] || '').toLowerCase();
  const poweredBy = String(headers['x-powered-by'] || '').toLowerCase();
  const via = String(headers['via'] || '').toLowerCase();

  // CDNs and Reverse Proxies
  if (headers['cf-ray'] || server.includes('cloudflare')) tech.add('Cloudflare');
  if (headers['x-amz-cf-id'] || via.includes('cloudfront')) tech.add('AWS CloudFront');
  if (headers['x-fastly-request-id'] || server.includes('fastly')) tech.add('Fastly');
  if (server.includes('akamai') || headers['x-akamai-transformed']) tech.add('Akamai');
  if (server.includes('vercel') || headers['x-vercel-id']) tech.add('Vercel');
  if (server.includes('netlify')) tech.add('Netlify');
  if (server.includes('gws') || server.includes('google')) tech.add('Google Front-End');
  if (server.includes('github') || headers['x-github-request-id']) tech.add('GitHub Pages');

  // Web Servers
  if (server.includes('nginx')) {
    const m = server.match(/nginx(?:\/([\d.]+))?/i);
    tech.add(m && m[1] ? `Nginx ${m[1]}` : 'Nginx');
  }
  if (server.includes('apache')) tech.add('Apache');
  if (server.includes('caddy')) tech.add('Caddy');
  if (server.includes('envoy')) tech.add('Envoy');
  if (server.includes('iis')) tech.add('Microsoft IIS');

  // Application Stacks
  if (poweredBy.includes('express')) tech.add('Express.js');
  if (poweredBy.includes('php')) tech.add('PHP');
  if (poweredBy.includes('asp.net')) tech.add('ASP.NET');
  if (poweredBy.includes('next.js')) tech.add('Next.js');

  // Body signatures
  if (body.includes('wp-content')) tech.add('WordPress');
  if (body.includes('__next')) tech.add('Next.js');
  if (body.includes('react')) tech.add('React');

  return Array.from(tech);
}

// Subdomain Takeover: Checks DNS CNAME Records against Verified Service Signatures
const TAKEOVER_SERVICES = [
  {
    service: 'GitHub Pages',
    cnameSuffixes: ['.github.io'],
    fingerprints: [
      "there isn't a github pages site here",
      'for root urls you must provide an index.html file',
    ],
    severity: 'HIGH',
    perResourceDns: false, // Shared anycast IP pool resolves wildcard DNS for all subdomains
    confirmedReason: 'Dangling CNAME points to unclaimed GitHub Pages repository.',
    remediation: 'Claim the GitHub repository or delete the stale DNS CNAME entry.',
  },
  {
    service: 'Amazon S3',
    // Comprehensive regex covering standard, regional, and website endpoints worldwide
    // Excludes generic *.amazonaws.com and *.elb.amazonaws.com to eliminate false positives
    cnameRegex: /^(?:[a-z0-9.-]+\.)?s3(?:[\.-]website)?(?:[\.-][a-z0-9-]+)?\.amazonaws\.com$/i,
    cnameSuffixes: ['.s3.amazonaws.com'],
    fingerprints: [
      'the specified bucket does not exist',
      'nosuchbucket',
    ],
    severity: 'CRITICAL',
    perResourceDns: false, // S3 resolves wildcard IPs for any bucket hostname
    confirmedReason: 'Dangling CNAME points to deleted or unregistered S3 bucket.',
    remediation: 'Claim the S3 bucket in your AWS account or delete the CNAME record.',
  },
  {
    service: 'AWS Elastic Beanstalk',
    cnameSuffixes: ['.elasticbeanstalk.com'],
    fingerprints: [],
    severity: 'HIGH',
    perResourceDns: true, // Elastic Beanstalk terminates per-resource DNS records (NXDOMAIN on release)
    confirmedReason: 'Dangling CNAME points to deleted or released Elastic Beanstalk environment (NXDOMAIN).',
    remediation: 'Claim the Elastic Beanstalk environment name in AWS or delete the CNAME record.',
  },
  {
    service: 'Azure Web App',
    cnameSuffixes: ['.azurewebsites.net'],
    fingerprints: [
      '404 web app not found',
    ],
    severity: 'HIGH',
    perResourceDns: true, // Azure Web App tears down specific subdomain DNS on de-allocation (NXDOMAIN)
    confirmedReason: 'Dangling CNAME points to unregistered or deleted Azure Web App.',
    remediation: 'Claim the Web App hostname in Azure App Service or delete the DNS record.',
  },
  {
    service: 'Azure Traffic Manager',
    cnameSuffixes: ['.trafficmanager.net'],
    fingerprints: [],
    severity: 'HIGH',
    perResourceDns: true, // Deleted Traffic Manager profile returns NXDOMAIN
    confirmedReason: 'Dangling CNAME points to non-existent Azure Traffic Manager profile (NXDOMAIN).',
    remediation: 'Recreate the Traffic Manager profile in Azure or remove the CNAME.',
  },
  {
    service: 'Fastly',
    cnameSuffixes: ['.fastly.net', '.fastlylb.net'],
    fingerprints: [
      'fastly error: unknown domain',
    ],
    severity: 'MEDIUM',
    perResourceDns: false, // Fastly uses shared anycast IPs
    confirmedReason: 'Dangling CNAME points to unclaimed Fastly CDN service.',
    remediation: 'Add the domain to your Fastly service or remove the CNAME.',
  },
  {
    service: 'Heroku',
    cnameSuffixes: ['.herokudns.com', '.herokuapp.com'],
    fingerprints: [
      'herokucdn.com',
      'no such app',
    ],
    severity: 'HIGH',
    perResourceDns: false, // Heroku routes via shared ingress
    confirmedReason: 'Dangling CNAME points to released Heroku application.',
    remediation: 'Claim the Heroku app name or remove DNS record.',
  },
  {
    service: 'Ghost(Pro)',
    cnameSuffixes: ['.ghost.io'],
    fingerprints: [
      'the thing you were looking for is no longer here',
    ],
    severity: 'MEDIUM',
    perResourceDns: false,
    confirmedReason: 'Dangling CNAME points to unclaimed Ghost blog.',
    remediation: 'Claim the Ghost blog or delete the CNAME record.',
  },
  {
    service: 'Zendesk',
    cnameSuffixes: ['.zendesk.com'],
    fingerprints: [
      'help center closed',
      'no such sub-domain',
    ],
    severity: 'MEDIUM',
    perResourceDns: false,
    confirmedReason: 'Unclaimed Zendesk helpdesk CNAME.',
    remediation: 'Claim Zendesk pod or remove CNAME.',
  },
  {
    service: 'Shopify',
    cnameSuffixes: ['.myshopify.com'],
    fingerprints: [
      'sorry, this shop is currently unavailable',
    ],
    severity: 'MEDIUM',
    perResourceDns: false,
    confirmedReason: 'Unclaimed Shopify store CNAME.',
    remediation: 'Claim the store name in Shopify or remove CNAME.',
  },
  {
    service: 'Surge.sh',
    cnameSuffixes: ['.surge.sh'],
    fingerprints: [
      'project not found',
    ],
    severity: 'LOW',
    perResourceDns: false,
    confirmedReason: 'Dangling CNAME points to unclaimed Surge domain.',
    remediation: 'Publish project to Surge or remove DNS record.',
  },
];

export async function checkTakeoverRisk(
  subdomain,
  statusCode,
  body = '',
  cnameResolverFn = dns.resolveCname,
  targetResolverFn = dns.resolve4
) {
  const b = (body || '').toLowerCase();

  let cnames = [];
  try {
    cnames = await cnameResolverFn(subdomain);
  } catch {
    // No CNAME record present
  }

  const normalizedCnames = (Array.isArray(cnames) ? cnames : [])
    .map(c => String(c || '').toLowerCase().replace(/\.$/, ''))
    .filter(Boolean);

  // If no CNAME resolved and body is empty, no takeover vulnerability exists
  if (normalizedCnames.length === 0 && b.length === 0) {
    return null;
  }

  for (const item of TAKEOVER_SERVICES) {
    // Match suffix against any CNAME in the chain using regex or strict suffix
    const matchingCname = normalizedCnames.find(cname => {
      if (item.cnameRegex && item.cnameRegex.test(cname)) {
        return true;
      }
      return item.cnameSuffixes?.some(suffix => {
        const cleanSuffix = suffix.toLowerCase().replace(/^\./, '');
        return cname === cleanSuffix || cname.endsWith(`.${cleanSuffix}`);
      });
    });

    const bodyMatches = b.length > 0 && item.fingerprints.some(fp => b.includes(fp));

    if (matchingCname) {
      // Per-Resource DNS verification: Only test target DNS when the provider terminates records per resource
      if (item.perResourceDns) {
        let targetNxDomain = false;
        try {
          await targetResolverFn(matchingCname);
        } catch (err) {
          // Only count genuine NXDOMAIN (Node's ENOTFOUND). Drop ESERVFAIL so resolver flakiness never produces false positives.
          if (err && err.code === 'ENOTFOUND') {
            targetNxDomain = true;
          }
        }

        if (targetNxDomain) {
          return {
            isVulnerable: true,
            certainty: 'Likely',
            service: item.service,
            cname: matchingCname,
            severity: item.severity,
            reason: `Dangling CNAME points to NXDOMAIN target (${matchingCname}). Per-resource DNS confirms the target environment does not exist and is susceptible to registration hijack.`,
            remediation: `Remove the dangling CNAME record for ${subdomain} or register the target resource with ${item.service}.`,
          };
        }
      }

      if (bodyMatches && (statusCode === 404 || statusCode === 0 || statusCode === 502 || statusCode === 503)) {
        return {
          isVulnerable: true,
          certainty: 'Likely',
          service: item.service,
          cname: matchingCname,
          severity: item.severity,
          reason: `CNAME points to ${item.service} (${matchingCname}) and HTTP response matched unclaimed provider fingerprint.`,
          remediation: `Verify project ownership on ${item.service}. If abandoned, delete the CNAME DNS record.`,
        };
      }
    } else if (bodyMatches && statusCode === 404) {
      return {
        isVulnerable: true,
        certainty: 'Potential',
        service: `${item.service} (Potential)`,
        cname: normalizedCnames[0] || 'None',
        severity: 'LOW',
        reason: `HTTP response matched ${item.service} signature, but CNAME does not point to known provider suffix.`,
        remediation: `Inspect DNS and reverse proxy configuration for accidental leak or misconfigured routing.`,
      };
    }
  }

  return null;
}

// Differentiates internal/reserved IPs by range using net.BlockList (failure-proof, no string prefixes)
export function classifyIpRisk(ip) {
  if (!ip || typeof ip !== 'string') {
    return {
      severity: 'LOW',
      title: 'Reserved Internal Address',
      reason: 'Unparseable or unknown IP address representation.',
      remediation: 'Verify DNS record validity.',
    };
  }

  const clean = ip.trim().toLowerCase();
  const ver = net.isIP(clean);
  if (ver === 0) {
    return {
      severity: 'LOW',
      title: 'Reserved Internal Address',
      reason: 'Unparseable or unknown IP address representation.',
      remediation: 'Verify DNS record validity.',
    };
  }

  // Check if an embedded IPv4 address is present (unwrapping ::ffff:, 64:ff9b::, 2002::, etc.)
  const v4 = unwrapEmbeddedIPv4(clean);
  if (v4) {
    if (loopbackBlockList.check(v4, 'ipv4')) {
      return {
        severity: 'INFO',
        title: 'Localhost / Loopback Mapping',
        reason: 'Subdomain maps to loopback interface. Often deliberate for local development, split-horizon routing, or desktop client sync (e.g. localhost.target.com -> 127.0.0.1).',
        remediation: 'Ensure loopback mapping is intentional and does not expose local services to cross-origin abuse.',
      };
    }
    if (imdsBlockList.check(v4, 'ipv4')) {
      return {
        severity: 'HIGH',
        title: 'Link-Local / Cloud IMDS Mapping',
        reason: 'Subdomain resolves to link-local or Cloud Instance Metadata Service (IMDS) range (169.254.169.254). Potential SSRF jump-point if requested by cloud workloads.',
        remediation: 'Remove link-local or IMDS IP mappings from public DNS zones immediately.',
      };
    }
    if (rfc1918BlockList.check(v4, 'ipv4')) {
      return {
        severity: 'MEDIUM',
        title: 'Internal IP Leak / RFC 1918 Exposure',
        reason: 'Subdomain resolves to internal private network address space, disclosing internal network topology in public DNS.',
        remediation: 'Remove internal IP mappings from public DNS zones or use split-horizon DNS to keep private IPs restricted to internal resolvers.',
      };
    }
    if (cgnatBlockList.check(v4, 'ipv4')) {
      return {
        severity: 'LOW',
        title: 'Carrier-Grade NAT Address (RFC 6598)',
        reason: 'Subdomain maps to shared address space used by telecommunication providers and CGNAT infrastructure.',
        remediation: 'Review DNS configuration to confirm whether shared carrier address allocation is intentional.',
      };
    }
    if (reservedBlockList.check(v4, 'ipv4')) {
      return {
        severity: 'LOW',
        title: 'Reserved / Multicast IP Address',
        reason: 'Subdomain resolves to multicast, broadcast, or IETF reserved address range.',
        remediation: 'Update DNS record to point to a valid public unicast IP address.',
      };
    }
  }

  // Native IPv6 evaluation
  if (ver === 6) {
    if (loopbackBlockList.check(clean, 'ipv6')) {
      return {
        severity: 'INFO',
        title: 'Localhost / Loopback Mapping',
        reason: 'Subdomain maps to IPv6 loopback (::1). Often deliberate for local development or split-horizon routing.',
        remediation: 'Ensure loopback mapping is intentional and does not expose local services to cross-origin abuse.',
      };
    }
    if (imdsBlockList.check(clean, 'ipv6')) {
      return {
        severity: 'HIGH',
        title: 'Link-Local / Cloud IMDS Mapping',
        reason: 'Subdomain resolves to IPv6 link-local unicast range (fe80::/10).',
        remediation: 'Remove link-local IP mappings from public DNS zones immediately.',
      };
    }
    if (rfc1918BlockList.check(clean, 'ipv6')) {
      return {
        severity: 'MEDIUM',
        title: 'Internal IP Leak / RFC 1918 Exposure',
        reason: 'Subdomain resolves to IPv6 Unique Local Address range (fc00::/7), disclosing internal network topology.',
        remediation: 'Remove internal ULA mappings from public DNS zones or use split-horizon DNS.',
      };
    }
    if (reservedBlockList.check(clean, 'ipv6')) {
      return {
        severity: 'LOW',
        title: 'Reserved / Multicast IP Address',
        reason: 'Subdomain resolves to IPv6 multicast (ff00::/8) or unspecified address range.',
        remediation: 'Update DNS record to point to a valid public unicast IP address.',
      };
    }
  }

  return {
    severity: 'LOW',
    title: 'Reserved Internal Address',
    reason: 'Subdomain resolves to a reserved internal network address.',
    remediation: 'Update DNS record to point to a valid public IP address.',
  };
}

// Active Host Prober with Dual IPv4/IPv6, Real DNS Latency, and SSRF Defense
async function probeLiveHost(subdomain) {
  let ip4 = null;
  let ip6 = null;
  let dnsTime = 0;

  // Measure genuine DNS lookup latency
  const dnsStart = performance.now();
  try {
    const results = await dns.resolve4(subdomain);
    ip4 = results[0];
  } catch {
    // no IPv4
  }

  try {
    const results6 = await dns.resolve6(subdomain);
    ip6 = results6[0];
  } catch {
    // no IPv6
  }
  dnsTime = Math.round(performance.now() - dnsStart);

  const primaryIp = ip4 || ip6;
  const category = categorizeSubdomain(subdomain);

  // SSRF Pre-check: Internal IPs showing up in public DNS are reportable findings
  if (primaryIp && isPrivateOrReservedIp(primaryIp)) {
    const ipRisk = classifyIpRisk(primaryIp);
    return {
      url: `http://${subdomain}`,
      subdomain,
      statusCode: 0,
      title: ipRisk.title,
      latencyMs: dnsTime,
      ip: primaryIp,
      ipv6: ip6,
      category: 'internal-leak',
      techStack: [`${ipRisk.title} (SSRF Blocked)`],
      takeoverRisk: null,
      ssrfBlocked: true,
      internalLeak: true,
      ipRisk,
    };
  }

  // Probe HTTPS first, then fallback to HTTP
  // rejectUnauthorized is set to false exclusively for target host discovery to inspect self-signed certs
  const protocols = ['https://', 'http://'];
  for (const protocol of protocols) {
    const targetUrl = `${protocol}${subdomain}`;
    const httpStart = performance.now();
    try {
      const res = await safeHttpRequest(targetUrl, {
        timeoutMs: 3800,
        overallDeadlineMs: 5000,
        maxBytes: 150 * 1024,
        rejectUnauthorized: false,
      });
      const latencyMs = Math.round(performance.now() - httpStart);

      let title = '';
      const match = res.body.match(/<title[^>]*>([^<]+)<\/title>/i);
      if (match && match[1]) {
        title = match[1].trim().slice(0, 90);
      }

      const techStack = fingerprintTechStack(res.headers, res.body);
      const takeoverRisk = await checkTakeoverRisk(subdomain, res.statusCode, res.body);

      return {
        url: targetUrl,
        subdomain,
        statusCode: res.statusCode,
        title, // Honest: empty string if no HTML title found
        latencyMs,
        ip: primaryIp,
        ipv6: ip6,
        server: res.headers['server'] || undefined,
        category,
        techStack: techStack.length > 0 ? techStack : (res.headers['server'] ? [res.headers['server']] : ['Web Server']),
        takeoverRisk,
      };
    } catch (err) {
      if (err.code === 'ERR_SSRF_BLOCKED' || (err.message && err.message.includes('SSRF blocked'))) {
        const ipRisk = classifyIpRisk(primaryIp);
        return {
          url: targetUrl,
          subdomain,
          statusCode: 0,
          title: ipRisk.title,
          latencyMs: 0,
          ip: primaryIp,
          ipv6: ip6,
          category: 'internal-leak',
          techStack: [`${ipRisk.title} (SSRF Blocked via Rebinding Protection)`],
          takeoverRisk: null,
          ssrfBlocked: true,
          internalLeak: true,
          ipRisk,
        };
      }
      // try next protocol
    }
  }

  // If DNS resolved but HTTP ports are unreachable
  if (primaryIp) {
    // Only check takeover if CNAME points to a known service whose target returns NXDOMAIN
    const takeoverRisk = await checkTakeoverRisk(subdomain, 0, '');
    return {
      url: `http://${subdomain}`,
      subdomain,
      statusCode: 0,
      title: '',
      latencyMs: dnsTime, // Real measured DNS latency
      ip: primaryIp,
      ipv6: ip6,
      category,
      techStack: ['DNS Only (Web Ports Closed)'],
      takeoverRisk,
    };
  }

  return null;
}

// 6-Stage Reconnaissance Pipeline
async function executeReconWorkflow(scan) {
  const domain = scan.domain;
  const startSec = Math.floor(scan.startTime / 1000);

  appendLog(scan, `\x1b[34m===========================================================\x1b[0m`);
  appendLog(scan, `\x1b[34m        ReconForge Automation Engine v2.1                  \x1b[0m`);
  appendLog(scan, `\x1b[34m===========================================================\x1b[0m`);
  appendLog(scan, `\x1b[36mTarget Domain   :\x1b[0m ${domain}`);
  appendLog(scan, `\x1b[36mMode            :\x1b[0m Passive Enumeration + Active Service Probing`);
  appendLog(scan, `\x1b[36mArtifacts Path  :\x1b[0m output/${domain}`);
  appendLog(scan, `-----------------------------------------------------------`);

  // Stage 1: Scope Validation & Network Resolver Verification
  scan.step = 1;
  scan.currentAction = 'Validating Scope & Initializing Resolvers';
  appendLog(scan, `[1/6] Validating Target Scope & Network Resolvers...`);

  let resolverActive = false;
  try {
    const testResolve = await dns.resolve4('dns.google').catch(() => dns.resolve4('cloudflare.com'));
    if (testResolve && testResolve.length > 0) {
      resolverActive = true;
      appendLog(scan, `      System DNS Resolvers: Active and responsive \x1b[32m✓\x1b[0m`);
    }
  } catch {
    appendLog(scan, `      System DNS Resolvers: \x1b[33mWarning - high latency or limited connectivity\x1b[0m`);
  }

  // Stage 2: Certificate Transparency Logs (crt.sh API)
  scan.step = 2;
  scan.currentAction = 'Querying Certificate Transparency Logs';
  appendLog(scan, `[2/6] Querying Certificate Transparency (crt.sh API)... `);
  const crtResult = await queryCrtSh(domain);
  if (crtResult.error) {
    appendLog(scan, `      crt.sh: \x1b[33m${crtResult.error}\x1b[0m (0 records)`);
  } else {
    appendLog(scan, `      crt.sh: ${crtResult.records.length} records discovered \x1b[32m✓\x1b[0m`);
  }

  // Stage 3: Passive Threat Intelligence & DNS Feeds
  scan.step = 3;
  scan.currentAction = 'Querying Passive Threat Intel & DNS Feeds';
  appendLog(scan, `[3/6] Querying Passive DNS Feeds (AlienVault OTX & HackerTarget)... `);

  const [otxResult, htResult, wildcardCheck] = await Promise.all([
    queryAlienVaultOTX(domain),
    queryHackerTarget(domain),
    detectWildcardDNS(domain),
  ]);

  appendLog(scan, `      AlienVault OTX: ${otxResult.records.length} records ${otxResult.error ? `\x1b[33m(${otxResult.error})\x1b[0m` : '\x1b[32m✓\x1b[0m'}`);
  appendLog(scan, `      HackerTarget  : ${htResult.records.length} records ${htResult.error ? `\x1b[33m(${htResult.error})\x1b[0m` : '\x1b[32m✓\x1b[0m'}`);

  let dictionaryRecords = [];
  const wildcardIpsSet = new Set(wildcardCheck.wildcardIps);

  if (wildcardCheck.hasWildcard) {
    appendLog(scan, `      \x1b[33m[Notice] Wildcard DNS active (*.${domain} -> ${wildcardCheck.wildcardIps.join(', ')})\x1b[0m`);
    appendLog(scan, `      Dictionary guessing bypassed to eliminate false-positive floods.`);
    appendLog(scan, `      Preserving all verified passive records (historical CT logs & OSINT feeds).`);
  } else {
    dictionaryRecords = await resolveCommonSubdomains(domain);
    if (dictionaryRecords.length > 0) {
      appendLog(scan, `      Active DNS Resolvers: ${dictionaryRecords.length} active prefixes verified \x1b[32m✓\x1b[0m`);
    }
  }

  // Stage 4: Deduplication & Normalization
  scan.step = 4;
  scan.currentAction = 'Deduplicating & Normalizing Attack Surface';
  appendLog(scan, `[4/6] Deduplicating & Normalizing Target List... `);

  // Passive records from crt.sh, AlienVault OTX, and HackerTarget represent cryptographic or observable evidence.
  // We keep all passive records even if their current IP equals the wildcard IP, discarding only speculative dictionary guesses.
  const combined = Array.from(new Set([
    domain,
    ...crtResult.records,
    ...otxResult.records,
    ...htResult.records,
    ...dictionaryRecords,
  ])).sort();

  scan.subdomains = combined;
  scan.totalSubdomains = combined.length;
  appendLog(scan, `      Unique attack surface targets: ${scan.totalSubdomains} \x1b[32m✓\x1b[0m`);

  // Stage 5: Active HTTP/TLS Probing & SSRF Defense
  scan.step = 5;
  scan.currentAction = 'Probing Live HTTP/TLS Services';
  appendLog(scan, `[5/6] Probing Live HTTP/TLS Services & Checking SSRF Safeguards... `);

  const aliveList = [];
  const batchSize = 6;
  for (let i = 0; i < combined.length; i += batchSize) {
    const chunk = combined.slice(i, i + batchSize);
    const results = await Promise.all(chunk.map((sub) => probeLiveHost(sub)));
    for (const r of results) {
      if (r) {
        aliveList.push(r);
        const logLine = r.internalLeak || r.ssrfBlocked
          ? `      [INTERNAL IP LEAK / SSRF BLOCKED] ${r.subdomain} (Resolves to private IP: ${r.ip})`
          : `      [ALIVE] ${r.url} [Status: ${r.statusCode || 'DNS'}] [${r.latencyMs}ms] ${r.title ? `"${r.title}"` : ''}`;
        appendLog(scan, logLine);
      }
    }
    scan.aliveHosts = [...aliveList];
    scan.aliveCount = aliveList.length;
    broadcastScanUpdate(scan.id, scan);
  }

  appendLog(scan, `      Live services verified: ${aliveList.length} \x1b[32m✓\x1b[0m`);

  // Stage 6: Report Compilation & Artifact Generation
  scan.step = 6;
  scan.currentAction = 'Generating Summary & Reports';
  appendLog(scan, `[6/6] Generating Summary, Markdown Report & Audit Logs... `);

  const endSec = Math.floor(Date.now() / 1000);
  const timeTaken = Math.max(1, endSec - startSec);
  const dateStr = new Date().toUTCString();

  scan.endTime = Date.now();
  scan.executionTime = timeTaken;

  const summaryTxt = `===================================================
ReconForge Reconnaissance Summary v2.1
===================================================

Target Domain       : ${domain}
Unique Subdomains   : ${scan.totalSubdomains}
Live HTTP Services  : ${scan.aliveCount}
Execution Time      : ${timeTaken} seconds
Generated At        : ${dateStr}

Sources Consulted:
- Certificate Transparency (crt.sh): ${crtResult.records.length} records
- AlienVault OTX Passive DNS       : ${otxResult.records.length} records
- HackerTarget Host Search         : ${htResult.records.length} records
- DNS Resolvers Verified           : ${dictionaryRecords.length} records
- Wildcard DNS Detected            : ${wildcardCheck.hasWildcard ? 'YES' : 'NO'}

===================================================`;

  const reportMd = `# ReconForge Reconnaissance Report

## Executive Summary

| Parameter | Value |
|-----------|-------|
| Target Domain | \`${domain}\` |
| Total Subdomains | **${scan.totalSubdomains}** |
| Live Responding Services | **${scan.aliveCount}** |
| Execution Time | ${timeTaken} seconds |
| Wildcard DNS | ${wildcardCheck.hasWildcard ? 'Active' : 'Disabled'} |
| Date | ${dateStr} |

---

## Output Artifacts

- \`output/${domain}/subdomains.txt\`
- \`output/${domain}/alive.txt\`
- \`output/${domain}/summary.txt\`

---

## Discovered Live Applications

| URL | Status | Latency | IP Address | Technologies | Title | Takeover Risk |
|-----|--------|---------|------------|--------------|-------|---------------|
${aliveList.map(h => `| ${h.url} | ${h.statusCode || 'DNS'} | ${h.latencyMs}ms | ${h.ip || 'N/A'} | ${(h.techStack || []).join(', ') || 'Web Server'} | ${(h.title || '').replace(/\|/g, '-')} | ${h.takeoverRisk ? `${h.takeoverRisk.service} (${h.takeoverRisk.severity})` : 'None'} |`).join('\n')}

---

Generated by ReconForge v2.1
`;

  const subdomainsTxt = combined.join('\n');
  const aliveTxt = aliveList.map(h => h.url).join('\n');
  const reconLog = `==================================================

${dateStr}

Target          : ${domain}
Total Targets   : ${scan.totalSubdomains}
Live Services   : ${scan.aliveCount}
Execution Time  : ${timeTaken} seconds
Status          : SUCCESS

==================================================
`;

  scan.files = {
    subdomainsTxt,
    aliveTxt,
    summaryTxt,
    reportMd,
    reconLog,
  };

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
  appendLog(scan, `Live Services      : ${scan.aliveCount}`);
  appendLog(scan, `Execution Time     : ${timeTaken} seconds`);
  appendLog(scan, `===========================================================`);
  appendLog(scan, `Completed.`);
  appendLog(scan, `===========================================================`);

  scan.status = 'completed';
  broadcastScanUpdate(scan.id, scan);

  // Close SSE streams cleanly so client immediately transitions
  const clients = sseClients.get(scan.id) || [];
  for (const client of clients) {
    try {
      client.end();
    } catch {
      // ignore
    }
  }
  sseClients.delete(scan.id);
}

// API Routes
app.post('/api/recon/start', async (req, res) => {
  // Session token validation strictly via header prevents Cross-Origin Scanner Hijacking
  const clientToken = req.headers['x-reconforge-session'];
  if (!isTokenValid(clientToken)) {
    return res.status(403).json({
      error: 'Forbidden: Missing or invalid x-reconforge-session header. Scanner hijacking protection active.',
    });
  }

  // Concurrency throttle: prevent background resource exhaustion
  let activeRunningCount = 0;
  for (const s of scans.values()) {
    if (s.status === 'running') activeRunningCount++;
  }
  if (activeRunningCount >= MAX_CONCURRENT_RUNNING) {
    return res.status(429).json({
      error: `Too Many Requests: Maximum concurrent active scans reached (${MAX_CONCURRENT_RUNNING}). Please wait for an active scan to complete.`,
    });
  }

  const rawDomain = req.body?.domain;
  if (!rawDomain) {
    return res.status(400).json({ error: 'Target domain is required (e.g. example.com)' });
  }

  const domain = sanitizeDomain(String(rawDomain));
  if (!isValidDomain(domain)) {
    return res.status(400).json({ error: 'Invalid domain syntax. Examples: example.com, hackerone.com' });
  }

  const scanId = `scan_${domain.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}`;
  const scanData = {
    id: scanId,
    domain,
    status: 'running',
    startTime: Date.now(),
    step: 0,
    currentAction: 'Initializing scope',
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

  storeScan(scanId, scanData);

  executeReconWorkflow(scanData).catch((err) => {
    console.error('Workflow error:', err);
    scanData.status = 'failed';
    scanData.error = err?.message || 'Workflow execution error';
    appendLog(scanData, `\x1b[31m[ERROR] Scan failed: ${scanData.error}\x1b[0m`);
    broadcastScanUpdate(scanData.id, scanData);
  });

  return res.json({ scanId, domain, status: 'running' });
});

// Read Endpoints: Protected by Inbound Host Header validation (preventing DNS rebinding)
// and strict CORS exact-origin matching (enforcing browser Same-Origin Policy isolation).
app.get('/api/recon/stream/:scanId', (req, res) => {
  const { scanId } = req.params;
  const scan = getScan(scanId);

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

  // Send initial full scan state upon connection
  res.write(`data: ${JSON.stringify(scan)}\n\n`);

  req.on('close', () => {
    const list = sseClients.get(scanId) || [];
    sseClients.set(scanId, list.filter(c => c !== res));
  });
});

app.get('/api/recon/scan/:scanId', (req, res) => {
  const { scanId } = req.params;
  const scan = getScan(scanId);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  return res.json(scan);
});

app.get('/api/recon/history', (_req, res) => {
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

app.get('/api/recon/download/:scanId/:fileType', (req, res) => {
  const { scanId, fileType } = req.params;
  const scan = getScan(scanId);
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

export { app };

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

  app.listen(PORT, BIND_HOST, () => {
    console.log(`ReconForge Server running at http://${BIND_HOST}:${PORT}`);
  });
}

if (process.env.NODE_ENV !== 'test') {
  startServer();
}
