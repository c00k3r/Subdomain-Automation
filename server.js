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
const BIND_HOST = process.env.HOST || '0.0.0.0';
const isProd = process.env.NODE_ENV === 'production';

// Strict CORS Origin Policy: Permits local addresses, Cloud Run preview domains (*.run.app),
// Google AI Studio infrastructure, and web container environments.
export function isAllowedOrigin(origin) {
  // Allow non-browser requests (CLI, curl, server-to-server)
  if (!origin) return true;

  try {
    const url = new URL(origin);
    const host = url.hostname.toLowerCase();

    // 1. Localhost and loopback bindings (any port)
    if (
      host === 'localhost' ||
      host === '127.0.0.1' ||
      host === '0.0.0.0' ||
      host.endsWith('.localhost')
    ) {
      return true;
    }

    // 2. Google Cloud Run preview and deployment domains (*.run.app)
    if (host === 'run.app' || host.endsWith('.run.app')) {
      return true;
    }

    // 3. Google AI Studio, Google infrastructure, and web containers
    if (
      host.endsWith('.google.com') ||
      host.endsWith('.googleusercontent.com') ||
      host.endsWith('.webcontainer.io') ||
      host.includes('aistudio')
    ) {
      return true;
    }

    return false;
  } catch {
    return false;
  }
}

app.use(cors({
  origin: (origin, callback) => {
    if (isAllowedOrigin(origin)) {
      callback(null, true);
    } else {
      // Per CORS spec: withhold allow headers without crashing Express middleware
      callback(null, false);
    }
  },
  credentials: true,
}));

app.use(express.json());

// In-memory store for active and past user scans with LRU/bounded eviction
const MAX_SCANS = 30;
const scans = new Map();
const sseClients = new Map();

function storeScan(scanId, scanData) {
  if (scans.size >= MAX_SCANS) {
    const oldestKey = scans.keys().next().value;
    if (oldestKey) {
      scans.delete(oldestKey);
      const clients = sseClients.get(oldestKey) || [];
      for (const client of clients) {
        try { client.end(); } catch {}
      }
      sseClients.delete(oldestKey);
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
  broadcastScanUpdate(scan.id, scan);
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

// Evaluates an IP against RFC ranges with normalization for IPv4-mapped IPv6
export function isPrivateOrReservedIp(ip) {
  if (!ip || typeof ip !== 'string') return false;
  const clean = ip.trim().toLowerCase();

  // Normalize IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 or ::ffff:7f00:0001)
  if (clean.startsWith('::ffff:')) {
    const after = clean.slice(7);
    if (net.isIP(after) === 4) {
      return ipBlockList.check(after, 'ipv4');
    }
    const hexParts = after.split(':');
    if (hexParts.length === 2 && hexParts.every(p => /^[0-9a-f]{1,4}$/i.test(p))) {
      const num1 = parseInt(hexParts[0], 16);
      const num2 = parseInt(hexParts[1], 16);
      const b0 = (num1 >> 8) & 0xff;
      const b1 = num1 & 0xff;
      const b2 = (num2 >> 8) & 0xff;
      const b3 = num2 & 0xff;
      const v4 = `${b0}.${b1}.${b2}.${b3}`;
      return ipBlockList.check(v4, 'ipv4');
    }
  }

  const ver = net.isIP(clean);
  if (ver === 4) {
    return ipBlockList.check(clean, 'ipv4');
  } else if (ver === 6) {
    return ipBlockList.check(clean, 'ipv6');
  }

  return false;
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
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconForge/2.0',
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

// 4. Wildcard DNS Pre-Check: Probes a random non-existent subdomain to prevent false positive bursts
export async function detectWildcardDNS(domain, resolverFn = dns.resolve4) {
  const randomSuffix = crypto.randomBytes(4).toString('hex');
  const testHost = `_wildcard_check_${randomSuffix}.${domain}`;
  try {
    const ips = await resolverFn(testHost);
    if (ips && ips.length > 0) {
      return { hasWildcard: true, wildcardIps: ips };
    }
  } catch {
    // Expected behavior: NXDOMAIN / ENOTFOUND
  }
  return { hasWildcard: false, wildcardIps: [] };
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
    confirmedReason: 'Dangling CNAME points to unclaimed GitHub Pages repository.',
    remediation: 'Claim the GitHub repository or delete the stale DNS CNAME entry.',
  },
  {
    service: 'Amazon S3',
    cnameSuffixes: ['.s3.amazonaws.com', '.s3-website', '.amazonaws.com'],
    fingerprints: [
      'the specified bucket does not exist',
      'nosuchbucket',
    ],
    severity: 'CRITICAL',
    confirmedReason: 'Dangling CNAME points to deleted or unregistered S3 bucket.',
    remediation: 'Claim the S3 bucket in your AWS account or delete the CNAME record.',
  },
  {
    service: 'Heroku',
    cnameSuffixes: ['.herokudns.com', '.herokuapp.com'],
    fingerprints: [
      'herokucdn.com',
      'no such app',
    ],
    severity: 'HIGH',
    confirmedReason: 'Dangling CNAME points to released Heroku application.',
    remediation: 'Claim the Heroku app name or remove DNS record.',
  },
  {
    service: 'Zendesk',
    cnameSuffixes: ['.zendesk.com'],
    fingerprints: [
      'help center closed',
      'no such sub-domain',
    ],
    severity: 'MEDIUM',
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
    confirmedReason: 'Dangling CNAME points to unclaimed Surge domain.',
    remediation: 'Publish project to Surge or remove DNS record.',
  },
];

export async function checkTakeoverRisk(subdomain, statusCode, body = '', cnameResolverFn = dns.resolveCname) {
  if (statusCode !== 404 && statusCode !== 0) return null;
  const b = body.toLowerCase();

  let cnames = [];
  try {
    cnames = await cnameResolverFn(subdomain);
  } catch {
    // No CNAME record present
  }

  const primaryCname = (cnames[0] || '').toLowerCase();

  for (const item of TAKEOVER_SERVICES) {
    const bodyMatches = item.fingerprints.some(fp => b.includes(fp));
    const cnameMatches = primaryCname && item.cnameSuffixes.some(suffix => primaryCname.endsWith(suffix) || primaryCname.includes(suffix));

    if (bodyMatches && cnameMatches) {
      return {
        isVulnerable: true,
        isConfirmed: true,
        service: item.service,
        cname: primaryCname,
        severity: item.severity,
        reason: `Dangling CNAME (${primaryCname}) points to unclaimed ${item.service} resource.`,
        remediation: item.remediation,
      };
    } else if (bodyMatches) {
      return {
        isVulnerable: true,
        isConfirmed: false,
        service: `${item.service} (Possible)`,
        cname: primaryCname || 'None resolved',
        severity: 'LOW',
        reason: `HTTP response contains ${item.service} error string, but CNAME record is unconfirmed or not pointing to provider.`,
        remediation: 'Verify whether a DNS record or routing rule points to this service.',
      };
    }
  }

  return null;
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

  // SSRF Pre-check (also validated at socket connect time via ssrfSafeLookup)
  if (primaryIp && isPrivateOrReservedIp(primaryIp)) {
    return {
      url: `http://${subdomain}`,
      subdomain,
      statusCode: 0,
      title: '',
      latencyMs: dnsTime,
      ip: primaryIp,
      ipv6: ip6,
      category,
      techStack: ['Internal IP (SSRF Blocked)'],
      takeoverRisk: null,
      ssrfBlocked: true,
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
        return {
          url: targetUrl,
          subdomain,
          statusCode: 0,
          title: '',
          latencyMs: 0,
          ip: primaryIp,
          ipv6: ip6,
          category,
          techStack: ['Internal IP (SSRF Blocked via Rebinding Protection)'],
          takeoverRisk: null,
          ssrfBlocked: true,
        };
      }
      // try next protocol
    }
  }

  // If DNS resolved but HTTP ports are unreachable
  if (primaryIp) {
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
  appendLog(scan, `\x1b[34m        ReconForge Automation Engine v2.0                  \x1b[0m`);
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
    appendLog(scan, `      Dictionary guessing bypassed; passive hits matching wildcard IPs will be filtered.`);
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

  const rawList = Array.from(new Set([
    domain,
    ...crtResult.records,
    ...otxResult.records,
    ...htResult.records,
    ...dictionaryRecords,
  ])).sort();

  // If wildcard active, filter passive records that resolve exclusively to wildcard IPs
  let combined = rawList;
  if (wildcardCheck.hasWildcard && wildcardIpsSet.size > 0) {
    const filtered = [];
    let wildcardFilteredCount = 0;
    for (let i = 0; i < rawList.length; i += 8) {
      const slice = rawList.slice(i, i + 8);
      await Promise.all(slice.map(async (host) => {
        if (host === domain) {
          filtered.push(host);
          return;
        }
        try {
          const ips = await dns.resolve4(host);
          const isWildcardHit = ips.length > 0 && ips.every(ip => wildcardIpsSet.has(ip));
          if (!isWildcardHit) {
            filtered.push(host);
          } else {
            wildcardFilteredCount++;
          }
        } catch {
          filtered.push(host);
        }
      }));
    }
    combined = filtered.sort();
    if (wildcardFilteredCount > 0) {
      appendLog(scan, `      Filtered ${wildcardFilteredCount} passive records matching wildcard IPs.`);
    }
  }

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
        const logLine = r.ssrfBlocked
          ? `      [SSRF BLOCKED] ${r.subdomain} (Points to private IP: ${r.ip})`
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
ReconForge Reconnaissance Summary v2.0
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

Generated by ReconForge v2.0
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
  });

  return res.json({ scanId, domain, status: 'running' });
});

app.get('/api/recon/stream/:scanId', (req, res) => {
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

  res.write(`data: ${JSON.stringify(scan)}\n\n`);

  req.on('close', () => {
    const list = sseClients.get(scanId) || [];
    sseClients.set(scanId, list.filter(c => c !== res));
  });
});

app.get('/api/recon/scan/:scanId', (req, res) => {
  const { scanId } = req.params;
  const scan = scans.get(scanId);
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
