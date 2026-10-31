# Security Policy & Threat Model

ReconForge is an automated subdomain reconnaissance and service probing tool designed for authorized penetration testing, bug bounty hunting, and attack surface management. Because network scanners actively probe target infrastructure, they inherently touch sensitive network boundaries and must defend against weaponized DNS responses, SSRF (Server-Side Request Forgery), and uncontrolled query loops.

---

## 1. Threat Model & Mitigations

### 1.1 Server-Side Request Forgery (SSRF) & Cloud IMDS Theft

#### The Vulnerability
When actively probing discovered subdomains via HTTP/HTTPS (`probeLiveHost`), an adversary controlling DNS records for a target domain (or a malicious user scanning their own rogue domain) could configure a subdomain's `A` or `AAAA` record to point to:
1. **Cloud Instance Metadata Service (IMDS)**: `169.254.169.254` (AWS EC2, GCP metadata, Azure instance metadata).
2. **Local Loopback**: `127.0.0.1` or `127.0.0.0/8`, `::1`.
3. **Internal RFC 1918 Subnets**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.

#### Execution Trace Without Protection
If a target subdomain `rogue.target.com` resolves to `169.254.169.254`:
1. `dns.resolve4('rogue.target.com')` returns `['169.254.169.254']`.
2. Without pre-flight validation, `safeHttpRequest('https://rogue.target.com')` initiates a TCP handshake to `169.254.169.254:443` or `http://169.254.169.254:80`.
3. If deployed on AWS/GCP, the scanner's Node.js process could inadvertently read instance IAM credentials, service account tokens, or project metadata and surface them in the UI response body or logs.

#### ReconForge Mitigation
Before any HTTP/HTTPS socket is opened, ReconForge executes `isPrivateOrReservedIp(primaryIp)`:
```javascript
// SSRF Safeguard in probeLiveHost (server.js)
if (primaryIp && isPrivateOrReservedIp(primaryIp)) {
  return {
    url: `http://${subdomain}`,
    subdomain,
    statusCode: 0,
    latencyMs: dnsTime,
    ip: primaryIp,
    category: 'internal',
    techStack: ['Internal IP (SSRF Blocked)'],
    ssrfBlocked: true,
  };
}
```
All outbound socket connections to `169.254.0.0/16`, `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, and IPv6 `::1`/`fe80::/10` are dropped before request dispatch.

---

### 1.2 Wildcard DNS False-Positive Cascades

#### The Vulnerability
If an organization configures a wildcard DNS record (`*.target.com IN A 192.0.2.1`), any query for a non-existent subdomain (e.g. `nonexistent123.target.com`) resolves successfully. 

When a scanner runs a dictionary of common prefixes (e.g. `admin`, `api`, `vpn`, `dev`, `portal`), all 25+ prefixes return positive resolutions. Without wildcard detection, the scanner pollutes the attack surface with 25 false-positive entries and fires unnecessary HTTP probes at the same wildcard web server.

#### ReconForge Mitigation
Before resolving dictionary prefixes, ReconForge executes an automated pre-flight probe using a cryptographically randomized label:
```javascript
export async function detectWildcardDNS(domain) {
  const randomSuffix = crypto.randomBytes(4).toString('hex');
  const testHost = `_wildcard_check_${randomSuffix}.${domain}`;
  try {
    const ips = await dns.resolve4(testHost);
    if (ips && ips.length > 0) {
      return { hasWildcard: true, wildcardIps: ips };
    }
  } catch {
    // Expected NXDOMAIN
  }
  return { hasWildcard: false, wildcardIps: [] };
}
```
If the wildcard probe resolves, dictionary guessing is automatically bypassed, a clear audit notice is logged in the UI terminal, and only legitimate passive records are retained.

---

### 1.3 Localhost Binding & Cross-Origin Safety

- **Local Host Binding**: When operated in desktop app mode, the Node.js server binds to `127.0.0.1` by default to prevent unauthorized network neighbors on shared Wi-Fi from querying local scans.
- **Strict Domain Validation**: Input domains are normalized and validated against RFC 1035 format and internationalized Punycode labels (`xn--...`), preventing command injection or directory traversal in report paths.

---

### 1.4 TLS Handshake Resilience

Security auditors routinely encounter internal services with self-signed, expired, or hostname-mismatched SSL/TLS certificates. Standard HTTP clients reject these connections with `ERR_TLS_CERT_ALTNAME_INVALID` or `DEPTH_ZERO_SELF_SIGNED_CERT`, prematurely dropping valid active web assets.

ReconForge uses an HTTPS agent configured with `rejectUnauthorized: false` exclusively for asset discovery, ensuring valid servers with outdated certs are surfaced while strictly retaining SSRF IP blocking.

---

## 2. Responsible Disclosure Policy

If you discover a vulnerability within ReconForge:
1. Please report it privately by opening a security advisory or contacting the maintainer directly.
2. Provide a reproduction script or proof of concept.
3. We will respond within 48 hours and work with you on a coordinated fix.

---

## 3. Permitted & Authorized Use

ReconForge sends active network requests (DNS queries and HTTP/HTTPS GET requests) during stage 5. **You must only scan domain names you own or have explicit written permission to assess under an authorized bug bounty program or penetration testing engagement.**
