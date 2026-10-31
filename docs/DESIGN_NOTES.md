# ReconForge Architecture & Security Design Notes

This document captures deep technical rationale, architectural trade-offs, and answers to core security engineering questions regarding the ReconForge v2.1 scanning engine.

---

## 1. Core Architectural & Security Questions

### Q1: Why does a pre-check in `probeLiveHost` alone not stop DNS rebinding?

**Answer**: Because of the Time-of-Check to Time-of-Use (TOCTOU) gap.

When an adversary operates an authoritative DNS server for their domain (e.g. `rebind.attacker.com`), they configure the nameserver to return a benign public IP address (such as `93.184.216.34`) with a Time-To-Live (TTL) of 0 seconds.

If an application uses a pre-check pattern:
1. `dns.resolve4('rebind.attacker.com')` queries the DNS server and receives `93.184.216.34`.
2. The application checks `isPrivateOrReservedIp('93.184.216.34')`, which evaluates to `false` (safe).
3. The application executes `http.request('http://rebind.attacker.com')`.
4. Because the TTL was 0, Node.js's internal networking layer performs a second, fresh DNS resolution to establish the TCP socket.
5. The attacker's nameserver now returns `169.254.169.254` (Cloud IMDS) or `127.0.0.1`.
6. Node.js sends the TCP SYN packet to `169.254.169.254` or `127.0.0.1`, completely bypassing the pre-check.

#### The Fix
Validation must occur at the moment of socket establishment. In Node.js, `http.request` and `https.request` accept a custom `lookup` option (`ssrfSafeLookup`). This hook intercepts the exact IP addresses returned by the operating system resolver right before the TCP handshake. Every resolved `A` and `AAAA` address is validated against `net.BlockList`. If any address is in a private or reserved range, the connection is aborted (`ERR_SSRF_BLOCKED`) before any TCP SYN packet leaves the host. Furthermore, direct IP literals in URLs (where Node skips DNS lookup) are checked immediately before socket creation.

---

### Q2: Why does CORS not stop a client on your LAN?

**Answer**: CORS (Cross-Origin Resource Sharing) is an in-browser security mechanism enforced exclusively by web browsers when JavaScript running on an origin initiates a cross-origin HTTP request.

CORS does not protect network listeners from non-browser clients:
1. **No Browser Sandbox**: A compromised machine, mobile device, or rogue IoT sensor on the local area network sends raw TCP packets directly to the daemon's port. They do not send an `Origin` header, or they send arbitrary headers.
2. **Attacker-Controlled Scripts**: Non-browser HTTP clients (`curl`, Python `requests`, Go, raw sockets) ignore CORS headers completely.
3. **LAN Access vs Loopback**: If a server binds to `0.0.0.0`, it accepts connections on all network interfaces, including Ethernet and Wi-Fi.

#### The Fix
Defense against unauthorized local and network access requires defense-in-depth:
1. **Loopback Default Binding**: The daemon binds strictly to `127.0.0.1` by default, refusing connections from external network interfaces unless explicitly configured with `HOST=0.0.0.0`.
2. **Inbound DNS Rebinding Defense**: The server inspects the HTTP `Host` header on all `/api` endpoints against an explicit set of authorized hostnames (`isValidHostHeader`). If an attacker tricks a victim's browser into resolving `evil.com` to `127.0.0.1:3000`, the browser sends `Host: evil.com`, which is rejected with `403 Forbidden`.
3. **Session Token Authorization**: Mutating operations (`POST /api/recon/start`) require a cryptographically random session token (`x-reconforge-session`) validated using constant-time comparison (`crypto.timingSafeEqual`).

---

### Q3: Why is a passive record under a wildcard zone still evidence?

**Answer**: Wildcard DNS (`*.target.com IN A 192.0.2.1`) is a zone-level catch-all routing rule where any arbitrary, non-existent label resolves to that IP address.

Dictionary brute-force guesses (`mail.target.com`, `admin.target.com`, `random123.target.com`) are speculative hypotheses. When a wildcard zone is present, 100% of guessed words resolve, creating false positives.

However, **passive records harvested from Certificate Transparency (CT) logs (`crt.sh`) or historical passive DNS telemetry represent cryptographic and empirical evidence**:
1. **Certificate Transparency**: An entry in a CT log proves that an authorized Certificate Authority issued an authentic X.509 certificate for that exact Fully Qualified Domain Name (FQDN). Domain validation (DV/OV/EV) was completed at issuance time.
2. **Telemetry Evidence**: Passive DNS sensors observed actual network traffic querying and resolving that hostname in the past.
3. **Shared Infrastructure**: It is common in cloud and CDN environments (e.g. Cloudflare, CloudFront, Fastly) for real subdomains and wildcard fallbacks to resolve to the same anycast IP range.

#### The Fix
A sound recon engine must not discard passive records simply because their resolved IP matches the wildcard canary. Instead, ReconForge detects wildcards using canary labels (`_wildcard_v4_<rand>` and `_wildcard_v6_<rand>`) across both IPv4 and IPv6, bypasses speculative dictionary guessing to prevent false-positive floods, and preserves all verified cryptographic passive records for active probing and risk evaluation.

---

## 2. In-Memory Store & LRU Eviction

ReconForge uses an in-memory `Map` with a maximum capacity of 30 scans to balance session continuity with memory bounds.

- **True LRU Semantics**: On every read (`getScan`), the accessed scan key is deleted and re-inserted into the `Map`, refreshing its position to the most recently used end of the iteration order.
- **Protection of Active Scans**: When the map exceeds capacity, the eviction routine iterates from oldest to newest and evicts the first scan whose `status !== 'running'`. Running scans are protected from eviction during multi-stage reconnaissance.
- **SSE Connection Cleanup**: When a scan is evicted, any open Server-Sent Events HTTP connections associated with that scan ID are cleanly terminated (`client.end()`) to avoid orphaned socket leaks.
