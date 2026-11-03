import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  app,
  createApp,
  sanitizeDomain,
  isValidDomain,
  isPrivateOrReservedIp,
  detectWildcardDNS,
  checkTakeoverRisk,
  classifyIpRisk,
  isAllowedOrigin,
  isValidHostHeader,
  safeHttpRequest,
  isTokenValid,
  SESSION_TOKEN,
  scans,
  storeScan,
  getScan,
  MAX_SCANS,
} from '../server.js';

test('sanitizeDomain - normalizes raw user inputs', () => {
  assert.equal(sanitizeDomain('https://example.com/'), 'example.com');
  assert.equal(sanitizeDomain('http://sub.example.com:8080/path?q=1'), 'sub.example.com');
  assert.equal(sanitizeDomain('  EXAMPLE.COM  '), 'example.com');
  assert.equal(sanitizeDomain('target.org:443'), 'target.org');
  assert.equal(sanitizeDomain(''), '');
});

test('isValidDomain - strictly validates FQDNs and Punycode IDNs', () => {
  // Valid domains
  assert.equal(isValidDomain('example.com'), true);
  assert.equal(isValidDomain('sub.example.com'), true);
  assert.equal(isValidDomain('deep.nested.sub.domain.co.uk'), true);
  assert.equal(isValidDomain('xn--80akhbyknj4f.com'), true); // Punycode
  assert.equal(isValidDomain('target-corp.io'), true);

  // Invalid domains
  assert.equal(isValidDomain(''), false);
  assert.equal(isValidDomain('   '), false);
  assert.equal(isValidDomain('localhost'), false);
  assert.equal(isValidDomain('192.168.1.1'), false);
  assert.equal(isValidDomain('example..com'), false);
  assert.equal(isValidDomain('http://example.com'), false);
  assert.equal(isValidDomain('-invalid.com'), false);
  assert.equal(isValidDomain('invalid-.com'), false);
  assert.equal(isValidDomain('example.c'), false); // TLD too short (<2 chars)
  assert.equal(isValidDomain('a'.repeat(255) + '.com'), false); // Exceeds 253 max RFC length
});

test('Invariant: isValidDomain rejects IP literals so Node never skips the lookup hook', () => {
  const ipLiterals = [
    '127.0.0.1',
    '169.254.169.254',
    '10.0.0.1',
    '172.16.0.1',
    '192.168.1.1',
    '8.8.8.8',
    '0.0.0.0',
    '::1',
    'fe80::1',
    '2606:4700:4700::1111',
  ];
  for (const ip of ipLiterals) {
    assert.equal(isValidDomain(ip), false, `isValidDomain must reject IP literal ${ip}`);
  }
});

test('isPrivateOrReservedIp - fails closed on invalid input and blocks all SSRF vectors', () => {
  // 1. Fail-closed on invalid/garbage inputs
  assert.equal(isPrivateOrReservedIp('garbage'), true, 'Fail closed: garbage string must be blocked');
  assert.equal(isPrivateOrReservedIp(''), true, 'Fail closed: empty string must be blocked');
  assert.equal(isPrivateOrReservedIp(null), true, 'Fail closed: null must be blocked');
  assert.equal(isPrivateOrReservedIp(undefined), true, 'Fail closed: undefined must be blocked');
  assert.equal(isPrivateOrReservedIp('not-an-ip.com'), true, 'Fail closed: non-ip hostname must be blocked');

  // 2. IPv4-mapped IPv6 bypass vectors (::ffff:)
  assert.equal(isPrivateOrReservedIp('::ffff:127.0.0.1'), true, 'Must block ::ffff:127.0.0.1');
  assert.equal(isPrivateOrReservedIp('::ffff:169.254.169.254'), true, 'Must block ::ffff:169.254.169.254');
  assert.equal(isPrivateOrReservedIp('::ffff:7f00:1'), true, 'Must block hex ::ffff:7f00:1');
  assert.equal(isPrivateOrReservedIp('::ffff:8.8.8.8'), false, 'Public IPv4 in ::ffff: must be allowed');

  // 3. NAT64 Well-Known Prefix (64:ff9b::/96)
  assert.equal(isPrivateOrReservedIp('64:ff9b::7f00:1'), true, 'Must block loopback in NAT64 (64:ff9b::7f00:1)');
  assert.equal(isPrivateOrReservedIp('64:ff9b::127.0.0.1'), true, 'Must block 127.0.0.1 in NAT64');
  assert.equal(isPrivateOrReservedIp('64:ff9b::a00:1'), true, 'Must block 10.0.0.1 in NAT64');
  assert.equal(isPrivateOrReservedIp('64:ff9b::808:808'), false, 'Public 8.8.8.8 in NAT64 must be allowed');

  // 4. 6to4 Encapsulation (2002::/16)
  assert.equal(isPrivateOrReservedIp('2002:7f00:1::1'), true, 'Must block loopback in 6to4 (2002:7f00:1::1)');
  assert.equal(isPrivateOrReservedIp('2002:a00:1::1'), true, 'Must block 10.0.0.1 in 6to4');
  assert.equal(isPrivateOrReservedIp('2002:808:808::1'), false, 'Public 8.8.8.8 in 6to4 must be allowed');

  // 5. IPv4-compatible IPv6 (::/96)
  assert.equal(isPrivateOrReservedIp('::7f00:1'), true, 'Must block loopback in IPv4-compatible (::7f00:1)');
  assert.equal(isPrivateOrReservedIp('::127.0.0.1'), true, 'Must block ::127.0.0.1');
  assert.equal(isPrivateOrReservedIp('::'), true, 'Must block :: unspecified address');
  assert.equal(isPrivateOrReservedIp('::1'), true, 'Must block ::1 loopback');
  assert.equal(isPrivateOrReservedIp('0:0:0:0:0:0:0:1'), true, 'Must block uncompressed ::1');

  // 6. Unique Local Address (fc00::/7) full CIDR range
  assert.equal(isPrivateOrReservedIp('fd12:3456::1'), true, 'Must block fd12:3456::1 (fc00::/7)');
  assert.equal(isPrivateOrReservedIp('fc00::1'), true, 'Must block fc00::1');

  // 7. Link-Local Unicast (fe80::/10) full CIDR range
  assert.equal(isPrivateOrReservedIp('fe90::1'), true, 'Must block fe90::1 (fe80::/10)');
  assert.equal(isPrivateOrReservedIp('fe80::1'), true, 'Must block fe80::1');

  // 8. Multicast and benchmark subnets
  assert.equal(isPrivateOrReservedIp('224.0.0.1'), true, 'Must block 224.0.0.1 (multicast 224.0.0.0/4)');
  assert.equal(isPrivateOrReservedIp('198.18.0.1'), true, 'Must block 198.18.0.1 (benchmark 198.18.0.0/15)');
  assert.equal(isPrivateOrReservedIp('192.0.0.1'), true, 'Must block 192.0.0.1 (IETF assignment 192.0.0.0/24)');

  // 9. Traditional RFC 1918, IMDS, and loopbacks
  assert.equal(isPrivateOrReservedIp('127.0.0.1'), true);
  assert.equal(isPrivateOrReservedIp('169.254.169.254'), true);
  assert.equal(isPrivateOrReservedIp('10.0.0.1'), true);
  assert.equal(isPrivateOrReservedIp('172.16.0.1'), true);
  assert.equal(isPrivateOrReservedIp('192.168.1.1'), true);
  assert.equal(isPrivateOrReservedIp('100.64.0.1'), true);
  assert.equal(isPrivateOrReservedIp('0.0.0.0'), true);

  // 10. Legitimate Public Internet Addresses
  assert.equal(isPrivateOrReservedIp('8.8.8.8'), false, 'Google DNS must be allowed');
  assert.equal(isPrivateOrReservedIp('1.1.1.1'), false, 'Cloudflare DNS must be allowed');
  assert.equal(isPrivateOrReservedIp('140.82.121.3'), false, 'GitHub IP must be allowed');
  assert.equal(isPrivateOrReservedIp('2606:4700:4700::1111'), false, 'Cloudflare IPv6 must be allowed');
});

test('classifyIpRisk - accurately classifies internal IP ranges with tiered severities', () => {
  // Loopback (INFO)
  const loopback4 = classifyIpRisk('127.0.0.1');
  assert.equal(loopback4.severity, 'INFO');
  assert.equal(loopback4.title, 'Localhost / Loopback Mapping');

  const loopback6 = classifyIpRisk('::1');
  assert.equal(loopback6.severity, 'INFO');

  // RFC 1918 & IPv6 ULA (MEDIUM)
  const rfc10 = classifyIpRisk('10.0.5.23');
  assert.equal(rfc10.severity, 'MEDIUM');
  assert.equal(rfc10.title, 'Internal IP Leak / RFC 1918 Exposure');

  const rfc172 = classifyIpRisk('172.16.4.1');
  assert.equal(rfc172.severity, 'MEDIUM');

  const rfc192 = classifyIpRisk('192.168.1.1');
  assert.equal(rfc192.severity, 'MEDIUM');

  const ula = classifyIpRisk('fd00:abcd::1');
  assert.equal(ula.severity, 'MEDIUM');

  // Cloud IMDS & Link-local (HIGH)
  const imds = classifyIpRisk('169.254.169.254');
  assert.equal(imds.severity, 'HIGH');
  assert.equal(imds.title, 'Link-Local / Cloud IMDS Mapping');

  const linkLocal6 = classifyIpRisk('fe80::1');
  assert.equal(linkLocal6.severity, 'HIGH');

  // CGNAT (LOW)
  const cgnat = classifyIpRisk('100.64.1.1');
  assert.equal(cgnat.severity, 'LOW');
  assert.equal(cgnat.title, 'Carrier-Grade NAT Address (RFC 6598)');

  // Multicast / Reserved (LOW)
  const multi = classifyIpRisk('224.0.0.1');
  assert.equal(multi.severity, 'LOW');
  assert.equal(multi.title, 'Reserved / Multicast IP Address');

  // Unwrapped/Decoded IPv4 addresses (IPv4-mapped and NAT64)
  const mappedLoopback = classifyIpRisk('::ffff:127.0.0.2');
  assert.equal(mappedLoopback.severity, 'INFO', '::ffff:127.0.0.2 must unwrap to 127.0.0.2 and classify as INFO');
  assert.equal(mappedLoopback.title, 'Localhost / Loopback Mapping');

  const mappedRfc1918 = classifyIpRisk('::ffff:10.0.0.1');
  assert.equal(mappedRfc1918.severity, 'MEDIUM', '::ffff:10.0.0.1 must unwrap and classify as RFC 1918 leak');
  assert.equal(mappedRfc1918.title, 'Internal IP Leak / RFC 1918 Exposure');

  const nat64Loopback = classifyIpRisk('64:ff9b::7f00:1');
  assert.equal(nat64Loopback.severity, 'INFO', 'NAT64 loopback must unwrap to 127.0.0.1 and classify as INFO');

  // Public internet addresses and invalid/unparseable inputs must return null (no internal risk)
  assert.equal(classifyIpRisk('8.8.8.8'), null, 'Public IP 8.8.8.8 must return null');
  assert.equal(classifyIpRisk('1.1.1.1'), null, 'Public IP 1.1.1.1 must return null');
  assert.equal(classifyIpRisk('garbage'), null, 'Unparseable input must return null');
  assert.equal(classifyIpRisk(''), null, 'Empty string must return null');
  assert.equal(classifyIpRisk(null), null, 'null input must return null');
  assert.equal(classifyIpRisk(undefined), null, 'undefined input must return null');
});

test('isTokenValid - performs constant-time cryptographic token verification', () => {
  assert.equal(isTokenValid(SESSION_TOKEN), true);
  assert.equal(isTokenValid('wrong-token-value'), false);
  assert.equal(isTokenValid(''), false);
  assert.equal(isTokenValid(null), false);
  assert.equal(isTokenValid(undefined), false);
});

test('storeScan and getScan - implements true LRU cache and preserves running scans', () => {
  scans.clear();

  // Populate scans
  for (let i = 1; i <= MAX_SCANS; i++) {
    storeScan(`scan_${i}`, {
      id: `scan_${i}`,
      status: i === 1 ? 'running' : 'completed',
      step: 1,
    });
  }

  assert.equal(scans.size, MAX_SCANS);
  assert.equal(scans.has('scan_1'), true); // scan_1 is running

  // Reading scan_2 refreshes its recency in the LRU Map
  getScan('scan_2');

  // Adding an additional scan triggers eviction of oldest NON-running scan
  // scan_1 is running (cannot be evicted), scan_2 was accessed (moved to MRU)
  // scan_3 is the oldest completed scan and must be evicted
  storeScan(`scan_${MAX_SCANS + 1}`, {
    id: `scan_${MAX_SCANS + 1}`,
    status: 'completed',
  });

  assert.equal(scans.size, MAX_SCANS);
  assert.equal(scans.has('scan_1'), true, 'Running scan_1 must NEVER be evicted');
  assert.equal(scans.has('scan_2'), true, 'Recently accessed scan_2 must not be evicted');
  assert.equal(scans.has('scan_3'), false, 'Oldest completed scan_3 should be evicted');
});

test('isValidHostHeader - protects against inbound DNS rebinding', () => {
  // Authorized local host headers
  assert.equal(isValidHostHeader('localhost'), true);
  assert.equal(isValidHostHeader('localhost:3000'), true);
  assert.equal(isValidHostHeader('127.0.0.1'), true);
  assert.equal(isValidHostHeader('127.0.0.1:3000'), true);
  assert.equal(isValidHostHeader('127.0.0.1:5173'), true);

  // Unauthorized host headers (inbound DNS rebinding attempts)
  assert.equal(isValidHostHeader('evil.attacker.com'), false);
  assert.equal(isValidHostHeader('attacker-rebind.com:3000'), false);
  assert.equal(isValidHostHeader('rebind.internal.net'), false);
  assert.equal(isValidHostHeader(''), false);
  assert.equal(isValidHostHeader(null), false);
});

test('isAllowedOrigin - exact matching blocks arbitrary subdomains and attacker origins', () => {
  // Non-browser / CLI / curl / direct requests
  assert.equal(isAllowedOrigin(null), true);
  assert.equal(isAllowedOrigin(undefined), true);

  // Authorized exact origins
  assert.equal(isAllowedOrigin('http://localhost:3000'), true);
  assert.equal(isAllowedOrigin('http://127.0.0.1:3000'), true);

  // Block attacker domains that previously slipped through loose regex/includes
  assert.equal(isAllowedOrigin('https://evil.run.app'), false, 'Must block arbitrary evil.run.app');
  assert.equal(isAllowedOrigin('https://evil.webcontainer.io'), false, 'Must block arbitrary webcontainers');
  assert.equal(isAllowedOrigin('https://sites.google.com'), false, 'Must block sites.google.com');
  assert.equal(isAllowedOrigin('https://my-aistudio.attacker.net'), false, 'Must block my-aistudio.attacker.net');
  assert.equal(isAllowedOrigin('http://0.0.0.0:3000'), false, 'Must block 0.0.0.0 origin');
  assert.equal(isAllowedOrigin('http://sub.localhost:3000'), false, 'Must block *.localhost origin');
  assert.equal(isAllowedOrigin('https://malicious.com'), false);
});

test('detectWildcardDNS - tests both IPv4 and IPv6 canary addresses', async () => {
  // Dual-stack stub resolver: positive IPv4 wildcard
  const mockV4Resolver = async () => ['93.184.216.34'];
  const mockNxResolver = async () => {
    const err = new Error('ENOTFOUND');
    err.code = 'ENOTFOUND';
    throw err;
  };

  const resV4 = await detectWildcardDNS('wildcard-v4.com', mockV4Resolver, mockNxResolver);
  assert.equal(resV4.hasWildcard, true);
  assert.deepEqual(resV4.wildcardIps, ['93.184.216.34']);

  // Positive IPv6-only wildcard
  const mockV6Resolver = async () => ['2606:2800:220:1:248:1893:25c8:1946'];
  const resV6 = await detectWildcardDNS('wildcard-v6.com', mockNxResolver, mockV6Resolver);
  assert.equal(resV6.hasWildcard, true);
  assert.deepEqual(resV6.wildcardIps, ['2606:2800:220:1:248:1893:25c8:1946']);

  // Negative wildcard (NXDOMAIN on both v4 and v6)
  const resClean = await detectWildcardDNS('clean-zone.com', mockNxResolver, mockNxResolver);
  assert.equal(resClean.hasWildcard, false);
  assert.deepEqual(resClean.wildcardIps, []);
});

test('checkTakeoverRisk - verified per-resource cloud services, regional S3 regex, and NXDOMAIN logic', async () => {
  const nxDomainTargetResolver = async () => {
    const err = new Error('ENOTFOUND');
    err.code = 'ENOTFOUND';
    throw err;
  };

  // 1. Dead ELB CNAME (*.elb.amazonaws.com) must NOT be flagged as S3 takeover!
  const elbCnameResolver = async () => ['my-load-balancer.elb.amazonaws.com'];
  const elbRes = await checkTakeoverRisk(
    'app.target.com',
    0,
    '',
    elbCnameResolver,
    nxDomainTargetResolver
  );
  assert.equal(elbRes, null, 'Dead ELB CNAME must NOT be reported as S3 takeover');

  // 2. Exact S3 suffix (.s3.amazonaws.com) with 404 + HTTP bucket fingerprint -> Likely Takeover
  const s3CnameResolver = async () => ['abandoned-bucket.s3.amazonaws.com'];
  const s3Res = await checkTakeoverRisk(
    'assets.target.com',
    404,
    'The specified bucket does not exist',
    s3CnameResolver,
    nxDomainTargetResolver
  );
  assert.ok(s3Res);
  assert.equal(s3Res.isVulnerable, true);
  assert.equal(s3Res.certainty, 'Likely');
  assert.equal(s3Res.service, 'Amazon S3');

  // 3. Regional S3 endpoint (bucket.s3.us-west-2.amazonaws.com) with 404 -> Likely Takeover
  const s3RegionalResolver = async () => ['my-bucket.s3.us-west-2.amazonaws.com'];
  const s3RegionalRes = await checkTakeoverRisk(
    'cdn.target.com',
    404,
    'NoSuchBucket',
    s3RegionalResolver,
    nxDomainTargetResolver
  );
  assert.ok(s3RegionalRes);
  assert.equal(s3RegionalRes.service, 'Amazon S3');
  assert.equal(s3RegionalRes.certainty, 'Likely');

  // 4. Regional S3 website endpoint (bucket.s3-website.eu-central-1.amazonaws.com) -> Likely Takeover
  const s3WebsiteResolver = async () => ['static.s3-website.eu-central-1.amazonaws.com'];
  const s3WebsiteRes = await checkTakeoverRisk(
    'web.target.com',
    404,
    'NoSuchBucket',
    s3WebsiteResolver,
    nxDomainTargetResolver
  );
  assert.ok(s3WebsiteRes);
  assert.equal(s3WebsiteRes.service, 'Amazon S3');

  // 4b. Dualstack S3 endpoints (s3.dualstack.<region>.amazonaws.com) -> Likely Takeover
  const s3DualstackResolver = async () => ['assets.s3.dualstack.us-west-2.amazonaws.com'];
  const s3DualstackRes = await checkTakeoverRisk(
    'media.target.com',
    404,
    'The specified bucket does not exist',
    s3DualstackResolver,
    nxDomainTargetResolver
  );
  assert.ok(s3DualstackRes);
  assert.equal(s3DualstackRes.service, 'Amazon S3');
  assert.equal(s3DualstackRes.certainty, 'Likely');
  assert.equal(s3DualstackRes.severity, 'CRITICAL');

  // Tightened S3 regex: s3-evil.amazonaws.com must NOT match S3 CNAME regex (does not report Likely/CRITICAL S3 takeover)
  const s3EvilResolver = async () => ['s3-evil.amazonaws.com'];
  const s3EvilRes = await checkTakeoverRisk(
    'test.target.com',
    404,
    'NoSuchBucket',
    s3EvilResolver,
    nxDomainTargetResolver
  );
  assert.notEqual(s3EvilRes?.service, 'Amazon S3', 's3-evil.amazonaws.com must NOT match Amazon S3 CNAME pattern');
  assert.notEqual(s3EvilRes?.certainty, 'Likely', 's3-evil.amazonaws.com must NOT be reported as Likely S3 takeover');

  const s3EvilEmptyRes = await checkTakeoverRisk(
    'test.target.com',
    0,
    '',
    s3EvilResolver,
    nxDomainTargetResolver
  );
  assert.equal(s3EvilEmptyRes, null, 's3-evil without body match must return null');

  // 5. Shared anycast services (S3 / GitHub Pages) do NOT trigger takeover on NXDOMAIN without HTTP fingerprint
  const s3EmptyBodyRes = await checkTakeoverRisk(
    'assets.target.com',
    0,
    '',
    s3CnameResolver,
    nxDomainTargetResolver
  );
  assert.equal(s3EmptyBodyRes, null, 'S3 with empty body should not trigger NXDOMAIN takeover because S3 is perResourceDns=false');

  // 6. AWS Elastic Beanstalk (perResourceDns: true) with NXDOMAIN -> Likely Takeover
  const ebCnameResolver = async () => ['my-env.elasticbeanstalk.com'];
  const ebRes = await checkTakeoverRisk(
    'api.target.com',
    0,
    '',
    ebCnameResolver,
    nxDomainTargetResolver
  );
  assert.ok(ebRes);
  assert.equal(ebRes.isVulnerable, true);
  assert.equal(ebRes.certainty, 'Likely');
  assert.equal(ebRes.service, 'AWS Elastic Beanstalk');

  // 7. Azure Web App (perResourceDns: true) with NXDOMAIN -> Likely Takeover
  const azureCnameResolver = async () => ['my-service.azurewebsites.net'];
  const azureRes = await checkTakeoverRisk(
    'portal.target.com',
    0,
    '',
    azureCnameResolver,
    nxDomainTargetResolver
  );
  assert.ok(azureRes);
  assert.equal(azureRes.service, 'Azure Web App');

  // 8. Azure Traffic Manager (perResourceDns: true) with NXDOMAIN -> Likely Takeover
  const tmCnameResolver = async () => ['traffic-prod.trafficmanager.net'];
  const tmRes = await checkTakeoverRisk(
    'routing.target.com',
    0,
    '',
    tmCnameResolver,
    nxDomainTargetResolver
  );
  assert.ok(tmRes);
  assert.equal(tmRes.service, 'Azure Traffic Manager');

  // 9. Resolver ESERVFAIL must NOT trigger takeover false positive
  const servFailResolver = async () => {
    const err = new Error('ESERVFAIL');
    err.code = 'ESERVFAIL';
    throw err;
  };
  const servFailRes = await checkTakeoverRisk(
    'flaky.target.com',
    0,
    '',
    ebCnameResolver,
    servFailResolver
  );
  assert.equal(servFailRes, null, 'Resolver ESERVFAIL must never trigger takeover');
});

test('Live Express API tests: Host header rebinding protection, read routes, session tokens & 429 throttle', async () => {
  const testApp = createApp({ runWorkflow: async (scan) => { scan.status = 'completed'; } });
  const server = http.createServer(testApp);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  try {
    // 1. Inbound Host Header: Malicious Host header returns 403
    const badHostStatus = await new Promise((resolve) => {
      const req = http.request(
        {
          hostname: '127.0.0.1',
          port,
          path: '/api/session',
          method: 'GET',
          headers: { Host: 'evil.attacker.com' },
        },
        (res) => resolve(res.statusCode)
      );
      req.end();
    });
    assert.equal(badHostStatus, 403, 'Inbound Host header rebinding must be blocked with 403');

    // 2. Inbound Host Header: Valid Host header returns 200
    const goodHostStatus = await new Promise((resolve) => {
      const req = http.request(
        {
          hostname: '127.0.0.1',
          port,
          path: '/api/session',
          method: 'GET',
          headers: { Host: `127.0.0.1:${port}` },
        },
        (res) => resolve(res.statusCode)
      );
      req.end();
    });
    assert.equal(goodHostStatus, 200, 'Valid Host header must return 200');

    // 3. Read endpoint (GET /api/recon/history) returns 200 without requiring x-reconforge-session header
    const historyStatus = await new Promise((resolve) => {
      const req = http.request(
        {
          hostname: '127.0.0.1',
          port,
          path: '/api/recon/history',
          method: 'GET',
          headers: { Host: `127.0.0.1:${port}` },
        },
        (res) => resolve(res.statusCode)
      );
      req.end();
    });
    assert.equal(historyStatus, 200, 'Read route /api/recon/history must return 200 without token header');

    // 4. POST /api/recon/start without session token returns 403
    const noTokenStatus = await new Promise((resolve) => {
      const req = http.request(
        {
          hostname: '127.0.0.1',
          port,
          path: '/api/recon/start',
          method: 'POST',
          headers: {
            Host: `127.0.0.1:${port}`,
            'Content-Type': 'application/json',
          },
        },
        (res) => resolve(res.statusCode)
      );
      req.write(JSON.stringify({ domain: 'owasp.org' }));
      req.end();
    });
    assert.equal(noTokenStatus, 403, 'Missing session token must return 403');

    // 5. POST /api/recon/start with valid session token returns 200
    const validTokenStatus = await new Promise((resolve) => {
      const req = http.request(
        {
          hostname: '127.0.0.1',
          port,
          path: '/api/recon/start',
          method: 'POST',
          headers: {
            Host: `127.0.0.1:${port}`,
            'Content-Type': 'application/json',
            'x-reconforge-session': SESSION_TOKEN,
          },
        },
        (res) => resolve(res.statusCode)
      );
      req.write(JSON.stringify({ domain: 'owasp.org' }));
      req.end();
    });
    assert.equal(validTokenStatus, 200, 'Valid session token must return 200');

    // 6. Concurrency limit (429 Too Many Requests) when MAX_CONCURRENT_RUNNING scans are active
    scans.set('concur_1', { id: 'concur_1', status: 'running' });
    scans.set('concur_2', { id: 'concur_2', status: 'running' });
    scans.set('concur_3', { id: 'concur_3', status: 'running' });

    const throttledStatus = await new Promise((resolve) => {
      const req = http.request(
        {
          hostname: '127.0.0.1',
          port,
          path: '/api/recon/start',
          method: 'POST',
          headers: {
            Host: `127.0.0.1:${port}`,
            'Content-Type': 'application/json',
            'x-reconforge-session': SESSION_TOKEN,
          },
        },
        (res) => resolve(res.statusCode)
      );
      req.write(JSON.stringify({ domain: 'owasp.org' }));
      req.end();
    });

    // Clean up concurrency fixtures
    scans.delete('concur_1');
    scans.delete('concur_2');
    scans.delete('concur_3');

    assert.equal(throttledStatus, 429, 'POST /api/recon/start must return 429 when max concurrent scans reached');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('Workflow runner injection: mocked workflow runs to completion and populates split host categories', async () => {
  let executedScan = null;
  const mockWorkflow = async (scan) => {
    executedScan = scan;
    scan.step = 6;
    scan.status = 'completed';
    scan.totalSubdomains = 3;
    scan.httpCount = 1;
    scan.dnsCount = 1;
    scan.blockedCount = 1;
    scan.aliveCount = 1;
    scan.aliveHosts = [
      { subdomain: `app.${scan.domain}`, hostType: 'http', statusCode: 200, url: `https://app.${scan.domain}`, latencyMs: 25 },
      { subdomain: `ns.${scan.domain}`, hostType: 'dns', statusCode: 0, url: `http://ns.${scan.domain}`, latencyMs: 12 },
      { subdomain: `corp.${scan.domain}`, hostType: 'blocked', statusCode: 0, ip: '10.0.0.1', ssrfBlocked: true, internalLeak: true },
    ];
  };

  const testApp = createApp({ runWorkflow: mockWorkflow });
  const server = http.createServer(testApp);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  try {
    const res = await new Promise((resolve) => {
      const req = http.request(
        {
          hostname: '127.0.0.1',
          port,
          path: '/api/recon/start',
          method: 'POST',
          headers: {
            Host: `127.0.0.1:${port}`,
            'Content-Type': 'application/json',
            'x-reconforge-session': SESSION_TOKEN,
          },
        },
        (r) => {
          let data = '';
          r.on('data', (c) => (data += c));
          r.on('end', () => resolve({ statusCode: r.statusCode, body: JSON.parse(data) }));
        }
      );
      req.write(JSON.stringify({ domain: 'example.org', allowActiveProbing: true }));
      req.end();
    });

    assert.equal(res.statusCode, 200);
    assert.ok(res.body.scanId);
    assert.equal(res.body.domain, 'example.org');

    // Give microtask queue an instant tick
    await new Promise((r) => setImmediate(r));

    assert.ok(executedScan, 'Injected workflow runner must be called');
    assert.equal(executedScan.allowActiveProbing, true);
    assert.equal(executedScan.status, 'completed');
    assert.equal(executedScan.httpCount, 1);
    assert.equal(executedScan.dnsCount, 1);
    assert.equal(executedScan.blockedCount, 1);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('Live SSRF defense: verifies connection-time hook blocks loopback and local server receives 0 hits', async () => {
  let hitCount = 0;
  const dummyServer = http.createServer((req, res) => {
    hitCount++;
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('VULNERABLE: Local server was reached!');
  });

  // Listen on random free port on 127.0.0.1
  await new Promise((resolve) => dummyServer.listen(0, '127.0.0.1', resolve));
  const port = dummyServer.address().port;

  try {
    await assert.rejects(
      async () => {
        await safeHttpRequest(`http://127.0.0.1:${port}/admin`, {
          timeoutMs: 1500,
          overallDeadlineMs: 2000,
        });
      },
      (err) => {
        return (
          err.code === 'ERR_SSRF_BLOCKED' ||
          (err.message && err.message.includes('SSRF blocked'))
        );
      }
    );

    assert.equal(hitCount, 0, 'Local test server must never receive any HTTP requests');
  } finally {
    await new Promise((resolve) => dummyServer.close(resolve));
  }
});
