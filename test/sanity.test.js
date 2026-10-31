import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  sanitizeDomain,
  isValidDomain,
  isPrivateOrReservedIp,
  detectWildcardDNS,
  checkTakeoverRisk,
  isAllowedOrigin,
  isValidHostHeader,
  safeHttpRequest,
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

test('isValidHostHeader - protects against inbound DNS rebinding', () => {
  // Authorized local and preview host headers
  assert.equal(isValidHostHeader('localhost'), true);
  assert.equal(isValidHostHeader('localhost:3000'), true);
  assert.equal(isValidHostHeader('127.0.0.1:3000'), true);
  assert.equal(isValidHostHeader('127.0.0.1:5173'), true);
  assert.equal(
    isValidHostHeader('ais-dev-sihmny3awbbh2y7w73gwjj-981974432220.asia-southeast1.run.app'),
    true
  );

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
  assert.equal(
    isAllowedOrigin('https://ais-dev-sihmny3awbbh2y7w73gwjj-981974432220.asia-southeast1.run.app'),
    true
  );

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

test('checkTakeoverRisk - strict endsWith matching, NXDOMAIN verification, and Likely certainty', async () => {
  // 1. Strict suffix matching: x.github.io.attacker.net must NOT match GitHub Pages
  const attackerCnameResolver = async () => ['x.github.io.attacker.net'];
  const attackerRes = await checkTakeoverRisk(
    'sub.attacker.net',
    404,
    "There isn't a GitHub Pages site here.",
    attackerCnameResolver
  );
  // Body matches signature, but CNAME target is attacker domain, so it must NOT be confirmed as GitHub Pages takeover
  assert.ok(attackerRes);
  assert.equal(attackerRes.certainty, 'Potential');

  // 2. Dangling CNAME pointing to NXDOMAIN target -> Likely Subdomain Takeover
  const legitCnameResolver = async () => ['abandoned-bucket.s3.amazonaws.com'];
  const nxDomainTargetResolver = async () => {
    const err = new Error('ENOTFOUND');
    err.code = 'ENOTFOUND';
    throw err;
  };
  const nxRes = await checkTakeoverRisk(
    'assets.target.com',
    0,
    '',
    legitCnameResolver,
    nxDomainTargetResolver
  );
  assert.ok(nxRes);
  assert.equal(nxRes.isVulnerable, true);
  assert.equal(nxRes.certainty, 'Likely');
  assert.equal(nxRes.service, 'Amazon S3');
  assert.equal(nxRes.cname, 'abandoned-bucket.s3.amazonaws.com');

  // 3. Normal 200 response -> No risk
  const cleanRes = await checkTakeoverRisk('sub.example.com', 200, '<html>OK</html>');
  assert.equal(cleanRes, null);
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
