import test from 'node:test';
import assert from 'node:assert/strict';
import {
  sanitizeDomain,
  isValidDomain,
  isPrivateOrReservedIp,
  detectWildcardDNS,
  checkTakeoverRisk,
  isAllowedOrigin,
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

test('isPrivateOrReservedIp - blocks all SSRF bypass vectors via net.BlockList', () => {
  // 1. IPv4-mapped IPv6 bypass vectors
  assert.equal(isPrivateOrReservedIp('::ffff:127.0.0.1'), true, 'Must block ::ffff:127.0.0.1');
  assert.equal(isPrivateOrReservedIp('::ffff:169.254.169.254'), true, 'Must block ::ffff:169.254.169.254');

  // 2. Uncompressed & unspecified IPv6 vectors
  assert.equal(isPrivateOrReservedIp('0:0:0:0:0:0:0:1'), true, 'Must block 0:0:0:0:0:0:0:1');
  assert.equal(isPrivateOrReservedIp('::'), true, 'Must block :: unspecified address');
  assert.equal(isPrivateOrReservedIp('::1'), true, 'Must block ::1 loopback');

  // 3. Unique Local Address (fc00::/7) full CIDR range
  assert.equal(isPrivateOrReservedIp('fd12:3456::1'), true, 'Must block fd12:3456::1 (fc00::/7)');
  assert.equal(isPrivateOrReservedIp('fc00::1'), true, 'Must block fc00::1');

  // 4. Link-Local Unicast (fe80::/10) full CIDR range
  assert.equal(isPrivateOrReservedIp('fe90::1'), true, 'Must block fe90::1 (fe80::/10)');
  assert.equal(isPrivateOrReservedIp('fe80::1'), true, 'Must block fe80::1');

  // 5. Multicast and benchmark subnets
  assert.equal(isPrivateOrReservedIp('224.0.0.1'), true, 'Must block 224.0.0.1 (multicast 224.0.0.0/4)');
  assert.equal(isPrivateOrReservedIp('198.18.0.1'), true, 'Must block 198.18.0.1 (benchmark 198.18.0.0/15)');
  assert.equal(isPrivateOrReservedIp('192.0.0.1'), true, 'Must block 192.0.0.1 (IETF assignment 192.0.0.0/24)');

  // 6. Traditional RFC 1918, IMDS, and loopbacks
  assert.equal(isPrivateOrReservedIp('127.0.0.1'), true);
  assert.equal(isPrivateOrReservedIp('169.254.169.254'), true);
  assert.equal(isPrivateOrReservedIp('10.0.0.1'), true);
  assert.equal(isPrivateOrReservedIp('172.16.0.1'), true);
  assert.equal(isPrivateOrReservedIp('192.168.1.1'), true);
  assert.equal(isPrivateOrReservedIp('100.64.0.1'), true);
  assert.equal(isPrivateOrReservedIp('0.0.0.0'), true);

  // 7. Legitimate Public Internet Addresses (Must be allowed)
  assert.equal(isPrivateOrReservedIp('8.8.8.8'), false, 'Google DNS must be allowed');
  assert.equal(isPrivateOrReservedIp('1.1.1.1'), false, 'Cloudflare DNS must be allowed');
  assert.equal(isPrivateOrReservedIp('140.82.121.3'), false, 'GitHub IP must be allowed');
  assert.equal(isPrivateOrReservedIp('2606:4700:4700::1111'), false, 'Cloudflare IPv6 must be allowed');
  assert.equal(isPrivateOrReservedIp('::ffff:8.8.8.8'), false, 'Public IPv4 mapped into IPv6 must be allowed');
});

test('detectWildcardDNS - deterministic evaluation with stub resolver', async () => {
  // Test positive wildcard detection
  const mockWildcardResolver = async () => ['93.184.216.34'];
  const resWildcard = await detectWildcardDNS('wildcard-test.com', mockWildcardResolver);
  assert.equal(resWildcard.hasWildcard, true);
  assert.deepEqual(resWildcard.wildcardIps, ['93.184.216.34']);

  // Test negative wildcard detection (NXDOMAIN)
  const mockNxDomainResolver = async () => {
    const err = new Error('getaddrinfo ENOTFOUND');
    err.code = 'ENOTFOUND';
    throw err;
  };
  const resNoWildcard = await detectWildcardDNS('legit-zone.com', mockNxDomainResolver);
  assert.equal(resNoWildcard.hasWildcard, false);
  assert.deepEqual(resNoWildcard.wildcardIps, []);
});

test('checkTakeoverRisk - verifies CNAME target before claiming takeover', async () => {
  // Normal 200 response should never trigger takeover
  const cleanRes = await checkTakeoverRisk('sub.example.com', 200, '<html>Welcome</html>');
  assert.equal(cleanRes, null);

  // 404 response with body match but no CNAME -> Phrased as Possible / unconfirmed
  const unconfirmedRes = await checkTakeoverRisk('test.example.com', 404, "There isn't a GitHub Pages site here.");
  assert.ok(unconfirmedRes);
  assert.equal(unconfirmedRes.isConfirmed, false);
  assert.ok(unconfirmedRes.service.includes('Possible'));
});

test('isAllowedOrigin - authorizes local, Cloud Run, and AI Studio environments while blocking external origins', () => {
  // Non-browser / CLI / curl / direct requests
  assert.equal(isAllowedOrigin(null), true);
  assert.equal(isAllowedOrigin(undefined), true);
  assert.equal(isAllowedOrigin(''), true);

  // Localhost & 127.0.0.1
  assert.equal(isAllowedOrigin('http://localhost:3000'), true);
  assert.equal(isAllowedOrigin('http://127.0.0.1:5173'), true);
  assert.equal(isAllowedOrigin('https://localhost:8080'), true);

  // Google Cloud Run domains (AIS dev and preview URLs)
  assert.equal(
    isAllowedOrigin('https://ais-dev-sihmny3awbbh2y7w73gwjj-981974432220.asia-southeast1.run.app'),
    true
  );
  assert.equal(
    isAllowedOrigin('https://ais-pre-sihmny3awbbh2y7w73gwjj-981974432220.asia-southeast1.run.app'),
    true
  );
  assert.equal(isAllowedOrigin('https://my-service-xyz.run.app'), true);

  // Google AI Studio and WebContainer environments
  assert.equal(isAllowedOrigin('https://aistudio.google.com'), true);
  assert.equal(isAllowedOrigin('https://app.webcontainer.io'), true);

  // Unauthorized external origins
  assert.equal(isAllowedOrigin('https://malicious-attacker.com'), false);
  assert.equal(isAllowedOrigin('https://evil-phishing.org'), false);
  assert.equal(isAllowedOrigin('invalid-url-string'), false);
});

