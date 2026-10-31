import test from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeDomain, isValidDomain, isPrivateOrReservedIp, detectWildcardDNS } from '../server.js';

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

test('isPrivateOrReservedIp - blocks SSRF, IMDS, loopback and private networks', () => {
  // Cloud Instance Metadata Service (AWS/GCP/Azure IMDS)
  assert.equal(isPrivateOrReservedIp('169.254.169.254'), true, 'Must block AWS IMDS');
  assert.equal(isPrivateOrReservedIp('169.254.1.1'), true, 'Must block link-local');

  // IPv4 Loopback
  assert.equal(isPrivateOrReservedIp('127.0.0.1'), true, 'Must block 127.0.0.1');
  assert.equal(isPrivateOrReservedIp('127.128.0.1'), true, 'Must block 127.0.0.0/8');

  // RFC 1918 Private networks
  assert.equal(isPrivateOrReservedIp('10.0.0.1'), true, 'Must block 10.0.0.0/8');
  assert.equal(isPrivateOrReservedIp('10.254.254.254'), true, 'Must block 10.0.0.0/8');
  assert.equal(isPrivateOrReservedIp('172.16.0.1'), true, 'Must block 172.16.0.0/12');
  assert.equal(isPrivateOrReservedIp('172.31.255.255'), true, 'Must block 172.16.0.0/12');
  assert.equal(isPrivateOrReservedIp('192.168.1.1'), true, 'Must block 192.168.0.0/16');

  // Carrier Grade NAT & Zero address
  assert.equal(isPrivateOrReservedIp('100.64.0.1'), true, 'Must block CGNAT');
  assert.equal(isPrivateOrReservedIp('0.0.0.0'), true, 'Must block 0.0.0.0');

  // IPv6 loopback and private ranges
  assert.equal(isPrivateOrReservedIp('::1'), true, 'Must block IPv6 loopback');
  assert.equal(isPrivateOrReservedIp('fe80::1'), true, 'Must block IPv6 link-local');
  assert.equal(isPrivateOrReservedIp('fc00::1'), true, 'Must block IPv6 unique local');

  // Legitimate Public Internet IPs (MUST NOT be blocked)
  assert.equal(isPrivateOrReservedIp('8.8.8.8'), false, 'Google DNS must be allowed');
  assert.equal(isPrivateOrReservedIp('1.1.1.1'), false, 'Cloudflare DNS must be allowed');
  assert.equal(isPrivateOrReservedIp('140.82.121.3'), false, 'GitHub IP must be allowed');
  assert.equal(isPrivateOrReservedIp('172.32.0.1'), false, 'Public IP outside 172.16-31 range must be allowed');
});

test('detectWildcardDNS - handles standard domain query gracefully', async () => {
  assert.equal(typeof detectWildcardDNS, 'function');
  const result = await detectWildcardDNS('example.com');
  assert.equal(typeof result.hasWildcard, 'boolean');
  assert.ok(Array.isArray(result.wildcardIps));
});
