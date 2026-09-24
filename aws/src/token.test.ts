/**
 * Proves the Lambda@Edge Node-crypto token path accepts a REAL backend-minted
 * Ed25519 token (cross-language contract with Go's ed25519.Sign + RawURLEncoding),
 * and rejects tampered / wrong-tenant / machine-vs-browser / expired tokens. Also
 * locks the route-scope semantics shared with the backend and the CF Worker.
 */

import { verifyToken, matchesScope, type SigningKey } from './token';

// Golden vector minted by Go (ed25519 seed = bytes 1..32; exp = year 2100).
const KEYS: SigningKey[] = [{ kid: 'k1', public_key: 'ebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ=' }];
const TENANT = '11111111-1111-1111-1111-111111111111';
const BROWSER_TOKEN =
  'eyJraWQiOiJrMSIsInRlbmFudCI6IjExMTExMTExLTExMTEtMTExMS0xMTExLTExMTExMTExMTExMSIsImZwIjoiY2FudmFzaGFzaDEyMyIsInNjb3BlIjoiIiwiaWF0IjoxMDAwLCJleHAiOjQxMDI0NDQ4MDB9.jSTZaDhWw8xV66cQDKS1xiKvF9bUI3qEyQJtD64NwnHnKXF-60XAp_rKQRuxEEgQ8rFvDllboFAnkr9gP_JsBg';
const MACHINE_TOKEN =
  'eyJraWQiOiJrMSIsInRlbmFudCI6IjExMTExMTExLTExMTEtMTExMS0xMTExLTExMTExMTExMTExMSIsInR5cCI6Im1hY2hpbmUiLCJzdWIiOiJjcmVkLTEiLCJmcCI6IiIsInNjb3BlIjoiIiwiaWF0IjoxMDAwLCJleHAiOjQxMDI0NDQ4MDB9.AED4wFWChthFlTxV0t-cYL6EMdf_AifzpGACCV-RkWHZ9J8E6CDW4gOwVExYVhvfSefBaY7aUMuowVvXCXqRCA';

/**
 * The same token with one bit of its signature flipped (#1194).
 *
 * Decoded and re-encoded rather than edited as text: an Ed25519 signature is
 * 64 bytes and its base64url form ends in a character carrying only two
 * significant bits, so editing the end of the string can leave the signature
 * byte-for-byte identical.
 */
function tamperSignature(token: string): string {
  const dot = token.indexOf('.');
  const bytes = b64urlToBytes(token.slice(dot + 1));
  bytes[0] ^= 0x01;
  return `${token.slice(0, dot + 1)}${bytesToB64url(bytes)}`;
}

function b64urlToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4);
  return Uint8Array.from(Buffer.from(b64, 'base64'));
}

function bytesToB64url(b: Uint8Array): string {
  return Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const NOW = 1_700_000_000_000; // fixed, well before the year-2100 expiry

describe('verifyToken (Node crypto SPKI ↔ Go ed25519)', () => {
  it('accepts a real backend-minted browser token', () => {
    const claims = verifyToken(BROWSER_TOKEN, KEYS, TENANT, NOW);
    expect(claims).not.toBeNull();
    expect(claims!.fp).toBe('canvashash123');
    expect(claims!.typ ?? '').toBe('');
  });

  it('accepts a real machine token with its sub', () => {
    const claims = verifyToken(MACHINE_TOKEN, KEYS, TENANT, NOW);
    expect(claims!.typ).toBe('machine');
    expect(claims!.sub).toBe('cred-1');
  });

  it('rejects a tampered signature', () => {
    expect(verifyToken(tamperSignature(BROWSER_TOKEN), KEYS, TENANT, NOW)).toBeNull();
  });

  // The tamper has to be a real one. Swapping the token's last character,
  // which is what this test used to do, changes nothing the decoder reads
  // when that character shares its two significant bits with the one it
  // replaces: the signature survives, the token verifies, and the test
  // asserts the opposite of its name. It passed here only because this golden
  // vector happens to end in 'g' (#1194).
  it('tampers with the signature it is given', () => {
    for (const lastByte of [0x00, 0x04, 0x40, 0x80, 0xc0]) {
      const sig = new Uint8Array(64);
      sig[0] = 0x7f;
      sig[63] = lastByte;
      const token = `payload.${bytesToB64url(sig)}`;
      expect(b64urlToBytes(tamperSignature(token).split('.')[1])).not.toEqual(sig);
    }
    expect(b64urlToBytes(tamperSignature(BROWSER_TOKEN).split('.')[1])).not.toEqual(
      b64urlToBytes(BROWSER_TOKEN.split('.')[1])
    );
  });

  it('rejects a wrong-tenant token', () => {
    expect(verifyToken(BROWSER_TOKEN, KEYS, 'deadbeef', NOW)).toBeNull();
  });

  it('rejects an unknown kid', () => {
    expect(verifyToken(BROWSER_TOKEN, [{ kid: 'other', public_key: KEYS[0].public_key }], TENANT, NOW)).toBeNull();
  });

  it('rejects an expired token', () => {
    // now well past the year-2100 expiry
    expect(verifyToken(BROWSER_TOKEN, KEYS, TENANT, 5_000_000_000_000)).toBeNull();
  });
});

describe('matchesScope', () => {
  const cases: [string, string[], boolean][] = [
    ['/checkout', ['/checkout'], true],
    ['/checkout/', ['/checkout'], false],
    ['/checkout', ['/checkout/*'], true],
    ['/checkout/pay', ['/checkout/*'], true],
    ['/checkoutx', ['/checkout/*'], false],
    ['/api/v1/x', ['/api/*'], true],
    ['/', ['/*'], true],
    // "/*" is the whole site, not just the root (#1125).
    ['/home', ['/*'], true],
    ['/a/b/c', ['/*'], true],
    ['/home', [], false],
    ['/login', ['/checkout/*', '/login'], true],
  ];
  it.each(cases)('%s against %j -> %s', (path, patterns, want) => {
    expect(matchesScope(path, patterns)).toBe(want);
  });
});
