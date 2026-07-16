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
    const bad = BROWSER_TOKEN.slice(0, -1) + (BROWSER_TOKEN.endsWith('A') ? 'B' : 'A');
    expect(verifyToken(bad, KEYS, TENANT, NOW)).toBeNull();
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
    ['/home', [], false],
    ['/login', ['/checkout/*', '/login'], true],
  ];
  it.each(cases)('%s against %j -> %s', (path, patterns, want) => {
    expect(matchesScope(path, patterns)).toBe(want);
  });
});
