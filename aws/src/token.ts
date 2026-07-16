/**
 * wd_clearance token verification for the Lambda@Edge runtime (Node crypto).
 * Mirrors the Cloudflare Worker's WebCrypto path — same token format, same
 * checks — but builds the Ed25519 public key via SPKI DER, which is the reliable
 * route in the Node 18/20 Lambda runtime.
 */

import { createPublicKey, verify as cryptoVerify } from 'node:crypto';

export interface Claims {
  kid: string;
  tenant: string;
  typ?: string;
  sub?: string;
  fp: string;
  scope: string;
  iat: number;
  exp: number;
}

export interface SigningKey {
  kid: string;
  public_key: string; // base64 (std) raw Ed25519 public key
}

// Fixed 12-byte Ed25519 SubjectPublicKeyInfo prefix; append the 32 raw key bytes
// to get valid SPKI DER. (SEQUENCE / AlgorithmIdentifier OID 1.3.101.112 / BIT STRING)
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function importEd25519(rawStdB64: string) {
  const raw = Buffer.from(rawStdB64, 'base64');
  if (raw.length !== 32) throw new Error('bad ed25519 public key length');
  const der = Buffer.concat([ED25519_SPKI_PREFIX, raw]);
  return createPublicKey({ key: der, format: 'der', type: 'spki' });
}

/**
 * Verify a WebDecoy token: base64url(JSON claims) + "." + base64url(Ed25519 sig).
 * Returns claims if the signature is valid, the tenant matches, and (unless
 * ignoreExpiry) it hasn't expired. Returns null on any problem.
 */
export function verifyToken(
  token: string,
  keys: SigningKey[],
  tenant: string,
  now: number,
): Claims | null {
  try {
    const dot = token.indexOf('.');
    if (dot < 0) return null;
    const payload = Buffer.from(token.slice(0, dot), 'base64url');
    const sig = Buffer.from(token.slice(dot + 1), 'base64url');
    const claims = JSON.parse(payload.toString('utf8')) as Claims;

    const key = keys.find((k) => k.kid === claims.kid);
    if (!key) return null;
    if (!cryptoVerify(null, payload, importEd25519(key.public_key), sig)) return null;
    if (claims.tenant !== tenant) return null;
    if (now / 1000 >= claims.exp) return null;
    return claims;
  } catch {
    return null;
  }
}

/**
 * Route pattern semantics — identical to the backend IsValidRoutePattern and the
 * Cloudflare Worker: a '/'-rooted path; a trailing "/*" matches the base path and
 * everything under it, otherwise an exact match.
 */
export function matchesScope(path: string, patterns: string[]): boolean {
  for (const p of patterns) {
    if (p.endsWith('/*')) {
      const base = p.slice(0, -2) || '/';
      if (path === base || path.startsWith(base + '/')) return true;
    } else if (path === p) {
      return true;
    }
  }
  return false;
}
