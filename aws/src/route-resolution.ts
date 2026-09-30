/**
 * What protected paths say about one request path (#1125), for the Lambda.
 *
 * The rule is written on ResolveRoute in pkg/models/enforcement_route_scope.go.
 * Go, the Cloudflare Worker and this file replay
 * pkg/models/testdata/route_resolution_vectors.json.
 *
 * Deliberately partial: this validator does not enforce per-path verification
 * requirements (it has no route_min_trust handling), so it resolves coverage
 * and attribution only. Requirement cases are expected failures in the test,
 * pointing at the parity work in #1126, rather than a pure function here that
 * would claim a requirement the handler never applies.
 */

export interface LambdaRouteResolution {
  /** Every distinct covering pattern, most specific first. */
  covering: string[];
  /** The one path this request's activity counts against; '' when uncovered. */
  attributed: string;
}

/**
 * Canonicalize a request path (or a pattern) before matching (#1439). Byte-for-
 * byte identical to normalizeMatchPath in the Worker and Go, replaying the same
 * route_resolution_vectors.json: ASCII percent-decode, collapse slashes +
 * resolve "."/".." keeping one trailing slash, lowercase.
 */
function normalizeMatchPath(s: string): string {
  s = decodePercentAscii(s);
  s = cleanSlashesAndDots(s);
  return s.toLowerCase();
}

function decodePercentAscii(s: string): string {
  for (let i = 0; i < 4; i++) {
    const next = decodePercentAsciiOnce(s);
    if (next === s) break;
    s = next;
  }
  return s;
}

function decodePercentAsciiOnce(s: string): string {
  if (!s.includes('%')) return s;
  let out = '';
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '%' && i + 2 < s.length) {
      const hi = unhexNibble(s.charCodeAt(i + 1));
      const lo = unhexNibble(s.charCodeAt(i + 2));
      if (hi >= 0 && lo >= 0) {
        const v = (hi << 4) | lo;
        if (v < 0x80) {
          out += String.fromCharCode(v);
          i += 2;
          continue;
        }
      }
    }
    out += s[i];
  }
  return out;
}

function unhexNibble(c: number): number {
  if (c >= 48 && c <= 57) return c - 48;
  if (c >= 97 && c <= 102) return c - 97 + 10;
  if (c >= 65 && c <= 70) return c - 65 + 10;
  return -1;
}

function cleanSlashesAndDots(s: string): string {
  if (s === '') return s;
  const hadTrailing = s.length > 1 && s[s.length - 1] === '/';
  const stack: string[] = [];
  for (const p of s.split('/')) {
    if (p === '' || p === '.') continue;
    if (p === '..') {
      if (stack.length > 0) stack.pop();
      continue;
    }
    stack.push(p);
  }
  let res = '/' + stack.join('/');
  if (hadTrailing && res !== '/') res += '/';
  return res;
}

function patternMatches(path: string, pattern: string): boolean {
  const np = normalizeMatchPath(path);
  const pat = normalizeMatchPath(pattern);
  if (pat.endsWith('/*')) {
    const base = pat.slice(0, -2);
    // "/*" is the whole site. This used to coerce the empty base to '/' and
    // test startsWith('//'), which gated the root and nothing else while the
    // dashboard said the whole site was protected.
    if (base === '') return true;
    return np === base || np.startsWith(base + '/');
  }
  return np === pat;
}

/** Exact patterns outrank every prefix; a longer prefix outranks a shorter one. */
function specificity(pattern: string): number {
  return pattern.endsWith('/*') ? pattern.length - 2 : 1 << 20;
}

export function resolveRoute(path: string, patterns: string[]): LambdaRouteResolution {
  const covering: string[] = [];
  for (const p of patterns) {
    if (patternMatches(path, p) && !covering.includes(p)) covering.push(p);
  }
  covering.sort((a, b) => specificity(b) - specificity(a));
  return { covering, attributed: covering[0] ?? '' };
}
