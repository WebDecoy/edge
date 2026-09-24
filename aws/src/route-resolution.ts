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

function patternMatches(path: string, pattern: string): boolean {
  if (pattern.endsWith('/*')) {
    const base = pattern.slice(0, -2);
    // "/*" is the whole site. This used to coerce the empty base to '/' and
    // test startsWith('//'), which gated the root and nothing else while the
    // dashboard said the whole site was protected.
    if (base === '') return true;
    return path === base || path.startsWith(base + '/');
  }
  return path === pattern;
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
