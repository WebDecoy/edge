/**
 * WebDecoy clearance edge validator (WAF Enforcement PRD FR7, issue #121).
 *
 * Deployed by the customer on their Cloudflare zone. Statelessly evaluates each
 * request against the org's WebDecoy enforcement config:
 *
 *   1. machine service token header (FR9)  -> pass
 *   2. Cloudflare-verified bot category    -> pass (per org toggles)
 *   3. path not in the token-enforced scope -> pass
 *   4. valid wd_clearance cookie            -> pass
 *   otherwise: monitor mode -> annotate + pass through
 *              enforce mode -> challenge (interstitial mints a token and reloads)
 *
 * FAIL-OPEN INVARIANT: any error — config unreachable, malformed token, crypto
 * failure, unexpected exception — forwards the request untouched. The validator
 * must never take the customer's site down.
 */

export interface Env {
  /** Publishable WebDecoy site key (the organization id). */
  WD_SITE_KEY: string;
  /** WebDecoy ingest base URL, e.g. https://in.webdecoy.com */
  WD_API_BASE: string;
}

interface ValidatorConfig {
  mode: 'monitor' | 'enforce';
  routes: string[];
  allow: { search_engines: boolean; ai_crawlers: boolean; monitoring: boolean };
  keys: { kid: string; public_key: string }[];
  active_credentials: string[];
  /** Device fps denied via the decoy → deny-list binding (#124) — their live
   *  tokens are revoked even before expiry. */
  denied_fps: string[];
  generated_at: number;
}

interface Claims {
  kid: string;
  tenant: string;
  typ?: string;
  sub?: string;
  fp: string;
  scope: string;
  iat: number;
  exp: number;
}

const CONFIG_TTL_MS = 60_000;
const SERVICE_TOKEN_HEADER = 'x-wd-service-token';
const CLEARANCE_COOKIE = 'wd_clearance';
const VERDICT_HEADER = 'x-wd-clearance';

/** Per-isolate config cache; each PoP refreshes at most once a minute. */
let cachedConfig: ValidatorConfig | null = null;
let cachedAt = 0;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await handle(request, env);
    } catch {
      // Fail open, always.
      return fetch(request);
    }
  },
};

async function handle(request: Request, env: Env): Promise<Response> {
  const config = await getConfig(env);
  if (!config) {
    return fetch(request); // config unreachable -> fail open
  }

  const verdict = await evaluate(request, env, config);

  if (verdict.pass || config.mode !== 'enforce') {
    // Pass — and in monitor mode, pass no matter what. The verdict header gives
    // the origin/SDK observability into what enforce mode WOULD have done.
    return forwardWithVerdict(request, verdict.label);
  }
  return challenge(request, env);
}

interface Verdict {
  pass: boolean;
  label: string; // machine | verified-bot | unscoped | valid | missing | invalid
}

async function evaluate(request: Request, env: Env, config: ValidatorConfig): Promise<Verdict> {
  // 1. Machine service token (FR9): proof, not provenance.
  const serviceToken = request.headers.get(SERVICE_TOKEN_HEADER);
  if (serviceToken) {
    const claims = await verifyToken(serviceToken, config.keys, env.WD_SITE_KEY);
    if (
      claims &&
      claims.typ === 'machine' &&
      claims.sub &&
      config.active_credentials.includes(claims.sub)
    ) {
      return { pass: true, label: 'machine' };
    }
    // An invalid machine token falls through — it may still be a browser with
    // a stray header; the remaining checks decide.
  }

  // 2. Cloudflare-verified bots, gated by the org's category toggles. Cloudflare
  // has already done the rDNS/range/Web-Bot-Auth verification; we consume the
  // category. Categories outside the three toggles get no special treatment.
  const botCategory = ((request as any).cf?.verifiedBotCategory as string | undefined) ?? '';
  if (botCategory && isAllowedBotCategory(botCategory, config.allow)) {
    return { pass: true, label: 'verified-bot' };
  }

  // 3. Route scope (#108): the token requirement applies only on scoped paths.
  const path = new URL(request.url).pathname;
  if (!matchesScope(path, config.routes)) {
    return { pass: true, label: 'unscoped' };
  }

  // 4. wd_clearance cookie (FR6). Machine tokens never satisfy this check.
  const token = readCookie(request.headers.get('cookie') ?? '', CLEARANCE_COOKIE);
  if (!token) {
    return { pass: false, label: 'missing' };
  }
  const claims = await verifyToken(token, config.keys, env.WD_SITE_KEY);
  if (!claims || (claims.typ ?? '') !== '') {
    return { pass: false, label: 'invalid' };
  }
  // Decoy → deny-list revocation (#124): a still-unexpired token whose fp was
  // denied (the actor tripped a decoy) is dead, not valid.
  if (config.denied_fps && config.denied_fps.includes(claims.fp)) {
    return { pass: false, label: 'revoked' };
  }
  return { pass: true, label: 'valid' };
}

function isAllowedBotCategory(category: string, allow: ValidatorConfig['allow']): boolean {
  const c = category.toLowerCase();
  if (allow.search_engines && c.includes('search engine crawler')) return true;
  if (allow.ai_crawlers && c.startsWith('ai ')) return true;
  if (allow.monitoring && c.includes('monitoring')) return true;
  return false;
}

/**
 * Route pattern semantics (must match backend IsValidRoutePattern): a pattern is
 * a '/'-rooted path. Without a trailing "/*" it matches the exact path only;
 * with it, the base path and everything under it.
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

function readCookie(header: string, name: string): string | null {
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) {
      return part.slice(eq + 1).trim() || null;
    }
  }
  return null;
}

/** Verify a WebDecoy token: base64url(JSON claims) + "." + base64url(Ed25519 sig). */
async function verifyToken(
  token: string,
  keys: ValidatorConfig['keys'],
  tenant: string
): Promise<Claims | null> {
  try {
    const dot = token.indexOf('.');
    if (dot < 0) return null;
    const payload = b64urlDecode(token.slice(0, dot));
    const sig = b64urlDecode(token.slice(dot + 1));
    const claims = JSON.parse(new TextDecoder().decode(payload)) as Claims;

    const key = keys.find((k) => k.kid === claims.kid);
    if (!key) return null;
    const pub = await crypto.subtle.importKey(
      'raw',
      b64stdDecode(key.public_key),
      { name: 'Ed25519' },
      false,
      ['verify']
    );
    const ok = await crypto.subtle.verify({ name: 'Ed25519' }, pub, sig, payload);
    if (!ok) return null;
    if (claims.tenant !== tenant) return null;
    if (Date.now() / 1000 >= claims.exp) return null;
    return claims;
  } catch {
    return null;
  }
}

function b64urlDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4);
  return bytesOf(atob(b64));
}

function b64stdDecode(s: string): Uint8Array {
  return bytesOf(atob(s));
}

function bytesOf(bin: string): Uint8Array {
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function getConfig(env: Env): Promise<ValidatorConfig | null> {
  const now = Date.now();
  if (cachedConfig && now - cachedAt < CONFIG_TTL_MS) {
    return cachedConfig;
  }
  try {
    const res = await fetch(
      `${env.WD_API_BASE}/api/v1/clearance/config?aid=${encodeURIComponent(env.WD_SITE_KEY)}`,
      { signal: AbortSignal.timeout(3000) }
    );
    if (!res.ok) {
      return cachedConfig; // serve stale over nothing
    }
    cachedConfig = (await res.json()) as ValidatorConfig;
    cachedAt = now;
    return cachedConfig;
  } catch {
    return cachedConfig;
  }
}

function forwardWithVerdict(request: Request, verdict: string): Promise<Response> {
  const headers = new Headers(request.headers);
  headers.set(VERDICT_HEADER, verdict);
  return fetch(new Request(request, { headers }));
}

/**
 * The enforce-mode challenge: an interstitial that runs the client-side check,
 * mints a wd_clearance via the public issuance endpoint, sets the first-party
 * cookie, and reloads. A real browser self-heals in one round trip; a bot that
 * can't pass the check (or whose fingerprint is deny-listed) stays here.
 * Non-HTML clients get a JSON 403 — there is nothing useful to render them.
 */
function challenge(request: Request, env: Env): Response {
  const accept = request.headers.get('accept') ?? '';
  if (request.method !== 'GET' || !accept.includes('text/html')) {
    return new Response(JSON.stringify({ error: 'clearance required' }), {
      status: 403,
      headers: { 'content-type': 'application/json', [VERDICT_HEADER]: 'challenged' },
    });
  }
  const html = challengePage(env.WD_API_BASE, env.WD_SITE_KEY);
  return new Response(html, {
    status: 403,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      [VERDICT_HEADER]: 'challenged',
    },
  });
}

function challengePage(apiBase: string, siteKey: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Checking your browser…</title>
<style>
  body { font-family: system-ui, sans-serif; display: flex; align-items: center;
         justify-content: center; min-height: 100vh; margin: 0; background: #0b0e14; color: #e6e6e6; }
  .box { text-align: center; max-width: 24rem; padding: 2rem; }
  .spin { width: 2rem; height: 2rem; margin: 0 auto 1rem; border: 3px solid #2a2f3a;
          border-top-color: #22d3ee; border-radius: 50%; animation: r 0.8s linear infinite; }
  @keyframes r { to { transform: rotate(360deg); } }
  p { color: #9aa4b2; font-size: 0.9rem; line-height: 1.5; }
</style>
</head>
<body>
<div class="box">
  <div class="spin" id="spin"></div>
  <h1 style="font-size:1.1rem">Checking your browser</h1>
  <p id="msg">This takes a moment and happens only once.</p>
</div>
<script>
(async function () {
  var msg = document.getElementById('msg');
  try {
    // CANONICAL device fp — MUST stay byte-identical to @webdecoy/client
    // computeDeviceFP (webdecoy-node, clearance.ts). Same canvas routine +
    // 32-bit rolling hash as EnvironmentalCollector._getCanvasHash, same WebGL
    // extraction, same "wdfp1|canvas|webgl|screen|tz|platform|language" string.
    // Golden vector (see clearance.test.ts): inputs canvas32=1a2b3c,
    // webgl=ANGLE (Apple M1)~Google Inc., 1920x1080x24, America/New_York,
    // MacIntel, en-US -> f233cd174fddc4481c658d1c91cb7f2565f325c106355760403f2193f9a681da
    var canvas32 = 'na';
    try {
      var c = document.createElement('canvas');
      c.width = 200; c.height = 50;
      var x = c.getContext('2d');
      x.textBaseline = 'top'; x.font = '14px Arial';
      x.fillStyle = '#f60'; x.fillRect(125, 1, 62, 20);
      x.fillStyle = '#069'; x.fillText('FCaptcha', 2, 15);
      x.fillStyle = 'rgba(102, 204, 0, 0.7)'; x.fillText('FCaptcha', 4, 17);
      var dataUrl = c.toDataURL();
      var h = 0;
      for (var i = 0; i < dataUrl.length; i++) { h = ((h << 5) - h) + dataUrl.charCodeAt(i); h = h & h; }
      canvas32 = h.toString(16);
    } catch (e) { canvas32 = 'na'; }

    var webgl = 'na';
    try {
      var gc = document.createElement('canvas');
      var gl = gc.getContext('webgl') || gc.getContext('experimental-webgl');
      if (gl) {
        var dbg = gl.getExtension('WEBGL_debug_renderer_info');
        var vendor = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : 'unknown';
        var renderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : 'unknown';
        webgl = String(renderer) + '~' + String(vendor);
      }
    } catch (e) { webgl = 'na'; }

    var tz = 'na';
    try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone || 'na'; } catch (e) {}
    var raw = ['wdfp1', canvas32, webgl,
      screen.width + 'x' + screen.height + 'x' + screen.colorDepth,
      tz, navigator.platform || 'na', navigator.language || 'na'
    ].join('|');
    var buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(raw));
    var fp = Array.from(new Uint8Array(buf)).map(function (b) {
      return b.toString(16).padStart(2, '0');
    }).join('');

    var res = await fetch(${JSON.stringify(apiBase)} + '/api/v1/clearance', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        aid: ${JSON.stringify(siteKey)},
        fp: fp,
        scope: '',
        ua: navigator.userAgent,
        webdriver: navigator.webdriver === true,
        headless: /HeadlessChrome/.test(navigator.userAgent)
      })
    });
    var out = await res.json();
    if (out && out.granted && out.token) {
      document.cookie = 'wd_clearance=' + out.token +
        '; path=/; secure; samesite=lax; max-age=' + (out.expires_in || 1800);
      location.reload();
      return;
    }
    document.getElementById('spin').style.display = 'none';
    msg.textContent = 'Verification did not pass. If you believe this is an error, contact the site owner.';
  } catch (e) {
    document.getElementById('spin').style.display = 'none';
    msg.textContent = 'Verification could not complete. Please retry shortly.';
  }
})();
</script>
</body>
</html>`;
}
