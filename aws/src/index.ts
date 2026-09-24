/**
 * WebDecoy clearance edge validator — AWS Lambda@Edge (WAF Enforcement PRD FR7 for
 * AWS, issue #125). The AWS twin of the Cloudflare Worker: same job, same public
 * config endpoint, same evaluation order, same fail-open invariant. Runs as a
 * CloudFront viewer-request function.
 *
 *   1. machine service token header (FR9)                 -> pass
 *   2. verified crawler via forward-confirmed rDNS (FR9-b) -> pass (per org toggles)
 *   3. path not in the token-enforced scope (#108)         -> pass
 *   4. valid wd_clearance cookie, fp not decoy-denied (#124) -> pass
 *   otherwise: monitor -> annotate + pass · enforce -> challenge
 *
 * FAIL-OPEN: any error forwards the request untouched. Never takes a site down.
 *
 * Note: Lambda@Edge viewer-request has no env vars — see config.ts.
 */

import { promises as dnsPromises } from 'node:dns';
import { CONFIG } from './config';
import { recordVerdict } from './telemetry';
import { verifyToken, matchesScope, type SigningKey } from './token';
import { verifyBot, type AllowToggles, type DnsResolver } from './verified-bots';

interface ValidatorConfig {
  mode: 'monitor' | 'enforce';
  routes: string[];
  allow: AllowToggles;
  keys: SigningKey[];
  active_credentials: string[];
  denied_fps: string[];
  generated_at: number;
}

const CONFIG_TTL_MS = 60_000;
const SERVICE_TOKEN_HEADER = 'x-wd-service-token';
const CLEARANCE_COOKIE = 'wd_clearance';
const VERDICT_HEADER = 'x-wd-clearance';
// Deploy verification (#139): a request carrying this query param short-circuits
// to a JSON heartbeat so the dashboard can confirm the validator is live.
const HEALTHCHECK_PARAM = '__wd_clearance_check';

/** Extract the health-check nonce from a CloudFront querystring, or null. */
export function healthNonce(querystring: string): string | null {
  for (const part of querystring.split('&')) {
    const eq = part.indexOf('=');
    const key = eq < 0 ? part : part.slice(0, eq);
    if (decodeURIComponent(key) === HEALTHCHECK_PARAM) {
      return eq < 0 ? '' : decodeURIComponent(part.slice(eq + 1));
    }
  }
  return null;
}

let cachedConfig: ValidatorConfig | null = null;
let cachedAt = 0;

const nodeResolver: DnsResolver = {
  reverse: (ip) => dnsPromises.reverse(ip),
  resolve4: (h) => dnsPromises.resolve4(h),
  resolve6: (h) => dnsPromises.resolve6(h),
};

// CloudFront request/response shapes (minimal — only what we touch).
interface CfHeader {
  key?: string;
  value: string;
}
type CfHeaders = Record<string, CfHeader[]>;
interface CfRequest {
  clientIp: string;
  method: string;
  uri: string;
  querystring: string;
  headers: CfHeaders;
}
interface CfResponse {
  status: string;
  statusDescription?: string;
  headers?: CfHeaders;
  body?: string;
}

export async function handler(event: {
  Records: { cf: { request: CfRequest } }[];
}): Promise<CfRequest | CfResponse> {
  const request = event.Records[0].cf.request;
  try {
    return await handle(request);
  } catch {
    return request; // fail open, always
  }
}

async function handle(request: CfRequest): Promise<CfRequest | CfResponse> {
  const nonce = healthNonce(request.querystring || '');
  const config = await getConfig();

  // Deploy heartbeat (#139): answered by the validator directly; if it reaches
  // origin instead, the dashboard knows the validator isn't associated.
  if (nonce !== null) {
    return healthResponse(nonce, config ? config.mode : 'unknown');
  }

  if (!config) return request; // config unreachable -> fail open

  const verdict = await evaluate(request, config);

  // Verdict telemetry (#435). Awaited, unlike the Worker's: Lambda@Edge may be
  // frozen the instant this handler returns, so a background promise reports
  // nothing. recordVerdict only returns one when a window actually closed, so
  // this costs 1 request in N and is capped well under the viewer-request
  // budget. It never rejects.
  const flush = recordVerdict(verdict.label, config.mode, CONFIG.siteKey, CONFIG.apiBase);
  if (flush) await flush;

  if (verdict.pass || config.mode !== 'enforce') {
    setHeader(request.headers, VERDICT_HEADER, verdict.label);
    return request;
  }
  return challenge(request);
}

interface Verdict {
  pass: boolean;
  label: string;
}

async function evaluate(request: CfRequest, config: ValidatorConfig): Promise<Verdict> {
  const now = Date.now();

  // 1. Machine service token (FR9).
  const serviceToken = headerValue(request.headers, SERVICE_TOKEN_HEADER);
  if (serviceToken) {
    const claims = verifyToken(serviceToken, config.keys, CONFIG.siteKey, now);
    if (claims && claims.typ === 'machine' && claims.sub && config.active_credentials.includes(claims.sub)) {
      return { pass: true, label: 'machine' };
    }
  }

  // 2. Verified crawler via forward-confirmed rDNS (FR9-b). AWS has no platform
  // bot signal, so we do the verification ourselves.
  if (config.allow.search_engines || config.allow.ai_crawlers || config.allow.monitoring) {
    const category = await verifyBot(request.clientIp, config.allow, nodeResolver, now);
    if (category) return { pass: true, label: 'verified-bot:' + category };
  }

  // 3. Route scope (#108).
  if (!matchesScope(request.uri, config.routes)) {
    return { pass: true, label: 'unscoped' };
  }

  // 4. wd_clearance cookie (FR6). Machine tokens never satisfy this check.
  const token = readCookie(headerValue(request.headers, 'cookie'), CLEARANCE_COOKIE);
  if (!token) return { pass: false, label: 'missing' };
  const claims = verifyToken(token, config.keys, CONFIG.siteKey, now);
  if (!claims || (claims.typ ?? '') !== '') return { pass: false, label: 'invalid' };
  // Decoy -> deny-list revocation (#124): a denied fp's live token is dead.
  if (config.denied_fps && config.denied_fps.includes(claims.fp)) {
    return { pass: false, label: 'revoked' };
  }
  return { pass: true, label: 'valid' };
}

async function getConfig(): Promise<ValidatorConfig | null> {
  const now = Date.now();
  if (cachedConfig && now - cachedAt < CONFIG_TTL_MS) return cachedConfig;
  try {
    const res = await fetch(
      `${CONFIG.apiBase}/api/v1/clearance/config?aid=${encodeURIComponent(CONFIG.siteKey)}`,
      { signal: AbortSignal.timeout(3000) },
    );
    if (!res.ok) return cachedConfig; // serve stale over nothing
    cachedConfig = (await res.json()) as ValidatorConfig;
    cachedAt = now;
    return cachedConfig;
  } catch {
    return cachedConfig;
  }
}

function headerValue(headers: CfHeaders, name: string): string {
  const h = headers[name.toLowerCase()];
  return h && h[0] ? h[0].value : '';
}

function setHeader(headers: CfHeaders, name: string, value: string): void {
  headers[name.toLowerCase()] = [{ key: name, value }];
}

function readCookie(header: string, name: string): string | null {
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim() || null;
  }
  return null;
}

/**
 * The enforce-mode challenge: an interstitial that runs the client check, mints a
 * token, sets the cookie, and reloads. Non-HTML clients get a JSON 403.
 * The device-fp algorithm is byte-identical to @webdecoy/client and the Cloudflare
 * Worker (canonical "wdfp1" — golden f233cd…681da), so a decoy-triggered deny
 * covers a token minted through either edge.
 */
/** Deploy-verification heartbeat. Permissive CORS so the dashboard can read it
 *  cross-origin from the customer's own site; no-store so it's never cached. */
function healthResponse(nonce: string, mode: string): CfResponse {
  return {
    status: '200',
    statusDescription: 'OK',
    headers: {
      'content-type': [{ key: 'Content-Type', value: 'application/json' }],
      'cache-control': [{ key: 'Cache-Control', value: 'no-store' }],
      'access-control-allow-origin': [{ key: 'Access-Control-Allow-Origin', value: '*' }],
    },
    body: JSON.stringify({ wd_clearance: true, nonce, mode, site_key: CONFIG.siteKey }),
  };
}

function challenge(request: CfRequest): CfResponse {
  const accept = headerValue(request.headers, 'accept');
  if (request.method !== 'GET' || !accept.includes('text/html')) {
    return {
      status: '403',
      statusDescription: 'Forbidden',
      headers: {
        'content-type': [{ key: 'Content-Type', value: 'application/json' }],
        [VERDICT_HEADER]: [{ key: VERDICT_HEADER, value: 'challenged' }],
      },
      body: JSON.stringify({ error: 'clearance required' }),
    };
  }
  return {
    status: '403',
    statusDescription: 'Forbidden',
    headers: {
      'content-type': [{ key: 'Content-Type', value: 'text/html; charset=utf-8' }],
      'cache-control': [{ key: 'Cache-Control', value: 'no-store' }],
      [VERDICT_HEADER]: [{ key: VERDICT_HEADER, value: 'challenged' }],
    },
    body: challengePage(CONFIG.apiBase, CONFIG.siteKey),
  };
}

function challengePage(apiBase: string, siteKey: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Checking your browser…</title>
<style>
  body{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#0b0e14;color:#e6e6e6}
  .box{text-align:center;max-width:24rem;padding:2rem}
  .spin{width:2rem;height:2rem;margin:0 auto 1rem;border:3px solid #2a2f3a;border-top-color:#22d3ee;border-radius:50%;animation:r .8s linear infinite}
  @keyframes r{to{transform:rotate(360deg)}}
  p{color:#9aa4b2;font-size:.9rem;line-height:1.5}
</style></head>
<body><div class="box">
  <div class="spin" id="spin"></div>
  <h1 style="font-size:1.1rem">Checking your browser</h1>
  <p id="msg">This takes a moment and happens only once.</p>
</div>
<script>
(async function(){
  var msg=document.getElementById('msg');
  try{
    // CANONICAL device fp — MUST match @webdecoy/client computeDeviceFP and the
    // Cloudflare Worker (wdfp1 / golden f233cd…681da).
    var canvas32='na';
    try{
      var c=document.createElement('canvas');c.width=200;c.height=50;
      var x=c.getContext('2d');x.textBaseline='top';x.font='14px Arial';
      x.fillStyle='#f60';x.fillRect(125,1,62,20);
      x.fillStyle='#069';x.fillText('FCaptcha',2,15);
      x.fillStyle='rgba(102, 204, 0, 0.7)';x.fillText('FCaptcha',4,17);
      var d=c.toDataURL();var h=0;
      for(var i=0;i<d.length;i++){h=((h<<5)-h)+d.charCodeAt(i);h=h&h;}
      canvas32=h.toString(16);
    }catch(e){canvas32='na';}
    var webgl='na';
    try{
      var gc=document.createElement('canvas');
      var gl=gc.getContext('webgl')||gc.getContext('experimental-webgl');
      if(gl){var dbg=gl.getExtension('WEBGL_debug_renderer_info');
        var ve=dbg?gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL):'unknown';
        var re=dbg?gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL):'unknown';
        webgl=String(re)+'~'+String(ve);}
    }catch(e){webgl='na';}
    var tz='na';try{tz=Intl.DateTimeFormat().resolvedOptions().timeZone||'na';}catch(e){}
    var raw=['wdfp1',canvas32,webgl,screen.width+'x'+screen.height+'x'+screen.colorDepth,tz,navigator.platform||'na',navigator.language||'na'].join('|');
    var buf=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(raw));
    var fp=Array.from(new Uint8Array(buf)).map(function(b){return b.toString(16).padStart(2,'0');}).join('');
    var res=await fetch(${JSON.stringify(apiBase)}+'/api/v1/clearance',{
      method:'POST',headers:{'content-type':'application/json'},
      body:JSON.stringify({aid:${JSON.stringify(siteKey)},fp:fp,scope:'',ua:navigator.userAgent,webdriver:navigator.webdriver===true,headless:/HeadlessChrome/.test(navigator.userAgent)})
    });
    var out=await res.json();
    if(out&&out.granted&&out.token){
      document.cookie='wd_clearance='+out.token+'; path=/; secure; samesite=lax; max-age='+(out.expires_in||1800);
      location.reload();return;
    }
    document.getElementById('spin').style.display='none';
    msg.textContent='Verification did not pass. If you believe this is an error, contact the site owner.';
  }catch(e){
    document.getElementById('spin').style.display='none';
    msg.textContent='Verification could not complete. Please retry shortly.';
  }
})();
</script></body></html>`;
}
