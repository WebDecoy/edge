import { generateKeyPairSync, sign } from 'node:crypto';
import { CONFIG } from './config';
import { handler, __resetConfigState } from './index';

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const fp = 'a'.repeat(64);
const token = (() => {
  const payload = Buffer.from(JSON.stringify({ kid: 'test', tenant: CONFIG.siteKey, fp, exp: 4102444800 }));
  return payload.toString('base64url') + '.' + sign(null, payload, privateKey).toString('base64url');
})();
const originalFetch = global.fetch;
afterEach(() => { global.fetch = originalFetch; __resetConfigState(); });

test.each([
  ['missing', '', false, true],
  ['invalid', 'wd_clearance=invalid', false, true],
  ['revoked', 'wd_clearance=' + token, true, false],
])('Lambda API refusal %s carries its actual recoverability', async (reason, cookie, revoked, recoverable) => {
  __resetConfigState();
  const config = { mode: 'enforce', routes: ['/api/*'], allow: { search_engines: false, ai_crawlers: false, monitoring: false }, keys: [{ kid: 'test', public_key: publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64') }], active_credentials: [], denied_fps: revoked ? [fp] : [], generated_at: 0 };
  global.fetch = jest.fn(async () => new Response(JSON.stringify(config)));
  const result = await handler({ Records: [{ cf: { request: { clientIp: '203.0.113.7', method: 'HEAD', uri: '/api/data', querystring: '', headers: { accept: [{ key: 'Accept', value: 'application/json' }], cookie: [{ key: 'Cookie', value: String(cookie) }] } } } }] });
  expect('status' in result && result.status).toBe('403');
  expect(result.headers?.['x-wd-challenge-reason']?.[0]?.value).toBe(reason);
  expect(result.headers?.['x-wd-challenge-recoverable']?.[0]?.value).toBe(String(recoverable));
  expect('body' in result && JSON.parse(result.body ?? '{}')).toEqual({ error: 'clearance required', challenge: { version: 1, reason, recoverable } });
});
