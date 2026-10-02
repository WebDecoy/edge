import { handler, __resetConfigState } from './index';

/**
 * Config fetching under an outage (#1245): one attempt per backoff window, not
 * one 3 second wait per request.
 */

function event() {
  return { Records: [{ cf: { request: { clientIp: '198.51.100.1', method: 'GET', uri: '/', querystring: '', headers: {} } } }] };
}

const original = global.fetch;
let calls = 0;
function serve(answer: () => Response) {
  calls = 0;
  global.fetch = (async () => {
    calls++;
    return answer();
  }) as typeof fetch;
}

beforeEach(() => {
  __resetConfigState();
  jest.useFakeTimers();
  jest.setSystemTime(new Date('2026-10-02T12:00:00Z'));
});
afterEach(() => {
  global.fetch = original;
  jest.useRealTimers();
});

describe('Lambda config fetch under an outage', () => {
  it('backs off after a failure instead of fetching on every request', async () => {
    serve(() => new Response('', { status: 503 }));
    for (let i = 0; i < 10; i++) await handler(event() as never);
    expect(calls).toBe(1);
    jest.setSystemTime(Date.now() + 31_000);
    await handler(event() as never);
    expect(calls).toBe(2);
  });

  it('honours Retry-After', async () => {
    serve(() => new Response('', { status: 429, headers: { 'retry-after': '120' } }));
    await handler(event() as never);
    jest.setSystemTime(Date.now() + 60_000);
    await handler(event() as never);
    expect(calls).toBe(1);
    jest.setSystemTime(Date.now() + 61_000);
    await handler(event() as never);
    expect(calls).toBe(2);
  });
});
