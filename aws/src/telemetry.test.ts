import { recordVerdict, normaliseVerdictLabel, __resetTelemetry, __pendingTelemetry } from './telemetry';

const SITE_KEY = 'org-uuid';
const API = 'https://ingest.test';
const T = 1_700_000_000_000;

let sent: Record<string, unknown>[];

beforeEach(() => {
  __resetTelemetry();
  sent = [];
  global.fetch = jest.fn(async (_url: unknown, init?: { body?: string }) => {
    if (init?.body) sent.push(JSON.parse(init.body));
    return { ok: true } as unknown as Response;
  }) as unknown as typeof fetch;
});

describe('normaliseVerdictLabel', () => {
  it('strips the category this edge appends to verified-bot', () => {
    // This edge reports verified-bot:<category> because AWS has no platform bot
    // signal and we resolve the category ourselves. The reporting endpoint
    // validates against a closed set, so unnormalised the composite would be
    // dropped as unknown and AWS deployments would report no verified-crawler
    // traffic at all — a silent hole, which is the worst kind.
    expect(normaliseVerdictLabel('verified-bot:search_engine')).toBe('verified-bot');
    expect(normaliseVerdictLabel('verified-bot:ai_crawler')).toBe('verified-bot');
  });

  it('leaves plain labels alone', () => {
    for (const label of ['valid', 'missing', 'invalid', 'revoked', 'unscoped', 'machine']) {
      expect(normaliseVerdictLabel(label)).toBe(label);
    }
  });
});

describe('accumulation', () => {
  it('sends nothing while the window is open', () => {
    expect(recordVerdict('valid', 'monitor', SITE_KEY, API, T)).toBeUndefined();
    expect(recordVerdict('valid', 'monitor', SITE_KEY, API, T + 100)).toBeUndefined();
    expect(sent).toHaveLength(0);
    expect(__pendingTelemetry()?.counts).toEqual({ valid: 2 });
  });

  it('returns a promise only when a window closes, and posts the closed one', async () => {
    recordVerdict('valid', 'monitor', SITE_KEY, API, T);
    const flush = recordVerdict('missing', 'monitor', SITE_KEY, API, T + 61_000);

    // The caller awaits this instead of relying on a background promise, which
    // Lambda@Edge would freeze before it resolved.
    expect(flush).toBeInstanceOf(Promise);
    await flush;

    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({ organization_id: SITE_KEY, mode: 'monitor', counts: { valid: 1 } });
    expect(sent[0].bucket_start).toBe(Math.floor(T / 1000 / 60) * 60);
    expect(__pendingTelemetry()?.counts).toEqual({ missing: 1 });
  });

  it('records the normalised label, not the composite', async () => {
    recordVerdict('verified-bot:search_engine', 'monitor', SITE_KEY, API, T);
    recordVerdict('verified-bot:ai_crawler', 'monitor', SITE_KEY, API, T + 10);
    await recordVerdict('valid', 'monitor', SITE_KEY, API, T + 61_000);

    expect(sent[0].counts).toEqual({ 'verified-bot': 2 });
  });

  it('flushes on a mode change inside one window', async () => {
    recordVerdict('missing', 'monitor', SITE_KEY, API, T);
    await recordVerdict('missing', 'enforce', SITE_KEY, API, T + 500);

    expect(sent).toHaveLength(1);
    expect(sent[0].mode).toBe('monitor');
    expect(__pendingTelemetry()?.mode).toBe('enforce');
  });
});

describe('it cannot break the gate', () => {
  it('never rejects when the network is down', async () => {
    global.fetch = jest.fn(async () => {
      throw new Error('network down');
    }) as unknown as typeof fetch;

    recordVerdict('valid', 'monitor', SITE_KEY, API, T);
    const flush = recordVerdict('valid', 'monitor', SITE_KEY, API, T + 61_000);
    await expect(flush).resolves.toBeUndefined();
  });

  it('never throws on bad inputs, and records nothing', () => {
    expect(() => recordVerdict('valid', 'monitor', '', API, T)).not.toThrow();
    expect(() => recordVerdict('valid', 'monitor', SITE_KEY, '', T)).not.toThrow();
    expect(() => recordVerdict('', 'monitor', SITE_KEY, API, T)).not.toThrow();
    expect(__pendingTelemetry()).toBeNull();
  });
});
