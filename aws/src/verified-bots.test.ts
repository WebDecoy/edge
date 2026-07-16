import { verifyBot, _resetCache, type AllowToggles, type DnsResolver } from './verified-bots';

const ALL_ON: AllowToggles = { search_engines: true, ai_crawlers: true, monitoring: true };
const NOW = 1_700_000_000_000;

/** Build a resolver from PTR + forward-resolution fixtures. */
function resolver(ptr: Record<string, string[]>, fwd: Record<string, string[]>): DnsResolver {
  return {
    reverse: async (ip) => ptr[ip] ?? Promise.reject(new Error('NXDOMAIN')),
    resolve4: async (h) => fwd[h] ?? [],
    resolve6: async (h) => fwd[h] ?? [],
  };
}

beforeEach(() => _resetCache());

describe('verifyBot (forward-confirmed rDNS)', () => {
  it('verifies Googlebot when the PTR forward-confirms', async () => {
    const dns = resolver(
      { '66.249.66.1': ['crawl-66-249-66-1.googlebot.com'] },
      { 'crawl-66-249-66-1.googlebot.com': ['66.249.66.1'] },
    );
    expect(await verifyBot('66.249.66.1', ALL_ON, dns, NOW)).toBe('search_engines');
  });

  it('rejects a spoofed PTR that does NOT forward-confirm to the same IP', async () => {
    const dns = resolver(
      { '1.2.3.4': ['fake.googlebot.com'] },
      { 'fake.googlebot.com': ['66.249.66.1'] }, // resolves elsewhere, not 1.2.3.4
    );
    expect(await verifyBot('1.2.3.4', ALL_ON, dns, NOW)).toBeNull();
  });

  it('rejects a PTR with no known crawler suffix', async () => {
    const dns = resolver({ '5.6.7.8': ['host.example.com'] }, { 'host.example.com': ['5.6.7.8'] });
    expect(await verifyBot('5.6.7.8', ALL_ON, dns, NOW)).toBeNull();
  });

  it('returns null when the matched category is disabled', async () => {
    const dns = resolver(
      { '66.249.66.1': ['crawl.googlebot.com'] },
      { 'crawl.googlebot.com': ['66.249.66.1'] },
    );
    const off: AllowToggles = { search_engines: false, ai_crawlers: true, monitoring: true };
    expect(await verifyBot('66.249.66.1', off, dns, NOW)).toBeNull();
  });

  it('returns null on a reverse-DNS failure (never auto-allows)', async () => {
    const dns = resolver({}, {});
    expect(await verifyBot('9.9.9.9', ALL_ON, dns, NOW)).toBeNull();
  });

  it('caches the result (second call does not hit DNS)', async () => {
    let reverseCalls = 0;
    const dns: DnsResolver = {
      reverse: async (ip) => {
        reverseCalls++;
        return ip === '66.249.66.1' ? ['x.googlebot.com'] : [];
      },
      resolve4: async () => ['66.249.66.1'],
      resolve6: async () => [],
    };
    await verifyBot('66.249.66.1', ALL_ON, dns, NOW);
    await verifyBot('66.249.66.1', ALL_ON, dns, NOW + 1000);
    expect(reverseCalls).toBe(1);
  });
});
