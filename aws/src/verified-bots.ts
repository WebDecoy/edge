/**
 * Verified-bot check via forward-confirmed reverse DNS (WAF Enforcement PRD FR9-b).
 *
 * On Cloudflare we consume `verifiedBotCategory` — the platform did the work. AWS
 * has no equivalent, so we verify crawlers ourselves the industry-standard way:
 * reverse-DNS the client IP, confirm the PTR ends in a known operator suffix, then
 * FORWARD-resolve that hostname and confirm the original IP is in the answer. A
 * cloud VM can't fake this — it can't set a `googlebot.com` PTR, and it can't add
 * a forward record in Google's zone.
 *
 * Scope: this covers operators that publish forward-confirmable rDNS (search
 * engines, solidly). Operators that publish ONLY IP ranges (most AI crawlers, many
 * monitors) need the range-feed layer — a documented follow-up. Never uses
 * User-Agent, never trusts a provider ASN.
 */

export type BotCategory = 'search_engines' | 'ai_crawlers' | 'monitoring';

export interface AllowToggles {
  search_engines: boolean;
  ai_crawlers: boolean;
  monitoring: boolean;
}

/** Minimal DNS surface, injected so the logic is testable without real lookups. */
export interface DnsResolver {
  reverse(ip: string): Promise<string[]>;
  resolve4(host: string): Promise<string[]>;
  resolve6(host: string): Promise<string[]>;
}

/**
 * Known crawler PTR suffixes with reliable forward-confirmable rDNS, grouped by
 * allow category. Suffixes are matched against the full lowercased PTR hostname.
 */
const SUFFIXES: { category: BotCategory; suffixes: string[] }[] = [
  {
    category: 'search_engines',
    suffixes: [
      '.googlebot.com',
      '.google.com',
      '.search.msn.com', // Bingbot
      '.crawl.yahoo.net',
      '.applebot.apple.com',
      '.yandex.com',
      '.yandex.net',
      '.yandex.ru',
      '.crawl.baidu.com',
      '.crawl.baidu.jp',
    ],
  },
];

function matchCategory(hostname: string, allow: AllowToggles): BotCategory | null {
  const h = hostname.toLowerCase().replace(/\.$/, '');
  for (const group of SUFFIXES) {
    if (!allow[group.category]) continue;
    for (const suffix of group.suffixes) {
      if (h.endsWith(suffix)) return group.category;
    }
  }
  return null;
}

interface CacheEntry {
  category: BotCategory | null;
  at: number;
}
const cache = new Map<string, CacheEntry>();
const CACHE_TTL_MS = 3_600_000; // 1h — verification is stable per IP
const CACHE_MAX = 5_000;

/**
 * Returns the allowed bot category for an IP, or null if it isn't a verified
 * crawler in an enabled category. Forward-confirms every PTR match. Any DNS error
 * yields null (not a verified bot) — the request then falls through to the token
 * check, never auto-allowed on a failed lookup.
 */
export async function verifyBot(
  ip: string,
  allow: AllowToggles,
  dns: DnsResolver,
  now: number,
): Promise<BotCategory | null> {
  const cached = cache.get(ip);
  if (cached && now - cached.at < CACHE_TTL_MS) {
    return cached.category;
  }

  let result: BotCategory | null = null;
  try {
    const ptrs = await dns.reverse(ip);
    for (const ptr of ptrs) {
      const category = matchCategory(ptr, allow);
      if (!category) continue;
      if (await forwardConfirms(ptr, ip, dns)) {
        result = category;
        break;
      }
    }
  } catch {
    result = null;
  }

  if (cache.size >= CACHE_MAX) cache.clear();
  cache.set(ip, { category: result, at: now });
  return result;
}

async function forwardConfirms(hostname: string, ip: string, dns: DnsResolver): Promise<boolean> {
  const host = hostname.replace(/\.$/, '');
  const resolvers = ip.includes(':') ? [dns.resolve6(host)] : [dns.resolve4(host)];
  try {
    const answers = (await Promise.all(resolvers)).flat();
    return answers.some((a) => a === ip);
  } catch {
    return false;
  }
}

/** Test-only: reset the warm-container cache. */
export function _resetCache(): void {
  cache.clear();
}
