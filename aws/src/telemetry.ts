/**
 * Verdict telemetry (#435) — the Lambda@Edge twin of the Worker's module.
 *
 * Same job: the validator decides something about every request, and without
 * this the decision goes to the origin in a header and is never seen by
 * WebDecoy again.
 *
 * ONE DELIBERATE DIFFERENCE from the Worker. Cloudflare gives us
 * `ctx.waitUntil`, so there the network cost of a flush is genuinely free.
 * Lambda@Edge has no such thing: the execution environment may be frozen the
 * moment the handler returns, so a fire-and-forget promise is not merely
 * unreliable, it is usually dropped. The choice is therefore between losing
 * almost every report and paying for it on the request that closes a window.
 *
 * We pay, but tightly:
 *   - at most one flush per window, so the cost lands on 1 request in N;
 *   - capped at FLUSH_TIMEOUT_MS, well under the viewer-request budget;
 *   - and abandoned rather than retried, because a viewer-request function is
 *     the worst possible place to be clever about delivery.
 *
 * If that trade ever looks wrong for a high-traffic deployment, the honest fix
 * is a longer window, not a background promise that silently reports nothing.
 */

/** Flush window, matching the Worker so both edges bucket identically. */
const WINDOW_SECONDS = 60;

/** Bounds what an evicted container loses on a busy distribution. */
const MAX_PER_WINDOW = 500;

/**
 * Hard cap on the one request per window that pays for the flush. Deliberately
 * far tighter than the Worker's, because here it is on the critical path.
 */
const FLUSH_TIMEOUT_MS = 400;

interface PendingWindow {
  bucketStart: number;
  mode: string;
  counts: Map<string, number>;
  total: number;
}

let pending: PendingWindow | null = null;

/**
 * Normalise a verdict label to the set the backend accepts.
 *
 * This edge reports `verified-bot:<category>` — richer than the Worker's bare
 * `verified-bot`, because AWS has no platform bot signal and we resolve the
 * category ourselves. The reporting endpoint validates against a closed set
 * taken from the Worker, so the composite form would be dropped as unknown and
 * AWS deployments would silently report no verified-crawler traffic at all.
 *
 * Normalising here rather than widening the backend's set is the right way
 * round: the label written to x-wd-clearance stays as informative as it is
 * today, and the two edges agree on the vocabulary they report in.
 */
export function normaliseVerdictLabel(label: string): string {
  const colon = label.indexOf(':');
  return colon === -1 ? label : label.slice(0, colon);
}

/**
 * Record one verdict. Returns a promise ONLY when a window closed and needs
 * flushing; the caller awaits it so the write happens before the container can
 * freeze. Never rejects.
 */
export function recordVerdict(
  label: string,
  mode: string,
  siteKey: string,
  apiBase: string,
  now: number = Date.now()
): Promise<void> | undefined {
  try {
    if (!label || !siteKey || !apiBase) return undefined;

    const normalised = normaliseVerdictLabel(label);
    const bucketStart = Math.floor(now / 1000 / WINDOW_SECONDS) * WINDOW_SECONDS;

    let toFlush: PendingWindow | null = null;
    if (pending && (pending.bucketStart !== bucketStart || pending.mode !== mode)) {
      toFlush = pending;
      pending = null;
    }
    if (!pending) {
      pending = { bucketStart, mode, counts: new Map(), total: 0 };
    }

    pending.counts.set(normalised, (pending.counts.get(normalised) ?? 0) + 1);
    pending.total++;

    if (!toFlush && pending.total >= MAX_PER_WINDOW) {
      toFlush = pending;
      pending = null;
    }

    return toFlush ? flush(toFlush, siteKey, apiBase) : undefined;
  } catch {
    return undefined;
  }
}

async function flush(win: PendingWindow, siteKey: string, apiBase: string): Promise<void> {
  try {
    if (win.total <= 0 || win.counts.size === 0) return;

    const counts: Record<string, number> = {};
    for (const [label, count] of win.counts) counts[label] = count;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FLUSH_TIMEOUT_MS);
    try {
      await fetch(apiBase.replace(/\/+$/, '') + '/api/v1/clearance/telemetry', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          organization_id: siteKey,
          bucket_start: win.bucketStart,
          mode: win.mode,
          counts,
        }),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }
  } catch {
    // Timed out, network refused, JSON threw. The window is lost; the request
    // is not, and that is the only ordering that matters.
  }
}

/** Test seam: drop any accumulated window without sending it. */
export function __resetTelemetry(): void {
  pending = null;
}

/** Test seam: inspect the un-flushed window. */
export function __pendingTelemetry(): { bucketStart: number; mode: string; counts: Record<string, number> } | null {
  if (!pending) return null;
  const counts: Record<string, number> = {};
  for (const [label, count] of pending.counts) counts[label] = count;
  return { bucketStart: pending.bucketStart, mode: pending.mode, counts };
}
