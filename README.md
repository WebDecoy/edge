# WebDecoy clearance edge validators

Deployable templates for the WebDecoy clearance edge validator — the piece that
enforces `wd_clearance` tokens at your CDN edge. It **fails open**: on any error
(can't reach WebDecoy, can't verify a token, anything unexpected) it forwards the
request untouched, so it can never take your site down.

> Mirror of `edge/` in the WebDecoy monorepo, published so the deploy paths below
> work against a public repo. Keep in sync with the monorepo.

- **Cloudflare** → this repo root (a Worker).
- **AWS / CloudFront** → [`aws/`](./aws) (a Lambda@Edge function).

## Cloudflare (one click)

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/WebDecoy/clearance-validators)

After it deploys into **your** Cloudflare account, set two variables and a route
(the WebDecoy dashboard → **Integrations → Enforcement → Deploy & verify**
pre-fills these for you):

| Variable | Value |
|---|---|
| `WD_SITE_KEY` | your publishable site key (organization id) |
| `WD_API_BASE` | `https://ingest.webdecoy.com` |

Add a **route** for the hostnames you want validated (e.g. `example.com/*`), then
run the deployment check in the dashboard to confirm it's live before switching
enforcement to **enforce**.

### Manual

```bash
npm install
# set WD_SITE_KEY + WD_API_BASE + your route in wrangler.toml
npx wrangler deploy
```

## AWS / CloudFront

See [`aws/README.md`](./aws). Lambda@Edge has more moving parts (us-east-1, an IAM
role, a published version associated with your CloudFront viewer-request behavior);
the `aws/template.yaml` CloudFormation stack provisions the function + role +
version for you.

## How it decides

Each request passes if any of these hold, in order: a valid **machine service
token** header → a **verified crawler** → an **unscoped path** → a valid
**`wd_clearance` cookie** (whose fingerprint hasn't been decoy-denied). Otherwise
monitor mode annotates and passes; enforce mode returns a one-time invisible
challenge. Everything it needs — mode, routes, keys, allowlist, revocations —
comes from a cached config poll; there is no per-request call to WebDecoy.

## Verify

```bash
npm run typecheck   # Cloudflare worker
cd aws && npm test  # Lambda: token verification, rDNS, healthcheck
```
