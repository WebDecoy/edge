# WebDecoy at your edge

Deployable WebDecoy components that run in front of your origin. **It fails open**: on any
error — can't reach WebDecoy, can't verify a token, anything unexpected — the request is
forwarded untouched, so it cannot take your site down.

- **Cloudflare** → this repo root, a Worker. Does both jobs below.
- **AWS / CloudFront** → [`aws/`](./aws), a Lambda@Edge function. Enforcement only.

## The two jobs

**Enforcement.** Validates `wd_clearance` tokens at the edge, so a client that has been
denied is stopped before it reaches your origin.

**Detection.** Reports automated clients **that never execute JavaScript** — Googlebot's
crawl pass, GPTBot, ClaudeBot, CCBot, `curl`, most scrapers.

That second one is not a nice-to-have. WebDecoy's page tag runs in the visitor's browser,
which is the impossible place to observe a client that never opens one. On a
JavaScript-only install your Citation Monitor can only ever show browser extensions and
LLM referrals — never a crawler. This Worker is the only thing that closes that gap.

Detection **never blocks, challenges, or modifies a response.** It is a sensor. Enforcement
is the part that acts, and only on clients you have already denied.

## Cloudflare (one click)

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/WebDecoy/edge)

Cloudflare clones this repository into your own GitHub or GitLab account and deploys it to
your Cloudflare account. Set two variables:

| Variable | What it is |
|---|---|
| `WD_SITE_KEY` | Your WebDecoy organization id. Integrations → Cloudflare in the app. |
| `WD_API_BASE` | Leave as `https://ingest.webdecoy.com` unless told otherwise. |

Without a correct `WD_SITE_KEY` the Worker runs and reports under no organization, which
looks identical to it not working.

### Then bind a route — this part is not automatic

**Deploying a Worker does not put it in the request path.** Until you add a route it runs
for nothing. *Workers & Pages → your Worker → Settings → Domains & Routes → Add route*:

```
example.com/*
```

The WebDecoy app can deploy and bind routes for you in one step — Integrations →
Cloudflare → Edge Sensor. This repository is for people who prefer to own the deployment.

### Then check the record is proxied

Worker routes only fire on **proxied** (orange-cloud) DNS records. On a DNS-only record
Cloudflare accepts the route and the Worker never runs — the install looks successful and
reports nothing, indefinitely. Confirm the orange cloud in *DNS → Records*.

## Invocations

The Worker consumes an invocation for every request it runs on; Workers' free tier is
100,000/day. Routes bound to **no script** stop any Worker running on a more specific path,
because Cloudflare matches most-specific-first. Adding these keeps it off asset traffic:

```
/_astro/*   /_next/*   /_nuxt/*   /_app/*   /assets/*   /static/*
/build/*    /dist/*    /wp-content/*   /wp-includes/*   /cdn-cgi/*
```

They affect **every** Worker on those paths, not just this one.

## Uninstall

Delete the route first, then the Worker. Deleting the Worker while a route still points at
it leaves the route referencing a script that no longer exists, and your visitors are what
discovers that.

## Privacy

The beacon carries request metadata — user agent, path, IP, TLS and header
characteristics. It does not carry request or response bodies, cookies, or credentials.

## `worker.js` is generated

It is published byte-identical to the script WebDecoy's one-click installer deploys, so
both paths run the same code. `aws/` is maintained as source.

Please do not send pull requests against `worker.js`; they cannot be merged. Open an issue,
or mail support@webdecoy.com.
