/**
 * Deploy-time configuration. Lambda@Edge viewer-request functions cannot use
 * environment variables, so these are code constants the customer sets before
 * `npm run deploy`. (The Cloudflare Worker uses wrangler vars for the same values.)
 */
export const CONFIG = {
  /** Publishable WebDecoy site key (the organization id). */
  siteKey: 'YOUR-SITE-KEY',
  /** WebDecoy ingest origin (issuance + config endpoints). */
  apiBase: 'https://ingest.webdecoy.com',
};
