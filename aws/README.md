# WebDecoy clearance validator — AWS Lambda@Edge

The AWS twin of the Cloudflare Worker (repo root), for sites fronted by
**CloudFront**. Same evaluation, same fail-open invariant. Because AWS has no
platform verified-bot signal, this validator verifies crawlers itself via
forward-confirmed reverse DNS.

Lambda@Edge viewer-request has **no environment variables**, so the site key and
ingest origin are code constants in [`src/config.ts`](./src/config.ts) — set them
before you build.

## Deploy (CloudFormation)

```bash
npm install
# set siteKey + apiBase in src/config.ts
npm run build                      # emits dist/
( cd dist && zip -r ../clearance-lambda.zip . )
# upload the zip to an S3 bucket in us-east-1, then:
aws cloudformation deploy \
  --region us-east-1 \
  --stack-name webdecoy-clearance-validator \
  --capabilities CAPABILITY_IAM \
  --template-file template.yaml \
  --parameter-overrides SiteKey=YOUR_SITE_KEY CodeS3Bucket=YOUR_BUCKET
```

The stack outputs `FunctionVersionArn`. Attach it to your CloudFront
distribution's **viewer-request** behavior (Behaviors → Edit → Function
associations → Lambda@Edge, *Viewer request*). Allow a few minutes for the
function to replicate to the edge.

Roll out in **monitor** mode first and run the deployment check in the WebDecoy
dashboard before switching to **enforce**.

## Verify

```bash
npm run typecheck
npm test   # token verification (real backend vector), rDNS, healthcheck
```
