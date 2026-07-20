# LeakLens integration

T3MP3ST invokes LeakLens as an external process and keeps the projects separable. No LeakLens source or rules are copied into this repository.

## Data flow

```text
Burp request/response
  -> explicit T3MP3ST LeakLens action
  -> loopback POST /api/leaklens/scan
  -> program-scope gate
  -> temporary mode-0600 file or scoped URL invocation
  -> leaklens scan --format json
  -> redacting parser boundary
  -> masked findings returned to Burp
```

The existing Burp bridge server now mounts both APIs:

```text
/api/burp/*       authorization differential workflow
/api/leaklens/*   client-side secret scanning workflow
```

Run it with:

```bash
npx tsx src/integrations/burp/server.ts
```

## Bridge request modes

### Scan a captured response body

```json
{
  "kind": "content",
  "contentBase64": "...",
  "sourceUrl": "https://app.example.test/static/app.js",
  "sourceMethod": "GET",
  "fileName": "app.js",
  "jsIntel": true,
  "scope": {
    "program": "authorized-bounty",
    "included": [{ "host": "app.example.test", "methods": ["GET"] }]
  }
}
```

### Scan or crawl a scoped URL

```json
{
  "kind": "url",
  "targetUrl": "https://app.example.test/",
  "crawl": true,
  "jsIntel": true,
  "rateLimit": 3,
  "concurrency": 2,
  "scope": {
    "program": "authorized-bounty",
    "included": [{ "host": "app.example.test", "methods": ["GET"] }]
  }
}
```

The bridge hard-bounds crawl concurrency to 4 and rate limit to 10 requests per second. It always supplies `--no-update-check`, uses `execFile` with a fixed argument template, and never enables LeakLens AI review.

## Redaction contract

LeakLens JSON can contain credential material in `Groups`, `NamedGroups`, and snippets. The bridge consumes those fields only long enough to create:

```json
{
  "findingId": "...",
  "ruleId": "...",
  "ruleName": "...",
  "source": "...",
  "line": 42,
  "maskedValue": "A1b2…O5p6",
  "secretSha256": "...",
  "validation": "not_run",
  "evidenceArtifact": "leaklens:<finding>:<match>"
}
```

Raw values, raw scanner stdout, snippets, authorization headers, and cookie values are not returned to Burp or inserted into the T3MP3ST evidence channel.

## Live validation gate

Provider validation is disabled by default because it creates outbound requests using the detected credential. Enabling it requires both:

```bash
T3MP3ST_LEAKLENS_ALLOW_VALIDATE=1
```

and a non-empty `approvalId` in the scan request. The Burp extension does not request validation in this increment.

## Burp extension

The LeakLens integration is packaged as a separate Burp extension so it can be loaded alongside the existing AuthZ workflow extension:

```bash
cd integrations/leaklens-burp
gradle jar
```

Context-menu actions:

- `Scan response body`
- `Scan selected asset URL`
- `Crawl application JS assets`

The Suite tab reports only sanitized findings. Response-body scanning is capped at 20 MiB and remains operator-triggered.

## License boundary

LeakLens is Apache-2.0 licensed. This integration communicates with its installed binary through a subprocess interface and retains upstream attribution in this document. If LeakLens code or rules are copied later, preserve its license and notices explicitly.
