# Harness runners backed by upstream T3MP3ST controls

This fork keeps execution queue-first while reusing upstream runtime controls instead of reimplementing them:

- `src/validation/` supplies JSON Schema generation, schema-depth limits, AJV validation, defaults, and safe scalar coercion.
- `src/arsenal/approval.ts` supplies the canonical gated risk vocabulary.
- `src/net/proxy.ts` supplies SOCKS4/5 egress and local-service bypass behavior.
- `src/recon/` supplies multi-language web-tree-sitter ingest.

## Worker lifecycle

```text
queued
  -> leased
  -> schema validation
  -> approval receipt when risk is intrusive/credential/dangerous
  -> running + heartbeat + AbortController
  -> completed / retry / failed / killed
```

The standalone harness starts its worker by default:

```bash
npm run harness
```

Disable automatic execution when using an external worker:

```bash
T3MP3ST_HARNESS_WORKER_AUTO=0 npm run harness
```

The combined Burp/LeakLens bridge keeps the worker manual by default. Enable it explicitly:

```bash
T3MP3ST_HARNESS_WORKER_AUTO=1 npx tsx src/integrations/burp/server.ts
```

## Registered runners

### `whitebox_ingest`

Runs the upstream multi-language ingest over a local repository path.

```json
{
  "programId": "acme",
  "kind": "whitebox_ingest",
  "config": {
    "repoPath": "/path/to/repo",
    "maxFiles": 50000,
    "maxUnits": 500,
    "reportUnits": 100
  }
}
```

The detailed analysis, including retained source bodies, is stored as a sealed artifact. The report artifact contains paths, line spans, exposure, reachability, risk signals, and priority without source bodies.

### `http_probe`

Sends one request to the job's centrally scoped target. The target must be supplied through the normal job `target` field so scope is checked before enqueue.

```json
{
  "programId": "acme",
  "kind": "http_probe",
  "target": {
    "url": "https://app.example.com/health",
    "method": "GET"
  },
  "config": {
    "timeoutMs": 15000,
    "maxBodyBytes": 2000000,
    "egress": { "mode": "direct" }
  }
}
```

SOCKS mode references a sealed artifact rather than placing credentials in queue state:

```json
{
  "egress": {
    "mode": "socks",
    "proxyArtifactId": "art_..."
  }
}
```

The sealed artifact content is a single SOCKS URL such as `socks5h://user:password@127.0.0.1:1080`. Explicit direct/SOCKS jobs are serialized because the upstream undici dispatcher is process-global. The configured upstream proxy is restored after each job.

## Approval receipts

Gated runners create one exact-job receipt and pause the job:

```http
GET /api/harness/approvals?status=pending
Authorization: Bearer <harness-token>
```

Approve and resume that same job:

```http
POST /api/harness/approvals/<receipt-id>/approve
Authorization: Bearer <harness-token>
Content-Type: application/json

{"note":"approved for this program and request"}
```

Denying the receipt kills the associated job:

```http
POST /api/harness/approvals/<receipt-id>/deny
Authorization: Bearer <harness-token>
Content-Type: application/json

{"note":"not permitted by program rules"}
```

Receipts are persisted in `.t3mp3st-harness/approvals.json` with mode `0600`. Approval does not authorize other jobs or other programs.

## Worker API

```text
GET  /api/harness/worker/health       public status
GET  /api/harness/runners             registered schemas and risks
GET  /api/harness/worker/status
POST /api/harness/worker/start
POST /api/harness/worker/stop
POST /api/harness/worker/run-once
```

All endpoints except worker health require the harness bearer token.
