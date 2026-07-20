# Harness control plane

This module is the deterministic queue and evidence layer for T3MP3ST's bug-bounty workflow. It is intentionally independent from the agent mission loop.

```text
Burp / mitmproxy / manual capture
        -> normalized request metadata
        -> central program scope check
        -> persistent job queue
        -> leased runner work
        -> content-addressed evidence
        -> report-safe or private evidence bundle
```

## Start it

Standalone:

```bash
npm run harness
```

The existing Burp bridge server also mounts it:

```bash
npx tsx src/integrations/burp/server.ts
```

Defaults:

```text
Standalone URL: http://127.0.0.1:3444/api/harness
Burp bridge URL: http://127.0.0.1:3000/api/harness
State directory: ./.t3mp3st-harness
```

Override them with:

```bash
T3MP3ST_HARNESS_HOST=127.0.0.1
T3MP3ST_HARNESS_PORT=3444
T3MP3ST_HARNESS_DIR=/private/path/acme-harness
T3MP3ST_HARNESS_TOKEN=<optional-fixed-token>
```

Only `/health` is unauthenticated. The control plane creates a 256-bit bearer token at:

```text
.t3mp3st-harness/api-token
```

Use it as:

```bash
TOKEN="$(cat .t3mp3st-harness/api-token)"
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:3444/api/harness/programs
```

The root directory is mode `0700`; token, snapshot, event log, and evidence files are mode `0600` where the operating system supports POSIX permissions.

## Storage layout

```text
.t3mp3st-harness/
├── api-token
├── control.lock
├── state.json
├── events.jsonl
├── artifacts/
│   └── <program-hash>/<sha-prefix>/<sha256>
└── exports/
    └── <program-hash>/<bundle-id>/
```

`state.json` is the authoritative dependency-free MVP snapshot. `events.jsonl` is an append-only audit stream with monotonic sequence cursors. Artifact bytes are content-addressed and partitioned by a hash of the program ID, so identical evidence from different programs does not share an artifact namespace.

The process takes an exclusive `control.lock`. Do not run the standalone server and Burp bridge against the same state directory at the same time.

## Register a program

```bash
curl -X POST http://127.0.0.1:3444/api/harness/programs \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "h1-acme-2026-q3",
    "label": "ACME public bounty",
    "scope": {
      "program": "h1-acme-2026-q3",
      "included": [
        {
          "host": "app.example.com",
          "includeSubdomains": true,
          "methods": ["GET", "POST", "PUT", "PATCH", "DELETE"]
        }
      ],
      "excluded": [
        { "host": "status.example.com", "includeSubdomains": true }
      ]
    },
    "maxConcurrency": 2,
    "maxRequestsPerSecond": 3
  }'
```

Scope is checked before a request is ingested and before a URL-backed job is queued. The full target URL is stored only as a sealed artifact; queue state and events receive a display URL with query values removed.

## Auth capsules

Auth capsules are references, not credentials:

```bash
curl -X POST http://127.0.0.1:3444/api/harness/auth-capsules \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "user-a",
    "programId": "h1-acme-2026-q3",
    "owner": "burp",
    "label": "User A",
    "role": "user",
    "tenant": "tenant-a",
    "replayReference": "burp:user-a"
  }'
```

Cookie and token values remain in Burp or a local secret store. Job configuration rejects common inline credential fields and known secret patterns; use an auth capsule or sealed artifact ID instead.

## Ingest a request

```bash
curl -X POST http://127.0.0.1:3444/api/harness/requests \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "programId": "h1-acme-2026-q3",
    "source": "burp",
    "method": "GET",
    "url": "https://app.example.com/api/orders/123?view=full",
    "headers": {
      "Authorization": "Bearer live-value",
      "Accept": "application/json"
    },
    "authCapsuleId": "user-a"
  }'
```

The result contains safe metadata plus two artifact references:

```text
sealedRequestArtifactId  full URL, headers, and body for local reproduction
reportRequestArtifactId  redacted headers, safe URL, body hash, and size
```

Raw request material never enters `state.json` or `events.jsonl`.

## Queue lifecycle

```text
queued -> leased -> running -> completed
                     └------> failed
queued/leased/running -> paused
queued/leased/running/paused -> killed
```

Create a job:

```bash
curl -X POST http://127.0.0.1:3444/api/harness/jobs \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "programId": "h1-acme-2026-q3",
    "kind": "replay",
    "requestId": "req_...",
    "authCapsuleId": "user-a",
    "priority": 20,
    "maxAttempts": 3,
    "config": {
      "mutationProfile": "object-id-neighbor"
    }
  }'
```

Lease work:

```bash
curl -X POST http://127.0.0.1:3444/api/harness/jobs/lease \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "workerId": "burp-worker-1",
    "kinds": ["replay"],
    "leaseMs": 30000
  }'
```

A lease records the worker, heartbeat, and expiration. Expired jobs are requeued with bounded exponential delay until `maxAttempts` is exhausted. Program concurrency and token-bucket job-start rate limits are enforced centrally during leasing.

Worker transitions:

```text
POST /jobs/:id/running
POST /jobs/:id/heartbeat
POST /jobs/:id/complete
POST /jobs/:id/fail
POST /jobs/:id/release
```

A process runner can register an `AbortController` directly with `HarnessControlPlane.registerAbortController()`. Per-job, per-program, and global kill operations abort registered controllers and prevent killed jobs from later being completed.

## Kill switches

Pause prevents new leases but preserves current state:

```text
POST /control/pause-all
POST /programs/:id/pause
POST /jobs/:id/pause
```

Kill is explicit and confirmation-gated over REST:

```bash
curl -X POST http://127.0.0.1:3444/api/harness/control/kill-all \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"confirm":"KILL_ALL"}'
```

Other confirmation strings:

```text
KILL_PROGRAM
KILL_JOB
```

`resume-all` or program `resume` reactivates dispatch, but previously killed jobs remain terminal.

## Evidence tiers

Artifacts use three tiers:

| Tier | Purpose | Default exposure |
|---|---|---|
| `sealed` | Full secret, authenticated raw request, original scanner result | Explicit local reveal/private bundle only |
| `operator` | Raw request/response or validation transcript used for analyst review | Operator/private bundle |
| `report` | Sanitized request/response, masked credential, screenshot, summary | Report-safe bundle |

Store evidence:

```bash
curl -X POST http://127.0.0.1:3444/api/harness/artifacts \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "programId": "h1-acme-2026-q3",
    "tier": "sealed",
    "mediaType": "text/plain",
    "fileName": "credential.txt",
    "source": "leaklens finding-1",
    "contentBase64": "..."
  }'
```

Reveal requires the bearer token and a deliberate confirmation:

```text
POST /artifacts/:id/reveal
{"confirm":"REVEAL_LOCAL_EVIDENCE"}
```

## Reproduction and report bundles

Create a report-safe bundle:

```bash
curl -X POST http://127.0.0.1:3444/api/harness/bundles \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "programId": "h1-acme-2026-q3",
    "findingId": "finding-001",
    "mode": "report-safe",
    "reportMarkdown": "# Exposed API credential",
    "artifactIds": ["art_sealed...", "art_operator...", "art_report..."]
  }'
```

Bundle modes:

| Mode | Included evidence |
|---|---|
| `report-safe` | `report` only; report text is redacted |
| `operator-review` | `report` + `operator`; sealed evidence remains referenced but omitted |
| `private-full` | all tiers, including full credential/raw evidence |

`private-full` additionally requires:

```json
{"confirm":"INCLUDE_SEALED_EVIDENCE"}
```

Each bundle contains `README.md`, `manifest.json`, SHA-256 values, artifact tiers, and copied evidence files. This preserves the original material needed to reproduce a finding while keeping the normal report export safe. The private bundle is local mode-0600 material; encrypt it with the submission channel's supported mechanism before sending outside the workstation.

## Event stream

```bash
curl -H "Authorization: Bearer $TOKEN" \
  'http://127.0.0.1:3444/api/harness/events?cursor=0&limit=200'
```

Use `nextCursor` for the next poll. Events contain IDs, lifecycle transitions, safe target metadata, artifact hashes, and approval/kill actions. They never include artifact content, raw request envelopes, auth material, or API tokens.

## Current boundary

This increment implements the deterministic control plane, not the runners. Burp replay, LeakLens, ffuf, nuclei, and OAST workers should consume leases and return result artifact IDs through this API. The snapshot backend is single-process and dependency-free; a future SQLite backend can implement the same control-plane contract when multi-process workers are required.
