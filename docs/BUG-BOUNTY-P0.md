# Bug bounty P0 core

The P0 core is intentionally deterministic and model-independent. Burp, CLI, MCP, or an agent can feed observations into the same pipeline without changing adjudication behavior.

## Pipeline

```text
ProgramScope
  -> AssetGraph
  -> HttpObservation
  -> analyzeAuthzDifferential
  -> assessBlackBoxEvidence
  -> deduplicateFindings
  -> renderBountyReport
```

## Included capabilities

- Program scope enforcement by protocol, host, subdomain, path, method, and exclusion.
- Canonical assets and endpoints with dynamic ID normalization.
- Multi-identity authorization differential analysis for BOLA/BFLA/cross-tenant candidates.
- Semantic response comparison with volatile field removal.
- Black-box evidence ladder from discovery through report readiness and retest.
- Stable finding fingerprints, duplicate suppression, and bounty-style Markdown reports.

## Burp integration contract

A Burp extension should capture and replay requests. T3MP3ST should only receive normalized observations and return candidate replay jobs.

```ts
import {
  AssetGraph,
  analyzeAuthzDifferential,
  assessBlackBoxEvidence,
} from '../src/bounty/index.js';
```

Each Burp identity should map to an `IdentityContext`. Every replay result should become an `HttpObservation` carrying immutable evidence IDs for the raw request and response stored by the adapter.

The extension must evaluate `ProgramScope` before replay. It should preserve Burp's cookie jar, session handling rules, client certificates, upstream proxy, and HTTP/2 behavior.

## Safety and confidence

An HTTP 200 response alone is not a confirmed finding. A high-confidence authorization candidate should include:

1. A successful owner baseline.
2. An attacker replay against the same protected object or action.
3. A denied or behaviorally distinct negative control.
4. At least two successful reproductions.
5. Evidence of the violated security boundary and impact.
6. A scope receipt and redacted evidence.

Only `report_ready` or `retested` evidence should be considered submission-ready.
