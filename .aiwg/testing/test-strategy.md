# Test Strategy — Architecture Baseline

## Objectives

Protect safety boundaries, cross-surface contracts, provider/tool adapters, evidence integrity, and public claims while keeping deterministic CI independent of live targets and paid models.

## Layers

- **Unit:** target normalization, scope predicates, parsers, configuration, provider selection, evidence transforms.
- **Contract:** CLI/HTTP/MCP schemas, provider adapters, tool argument construction, finding/report formats.
- **Integration:** mission lifecycle, connected-agent fallback, server guards, tool execution with controlled fixtures.
- **Security:** off-scope denial, exact-origin credential injection, command/argument injection, Host/origin controls, malicious target/source content.
- **Benchmark/provenance:** claim re-derivation, ground-truth grading, anti-fitting, model matrix, receipt validation.
- **Operational:** build, doctor, preflight, smoke, Docker health, updater preservation.

## Architecture Gate Mapping

| Decision / NFR | Required evidence |
| --- | --- |
| ADR-001 / NFR-04 | Loopback and server guard tests; Docker config review |
| ADR-002 / NFR-06 | Provider selection, fallback, timeout, and local-agent tests |
| ADR-003 / NFR-01/02/05 | Scope, approval, and exact-origin negative tests |
| ADR-004 / NFR-03/09 | Claims, provenance, grading, and anti-fitting gates |
| ADR-005 / NFR-09 | Documentation claim audit against vision-alignment matrix |

## Release Policy

Any regression in scope containment, credential routing, dangerous-tool approval, evidence provenance, or claim reproducibility blocks release. Live benchmark failures are evaluated against declared environment/infrastructure outcomes and cannot be silently converted to model failures or successes.

## Gaps

- Establish workload baselines for source ingestion and concurrent mission tasks.
- Add a machine-checkable maturity/vision consistency audit.
- Document coverage expectations for every external arsenal adapter.
