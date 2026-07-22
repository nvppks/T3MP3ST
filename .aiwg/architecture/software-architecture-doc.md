# Software Architecture Document — Current-State Baseline

**System:** T3MP3ST  
**Baseline:** revision `186afe6` on 2026-07-20  
**Status:** BASELINED (brownfield description)  
**Scope:** Implemented repository state; `VISION.md` is a directional source, not proof of implementation.

## 1. Purpose and Architectural Drivers

T3MP3ST turns a model or coding agent into the reasoning layer of a local offensive-security platform. The architecture must coordinate long-running, tool-backed security work while preserving target authorization, evidence, and honest claims. The strongest drivers are therefore not raw throughput. They are safe execution, local control, portability across reasoning providers, reproducibility, and the ability to evolve specialized security domains without copying the whole platform.

The system supports UC-001 through UC-005. UC-001 drives mission and safety boundaries; UC-002 drives provider abstraction; UC-003 drives multiple delivery adapters; UC-004 drives source-ingest extensibility; UC-005 drives the committed benchmark/provenance subsystem. NFR-01 through NFR-12 constrain all changes, particularly scope, authorization, provenance, secret isolation, and maturity labeling.

## 2. System Context

The principal human is an authorized operator. The operator uses a terminal, the browser War Room, or an integrating client. T3MP3ST communicates with one or more hosted model APIs, local inference servers, or authenticated local coding-agent processes. It invokes internal Node implementations and approved external security tools against targets named in rules of engagement. It writes local reports, evidence, configuration, and benchmark results. MCP clients can request the narrower MCP-exposed capability. GitHub hosts source collaboration and CI, while isolated Docker environments support application and challenge execution.

Trust boundaries exist between: browser and localhost server; client and HTTP/MCP adapters; T3MP3ST and each model provider; the orchestration core and tool processes; tools and target networks; runtime and local artifact storage; repository source and third-party benchmark/tool corpora. No diagram or prose may collapse these into a single trusted process merely because deployment is local.

## 3. Architectural Style

The implementation is a modular TypeScript monolith with ports/adapters characteristics. Domain modules share one Node.js runtime and package but expose cohesive responsibilities. Delivery adapters translate CLI, HTTP, library, and MCP calls into common modules. Provider adapters translate common model requests to hosted APIs, local OpenAI-compatible endpoints, or connected coding agents. Arsenal adapters translate approved tool intents to internal functions or external processes. Filesystem artifacts form the principal persistence mechanism; there is no application database in the current baseline.

This style is intentional for a self-hosted tool: installation remains straightforward, domain operations can share typed contracts, and local artifacts remain visible to operators. The cost is that dependency discipline must be maintained in code review because process boundaries do not enforce module boundaries.

## 4. Runtime and Deployment Views

### 4.1 CLI and Library

`src/cli.ts` provides the operator command surface, while `src/index.ts` exports the library-facing composition surface. Commands construct configuration, targets, missions, operators, and tools in-process. This is the lowest-overhead path and the natural entry for scripts and terminal operators.

### 4.2 War Room and HTTP API

`src/server.ts` hosts the browser War Room assets and JSON endpoints. It binds to `127.0.0.1:3333` by default. Localhost CORS/origin and Host-header defenses matter because HTTP endpoints can initiate local tool or model activity. Docker Compose preserves this boundary by publishing `127.0.0.1:3333:3333`, mounts `reports/` and `evidence/`, and checks `/api/health`.

### 4.3 MCP

`src/mcp-server.ts` exposes a stdio MCP server with a deliberately narrower supported surface than the entire HTTP/CLI application. MCP is an adapter, not a second mission engine; it must reuse shared validation and tool behavior and avoid silently broadening privileges.

### 4.4 Model and Agent Providers

`src/llm/`, `src/config/`, and agent/provider code resolve credentials, model identifiers, capabilities, timeouts, and fallback. Cloud-provider keys are optional when a connected local agent or local OpenAI-compatible server is used. Provider output is untrusted input to orchestration: it may suggest operations, but target, approval, evidence, and tool contracts remain authoritative.

## 5. Core Logical Components

### 5.1 Mission and Orchestration

`src/mission/` owns mission state and lifecycle. `src/admiral/` and `src/orchestration/` plan and coordinate tasks, context packs, prompts, and adjudication. `src/operators/` supplies role-specific behavior. The current system implements a coordinated operator model, but public evidence is stronger for benchmarked single-agent paths than for reliable end-to-end swarm exploitation. The architecture baseline therefore classifies swarm superiority as unproven rather than an invariant.

### 5.2 Target, Scope, and OPSEC

`src/target/` represents the authorized target context. `src/opsec/` and arsenal approval logic apply operational constraints. Once a mission target is set, built-in networked tools reject unrelated public hosts while allowing target/subdomain and loopback/private contexts under documented rules. Exact-origin target headers prevent credential forwarding to a different origin. These controls implement NFR-01, NFR-02, and NFR-05 and are the primary safety boundary.

### 5.3 Arsenal

`src/arsenal/` provides catalog, parser, adapter, post-exploitation, and approval modules. Some tools are internal Node implementations; others adapt external binaries. Dangerous or catalog-only drivers have narrow approved paths instead of generic arbitrary execution. Tool output is evidence, not automatically a validated finding. Changes here require adversarial tests for argument construction, scope propagation, timeout/exit behavior, and output parsing.

### 5.4 Evidence, Findings, and Reporting

`src/evidence/`, `src/analysis/`, and report/disclosure scripts transform raw observations into retained artifacts and deliverables. Verification scripts and disclosure generation support the transition from candidate to substantiated finding. Reports and evidence are mounted/preserved local paths and may contain credentials or pre-disclosure vulnerabilities; filesystem ownership does not remove the need for retention and access procedures.

### 5.5 Reconnaissance and Source Ingest

Black-box reconnaissance uses real DNS, network, TLS, and HTTP operations. White-box ingestion in `src/recon/code-ingest.ts`, `ts-parse.ts`, `ts-grammars.ts`, and `whitebox.ts` extracts structural units across supported languages using web-tree-sitter, with Python retaining a specialized parser. The current documentation identifies multi-language ingest as experimental. Benchmark results can prove performance on a corpus without promoting the general engine to stable.

### 5.6 Benchmarks and Provenance

`bench/` stores corpora, manifests, ledgers, ground truth, and receipts. Scripts recompute claims, grade flags/findings, test model matrices, and reject fitting. `.github/workflows/ci.yml` runs lint, typecheck, tests, coverage, doctor, claim verification, anti-fitting checks, provenance gate, prompt audit, and smoke tests. This subsystem is part of product architecture because reproducibility is a product promise, not auxiliary documentation.

## 6. Data and State

Configuration comes from environment variables, a local configuration store, and browser localStorage. Target header configuration is origin-bound. Mission state lives in memory and local artifacts according to the execution path. Reports and evidence are persisted in repository-local mounted directories by the Docker setup. Benchmark inputs and derived receipts are committed selectively. Update tooling preserves declared sensitive or expensive local paths.

There is no current transactional application database, distributed queue, centralized cache, or multi-tenant identity store. Any future hosted architecture would introduce fundamentally new trust, tenancy, retention, backup, migration, and compliance requirements and must not be treated as a small deployment variation.

## 7. Security Architecture

The security model assumes the operator host, model output, external tools, target responses, browser requests, and imported repositories may all introduce risk. Default loopback exposure reduces remote attack surface but does not protect against malicious local content or DNS rebinding without Host/origin validation. Scope containment reduces accidental or model-driven egress but must be propagated through every network-capable adapter. Approval gates reduce the chance of executing high-impact actions without human intent. Evidence/provenance controls reduce false reporting but do not make model output trustworthy.

Key failure modes are scope bypass, credential misrouting, shell/argument injection, unsafe parsing, evidence confusion, prompt injection from target/code content, and false maturity claims. CI and smoke tests cover important deterministic contracts; manual/release review remains necessary for new tools and trust-boundary changes.

## 8. Quality and Operations

The project favors deterministic CI that does not require live targets or paid models. Live tests and benchmarks are separated or opt-in. Timeouts bound slow local agents and task/planning calls. Doctor, preflight, smoke, capability, and gauntlet scripts provide layered diagnostics. The current codebase does not establish fleet-level SLOs, centralized observability, on-call, or disaster-recovery objectives, so those are unknown rather than missing implementation promises.

## 9. Vision Relationship

`VISION.md` describes seven research directions: cognitive architecture, swarm dynamics, adversarial machine learning, continuous autonomous operations, knowledge architecture, distributed/edge execution, and evaluation science. The current system strongly realizes evaluation science, partially realizes cognitive/swarm/knowledge ideas, contains research experiments for self-improvement, and leaves persistent autonomy and distributed execution largely future-facing. The authoritative classification and evidence are in `vision-alignment.md`.

Architectural evolution must preserve a two-axis view: maturity of implementation and alignment with direction. A feature can align with the vision while remaining experimental; conversely, a stable implementation need not imply completion of the broader vision vector.

## 10. Architectural Risks and Evolution Rules

The main structural risk is unsafe coupling across delivery, orchestration, provider, and tool layers in a single process. The mitigation is typed shared contracts, narrow adapters, trust-boundary tests, and ADR review. The main product risk is confusing benchmark success with general system maturity. The mitigation is corpus-scoped claims, re-derivation, maturity labels, and the alignment matrix.

Future changes require an ADR when they add a delivery surface, persistence system, privilege boundary, generic execution mechanism, network egress class, provider contract, or maturity promotion. A hosted/multi-tenant mode, distributed worker architecture, or autonomous persistent operation requires a new SAD baseline rather than an amendment that assumes current trust boundaries still apply.

## 11. Traceability

| Use case | Architectural coverage |
| --- | --- |
| UC-001 | Mission/orchestration, target/OPSEC, arsenal, evidence/reporting |
| UC-002 | Model and agent provider adapters |
| UC-003 | CLI/library, War Room/HTTP, MCP runtime views |
| UC-004 | Reconnaissance and source-ingest components |
| UC-005 | Benchmark/provenance subsystem and CI |

## 12. Accepted Decisions

This baseline is governed by:

- ADR-001 — modular monolith and local-first deployment
- ADR-002 — provider-neutral reasoning backbone
- ADR-003 — scope and approval enforcement below model output
- ADR-004 — evidence-derived public claims
- ADR-005 — explicit separation of current state from research vision
