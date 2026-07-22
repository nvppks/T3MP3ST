# Vision-to-Code Alignment Matrix

**Reference:** `VISION.md`  
**Rule:** Alignment is directional; only code/tests/receipts establish implementation maturity.

| Vision vector | Current maturity | Current evidence | Gap / next architectural proof |
| --- | --- | --- | --- |
| Cognitive architecture | Partial / experimental | Admiral planning, context packs, prompts, operator roles, adjudication | Demonstrate durable reasoning-state architecture and comparative outcomes beyond prompt composition |
| Swarm dynamics | Partial / experimental | Eight operator archetypes, orchestration, task assignment, shared mission context | Reproducible end-to-end swarm benchmark showing coordination reliability and value over solo baselines |
| Adversarial machine learning | Research / partial | Refusal-frontier probes, model matrices, adversarial benchmarks, anti-fitting | Formal threat model and stable adaptive defenses against prompt/model manipulation |
| Continuous autonomous operations | Future with small foundations | Mission lifecycle, lessons, update/preflight tooling | Persistent scheduler, safe pause/resume, operator governance, resource budgets, and incident controls |
| Knowledge architecture | Partial / research | Evidence, reports, lessons, benchmark corpora, context packs | Unified provenance-aware knowledge model with retention, conflict, and poisoning controls |
| Distributed and edge execution | Future | Local agents, local model servers, Docker, multiple surfaces | Authenticated worker protocol, tenancy, distributed state, failure recovery, and zero-trust execution design |
| Evaluation science | Strongly implemented | `bench/`, `verify-claims`, ground truth, model matrix, anti-fitting/provenance CI | Broaden external replication, workload/cost measures, and statistically powered comparisons |

## Alignment Rules

1. `README.md` and `FEATURES.md` maturity labels are product claims and must remain consistent with this matrix.
2. A benchmark validates only its defined corpus, model, harness, and metric.
3. Promotion to stable requires deterministic safety tests, an operational path, documentation, and a reproducible receipt.
4. Persistent autonomy, distributed execution, or shared knowledge services trigger new threat models and ADRs.
5. The SAD is updated from implementation evidence; the vision is not reverse-engineered into fictitious components.
