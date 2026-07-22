# Iteration 001 Plan — Architecture Alignment

**Sprint goal:** Make current-state architecture and vision alignment maintainable, testable governance assets.

## Planned Work

1. Review and accept/amend SAD and ADR-001–005 with maintainers.
2. Reconcile canonical repository identity in package metadata and tracker configuration.
3. Add a documentation audit that detects stable/experimental/roadmap conflicts across README, FEATURES, SAD, and vision alignment.
4. Map each network-capable arsenal adapter to scope/approval tests.
5. Establish performance baselines for source ingestion and concurrent mission tasks.
6. Triage the 18 TODO/FIXME/HACK/XXX markers identified during intake.

## Definition of Done

- Maintainer decisions are reflected in accepted/superseded ADR status.
- CI or a documented release check validates maturity claim consistency.
- Safety-test coverage matrix has no unidentified network adapter.
- Baseline measurements include command, corpus, environment, and receipt.
- No roadmap capability is presented as current stable architecture.

## Dependencies and Risks

Owner validation is needed for repository identity and roadmap priority. Architecture documentation changes are non-runtime, but any resulting safety-control change requires the full security and claim gate suite.
