# Non-Functional Requirements Register

| ID | Requirement | Verification |
| --- | --- | --- |
| NFR-01 Safety | Networked tools must deny off-scope public hosts by default. | Scope-containment tests and smoke/gate suites |
| NFR-02 Authorization | Real operations require an explicit authorized target context. | API/mission validation tests and doctrine audit |
| NFR-03 Provenance | Public claims and findings must trace to committed or retained evidence. | `verify-claims`, finding verifier, provenance gate |
| NFR-04 Local security | HTTP server defaults to loopback and guards Host/origin. | Server tests and Docker configuration inspection |
| NFR-05 Secret isolation | Target credentials are injected only for their configured exact origin. | Target-header tests |
| NFR-06 Portability | Core build supports Node.js 18+ on common desktop/server environments. | CI plus documented install matrix |
| NFR-07 Compatibility | CLI, HTTP, library, and MCP contracts change intentionally and visibly. | Typecheck, contract tests, release review |
| NFR-08 Testability | Deterministic paths must run without live model/network dependencies in CI. | Main CI workflow |
| NFR-09 Honesty | Experimental/research/roadmap work must not be described as stable. | Vision alignment and claim audit |
| NFR-10 Recoverability | Updates preserve configured sensitive artifact paths. | Update self-tests |
| NFR-11 Performance | Timeout controls bound local-agent, task, and planning calls. | Timeout/fallback tests; future percentile baseline |
| NFR-12 Maintainability | Major trust-boundary and platform decisions require ADR updates. | Architecture review checklist |
