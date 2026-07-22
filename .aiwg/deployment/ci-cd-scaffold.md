# CI/CD Baseline and Architecture Additions

## Current Pipeline

The repository already has a substantial GitHub Actions pipeline: `npm ci`, lint, typecheck, tests, coverage, doctor, claim verification, anti-fitting, provenance gate, prompt audit, and smoke.

## Recommended Additions

1. **Architecture document check:** required SAD, ADR, alignment, NFR, and gate files exist and contain accepted identifiers.
2. **Traceability check:** SAD references UC-001 through UC-005 and ADR-001 through ADR-005.
3. **Maturity consistency check:** stable/experimental/research/roadmap labels do not conflict across product docs.
4. **Adapter safety inventory:** every registered network-capable adapter maps to a scope test and approval classification.
5. **Release provenance:** consider signed tags/artifacts and SBOM generation according to the project threat model.

These are proposed pipeline stages, not claims that they already run. Existing CI remains authoritative until changes are implemented and reviewed.
