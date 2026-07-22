# Initial Risk Screening

| ID | Risk | Severity | Evidence | Mitigation / control | Status |
| --- | --- | --- | --- | --- | --- |
| R-01 | Operations exceed authorized target scope | Critical | Real network/exploitation tools | Target scope model, egress containment, approvals, scope receipts | Controlled; continuous verification |
| R-02 | Secrets or engagement evidence leak | High | Provider keys, target headers, reports/evidence | Environment variables, target-origin binding, protected paths, local storage guidance | Open residual risk |
| R-03 | Aspirational capability is represented as shipped | High | Broad `VISION.md`; mixed maturity surface | Status labels, claim verifier, vision-alignment matrix | Controlled; governance required |
| R-04 | Model/tool nondeterminism produces false findings | High | LLM and external-tool execution | Ground-truth grading, finding verification, refuter/provenance gates | Open residual risk |
| R-05 | External tools or dependencies compromise host/supply chain | High | Arsenal and container/tool installation | Narrow adapters, approval paths, pinned CI actions, isolated execution guidance | Open |
| R-06 | Modular monolith accumulates unsafe coupling | Medium | Broad `src/` domain surface | Module boundaries, SAD, ADRs, architecture checks | Open |
| R-07 | Local artifact loss or retention mishandling | Medium | Filesystem reports/evidence and browser localStorage | Protected update paths and operator procedures | Open |

No risk makes the documented current solution infeasible. R-01 is blocking for any release that weakens default containment without an approved replacement control.
