# SDLC Accelerate Intake — T3MP3ST

**Entry mode:** Existing codebase  
**Baseline revision:** `186afe6b50e365371774aa2ed7986d73eb0656db`  
**Guidance:** Capture architecture and design as current state, emphasize SAD/ADRs, and test alignment between `VISION.md` and implemented code.

## Problem Statement

Offensive-security capability is costly to assemble, difficult to coordinate, and easy to overstate. T3MP3ST provides a local-first orchestration platform that connects an operator's existing coding agent or model provider to scoped reconnaissance, exploitation, evidence, verification, and reporting workflows while retaining authorization and provenance controls.

## Stakeholders

- Authorized security operators and researchers
- Project maintainers and contributors
- Developers integrating through CLI, HTTP, library, or MCP surfaces
- Target/system owners who authorize engagements
- Recipients of verified findings and coordinated disclosures

## Current-State Scope

The implemented system is a TypeScript modular monolith with CLI, localhost War Room/API, MCP server, mission/admiral/operator orchestration, target and OPSEC controls, arsenal adapters, evidence/reporting, provider abstraction, source ingestion, and reproducible benchmarks. Stable, experimental, research, and planned capabilities remain explicitly distinct.

## Success Criteria

1. Every stable public capability claim remains re-derivable through `npm run verify-claims` and CI.
2. Networked operations reject out-of-scope public targets by default and require explicit authorization context.
3. The current-state SAD traces every core use case and names concrete implementation modules.
4. Major implemented design choices have accepted retrospective ADRs with evidence and consequences.
5. Every vision vector is classified as implemented, partial/experimental, research, or future without presenting aspiration as current state.

## Constraints

- Node.js 18+ and TypeScript/ESM
- Local-first and self-hosted operation, including connected local agents
- Real offensive tooling only for authorized targets
- Sensitive credentials/evidence remain operator-controlled
- AGPL-3.0-or-later licensing
- Existing CLI, HTTP, MCP, and benchmark interfaces require compatibility discipline

## Out of Scope for This Baseline

- Redesigning or implementing roadmap features
- Claiming hosted-service scale, enterprise certification, or production SLOs without evidence
- Treating `VISION.md` as an implemented specification
