# User Stories

| ID | Story | Acceptance signal |
| --- | --- | --- |
| US-01 | As an operator, I can define an authorized target and scope before execution. | Scope receipt exists; invalid/off-scope target is refused. |
| US-02 | As an operator, I can launch and monitor a mission from the CLI or War Room. | Shared mission state is visible through both surfaces. |
| US-03 | As an operator, I can connect an already-authenticated local coding agent. | Mission planning works without a new cloud API key. |
| US-04 | As an operator, I can approve or reject dangerous actions. | Approval decision is enforced before execution. |
| US-05 | As a researcher, I can preserve evidence behind each finding. | Finding links to tool/model evidence and verification state. |
| US-06 | As an integrator, I can access supported reconnaissance through MCP. | MCP schema validates and returns structured output. |
| US-07 | As a researcher, I can ingest supported source languages. | Supported grammar extracts blocks; unsupported input fails safely. |
| US-08 | As a maintainer, I can reproduce headline claims. | `npm run verify-claims` succeeds from committed artifacts. |
| US-09 | As a contributor, I can see whether a feature is stable, experimental, research, or roadmap. | Maturity classification is explicit in docs/alignment matrix. |
| US-10 | As a maintainer, I can detect prompt, provenance, and fitting regressions in CI. | Corresponding CI gates fail on seeded violations. |
