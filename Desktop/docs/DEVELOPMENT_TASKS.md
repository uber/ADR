# Desktop refinement tasks

Branch: `desktop-dev`. This is a development backlog, not a release announcement. Task status records implemented and verified work; a directory move alone does not complete a component extraction.

## Direction

Desktop is the local UI and composition layer. Reusable feature logic belongs in importable components with documented, versioned input/output contracts. Components run in the existing core process; separate packages do not mean separate daemons. Keep the native credential boundary and existing bounded workers where they provide isolation.

No task below authorizes a profile migration, wider agent permissions, automatic model requests, a public release, or changes to `main`.

## Phase summary

| ID | Status | Task | Done when |
| --- | --- | --- | --- |
| ARCH-01 | Complete | Explain component ownership and execution boundaries | The architecture guide distinguishes libraries, adapters, native secret handling, and short-lived workers; contributors can find the owner of each behavior. |
| ARCH-02 | Complete | Extract offline artifact intelligence into `Protection/` | Desktop imports the real implementation through a compatibility adapter; the package has no Desktop/runtime/service dependency and adds no process. |
| API-01 | Complete | Publish the artifact engine's v1 contract | The public import path, JSON shapes, matching semantics, errors, ordering, and digest behavior are documented and protected by golden/compatibility tests. |
| UX-01 | Complete | Make Setup & settings the setup home | Capture controls and agent connections are in one place; feature pages link there without duplicating the complete connection UI. All old feature routes continue to work. |
| UX-02 | Complete | Explain capabilities and simplify first use | A new user can distinguish local activity capture, inventory, connected-agent protections, credentials, and optional model reviews without enabling any of them. Advanced settings use disclosures. |
| QA-01 | Complete | Validate independent packaging and complete user flows | The Protection wheel works outside the checkout without Desktop installed; component tests, old Desktop tests, fresh-profile browser checks, and both frozen macOS builds pass. |
| ARCH-03 | Planned | Extract file-policy evaluation and normalized protection contracts | Policy evaluation consumes normalized inputs; harness decoding, trusted-MCP authorization, approval, and audit remain host adapters. Deny/Ask semantics and offline guardian behavior stay compatible. |
| ARCH-04 | Planned | Extract the review service behind narrow ports | Evidence/report validation, budgets, and scheduling no longer accept the entire Desktop Runtime. Storage, credential checking, clock, and CLI execution are explicit dependencies. Errors/partial results cannot become clean verdicts. |
| ARCH-05 | Planned | Separate credential coordination from native implementation | Metadata/grants and execution policies have narrow interfaces. Native code retains secret values, encryption, dialogs, execution, and output filtering; no raw-secret API is introduced. |
| ARCH-06 | Planned | Separate inventory and history projections from the UI | Existing Sensor/Discovery artifacts remain authoritative. Query/projection services own their outputs while the host owns the shared database and lifecycle. Original captures and grants remain unchanged. |
| UX-03 | Planned | Split frontend features behind shared UI primitives | Setup, sessions, inventory, and protection views have clear module ownership; navigation, dialogs, accessibility, and request/error handling remain shared and tested. |

## First implementation boundary

ARCH-02 and API-01 start with deterministic artifact-feed validation, normalization, generation compilation, matching, and summaries. They do not move filesystem inspection, the application-owned intelligence baseline, authorization, approval queues, policy publication, or data storage. Unknown artifacts remain unknown; an empty match result is not an allow decision.

UX-01 and UX-02 reuse `/settings` and the existing owner APIs. Capture does not require an agent plugin. Connecting the unified plugin still requires explicit consent to cross-agent history and current/future saved variables. Model reviews keep a separate consent flow. Visiting setup or hiding the introduction must not start capture, scan the device, install a plugin, add rules, or call a model.

## Compatibility and validation checklist

- [x] Preserve the public artifact schema and canonical generation digests.
- [x] Keep existing `adr_desktop.threat_feed` imports operational through a thin adapter.
- [x] Test the new library independently and from an installed wheel.
- [x] Preserve the CLI, MCP tool names/scopes, native IPC, guardian protocol, state directory, database, and saved permissions.
- [x] Verify fresh setup, cancel/error states, slow installation, existing profiles, keyboard navigation, narrow layouts, and dark mode using synthetic data.
- [x] Run the complete Desktop, Sensor, Discovery, and Protection test suites.
- [x] Verify frozen modules, native self-tests, and packaged guardian/MCP behavior on local Apple Silicon.
- [x] Confirm `desktop-dev` CI is green without creating a release or replacing the running app.

Verified by [all 12 branch CI jobs](https://github.com/uber/ADR/actions/runs/37613019678),
including Apple Silicon and Intel preview builds. See the
[validation record](VALIDATION.md#component-boundary-and-simpler-setup--october-7-2026)
for the local and synthetic-browser checks.

## Follow-up decisions

Choose the next extraction by its independent callers and safety boundary, not by a target number of packages. Do not copy all of Desktop into a new monolith or put HTTP between local features merely to call them separate services. Larger migrations should introduce a compatible adapter first, prove the replacement, and remove the old implementation only after its callers have moved.

See [component architecture and contracts](COMPONENTS.md) for the boundary rules.
