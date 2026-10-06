# Malicious artifact protection implementation plan

## Overview

Add local protection against known-malicious skills, MCP servers, and packages using a dedicated, reviewable artifact-intelligence feed. A confirmed identity match denies a supported agent operation before it executes. A non-match does not certify an artifact as safe and does not add new restrictions to unrelated work.

Branch: `desktop-dev`. The implementation remains in the developer preview until community launch; a branch push is not a desktop release.

## Delivery status

The feed, matcher, bounded identity adapters, composed hook/vault enforcement, owner APIs, installed-item checks, and UI are implemented. Local unit/API/browser and packaged-guardian validation passed; see [the validation record](VALIDATION.md). Live Codex acceptance is not complete: native inspection reports modified/untrusted ADR hook definitions, and the harmless live sentinel did not block. Those definitions still require owner review through Codex `/hooks` before rerunning that acceptance test. No trust bypass or automatic trust-store edit was made.

## Current state

ADR Desktop already has bounded pre-tool adapters, a native guardian, owner-only policy editing, atomic offline policy publication, a credential-backed command runner, and local inventory. The detection component's `threat_repository.yaml` describes adversary techniques; it is not a list of malicious artifact identities. Discovery's inventory is useful for finding candidate locations, but its display names and scrubbed configuration fields are not enforcement authority.

## Decisions

- Keep the pure feed validator/matcher and bounded identity extraction adjacent to Desktop's existing protection code. Do not add the Detection component's ML/service dependencies or change Discovery's privacy contract.
- Embed one validated feed generation in the existing private policy snapshot. Hooks require neither an available UI nor an online reputation service.
- Enable confirmed-match blocking by default, with a separate owner-controlled toggle. Preserve file rules, strict-execution preferences, capture settings, credentials, and grants.
- Bundle a small source-cited public baseline; allow an explicitly imported local list to add indicators. Never copy internal indicators into repository data.
- Match complete file bytes by SHA-256, skill manifests by a distinct complete-`SKILL.md` SHA-256 identity, exact npm/PyPI releases with registry provenance, and exact MCP endpoints. Explicit all-version package records are supported only when declared as such.
- Reject malformed or oversized feeds as a whole, retaining the active generation. Reject duplicate JSON keys and indicator IDs. Feed text is data, never executable rules or instructions.
- Do not automatically upload files, hashes, inventories, findings, or reports. Do not submit community PRs automatically. No network updater is included in this first version.
- Do not delete/quarantine files or rewrite third-party MCP configurations automatically. Per-artifact exceptions, pre-start MCP wrappers, native skill disabling, and signed remote updates are separate follow-up work.

## Approach

The alternatives were a new package-manager/MCP proxy layer or a shared check in the existing protection path. The shared check fits the current app and can be tested without changing how agents launch. A future proxy can reuse the identity matcher, but must separately prove that it intercepts server startup.

```mermaid
flowchart LR
    A[Reviewed artifact feed] --> B[Validated local generation]
    B --> C[Atomic policy snapshot]
    C --> D[Pre-tool and vault checks]
    D --> E[Block receipt and owner UI]
```

Identity extraction reads only bounded local metadata and referenced regular files; it never runs an installer, imports a package, launches a server, expands a shell, or downloads an artifact to discover its identity. MCP aliases are lookup keys, not indicators. Current configuration/provenance must establish the endpoint or package.

## Phase Summary

| Phase | What it adds | Depends on | Key files |
|---|---|---|---|
| 1 | Feed schema, public baseline, normalization, exact matching, validation tests | None | `adr_desktop/threat_feed.py`, `adr_desktop/data/malicious_artifacts.json` |
| 2 | Bounded artifact extraction and shared pre-execution decisions | Phase 1 | `adr_desktop/artifact_identity.py`, `adr_desktop/protection.py`, existing hooks/guardian/vault |
| 3 | Owner controls, local installed-item checks, block receipts, UI | Phases 1–2 | `adr_desktop/threat_protection.py`, runtime/store/API, web assets |
| 4 | Integration, offline/approval-race tests, browser/native verification, support documentation | Phases 1–3 | tests, synthetic QA scripts, `docs/THREAT_PROTECTION.md` |

## Phase 1: Feed and matching

Use a versioned JSON document with a feed ID, revision, publication timestamp, and bounded indicators. Each record has a stable ID, active/revoked status, plain-text explanation, source references, and exactly one supported target. A custom feed cannot revoke bundled records. Feed publication time remains distinct from local import time.

The public baseline covers eight exact package releases and one published binary hash. It contains no invented skill hashes or MCP endpoint indicators:

- `postmark-mcp` version `1.0.16`, from [Postmark's disclosure](https://postmarkapp.com/blog/information-regarding-malicious-postmark-mcp-package).
- `ua-parser-js` versions `0.7.29`, `0.8.0`, and `1.0.0`, from the [GitHub-reviewed advisory](https://github.com/advisories/GHSA-pjwm-rvh2-c87w).
- `ultralytics` versions `8.3.41`, `8.3.42`, `8.3.45`, and `8.3.46`, from [PyPI's incident analysis](https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/).
- The malicious `triton` binary hash published in [PyTorch's incident report](https://pytorch.org/blog/compromised-nightly-dependency/). This is a file hash, not a skill or package-archive hash.

Tests use fixture factories and parameterized cases for exact/neighboring versions, private-registry collisions, name normalization, scoped names, URL lookalikes, revoked records, empty coverage, malformed/deep/oversized JSON, duplicate keys/IDs, stable generation round-trips, and failed-import preservation. No malware is downloaded or executed.

## Phase 2: Runtime checks

Compose artifact matching with existing file decisions. A verified ADR MCP exemption must not bypass the artifact check; credential-backed commands are checked again inside the vault runner. Preserve existing denies and never emit a new blanket `allow`. Reevaluate after native approval queues/dialogs and immediately before vault execution.

Cover documented literal package install/run forms, including npm/npx/npm exec and pip/uv, supported static wrappers, and exact package aliases where their grammar is understood. Version ranges, tags, mutable dependencies, arbitrary generated scripts, or missing registry provenance must not be guessed into an exact malicious version. Direct reads and supported literal file operands use complete descriptor-verified hashes. Remediation writes/deletes must not be blocked just because the old destination matches a malicious hash.

Resolve MCP calls against bounded current user/project settings and explicit harness provenance where available. Duplicate aliases, unresolved substitutions, or unsupported configuration shapes must not be assigned to a guessed server.

Tests exercise denied operations before a harmless marker can be written, clean controls, argument mentions that are not execution, concurrent file/config changes, symlinks/special files, byte/time budgets, disabled protection, policy corruption, offline guardian behavior, trusted-ADR paths, and feed changes while approval is pending.

## Phase 3: Owner controls and UI

Add `/threats` under Protection. Show the independent enable state, actual feed coverage, public/custom revision information, a local-list import action, an installed-item check, matching items, and recent blocked activity. An inventory finding is not labeled an actual block. Unknown/partial checks are not a safety certificate.

All settings/import/check endpoints require the existing owner/session/CSRF checks. Feed changes use the observed policy revision as a concurrency guard and publish atomically. Agent and hook capabilities cannot edit intelligence or disable protection.

Store bounded identifiers and match metadata only, not raw commands, tool results, environment/header values, skill bodies, or credential-bearing URLs. A scan is local and bounded; it does not install, start, remove, or submit artifacts.

Tests cover owner/agent/hook separation, CSRF and stale revisions, invalid imports preserving policy, actual supported-count reporting, scan serialization, old-generation scan labeling, safe rendering, and blocked-only activity.

## Phase 4: Verification and documentation

- Run focused and full Desktop tests plus lint and JavaScript syntax checks. Use parameterized behavioral cases and shared fixtures; measure coverage where available rather than claiming an unmeasured percentage. _(sub-agent/main session)_
- Exercise the actual UI/API in an isolated synthetic browser profile using browser MCP: enable/disable, import rejection/success, installed matches, blocked activity, keyboard interaction, and narrow/dark layouts. Inspect screenshots. _(main session)_
- Build the signed local development app and run packaged guardian/MCP/native smoke checks. Use harmless sentinel programs to prove deny/no-execution behavior, never real malware installations. _(main session)_
- Preserve and verify prior captures, credential entries, file rules, and settings before updating the running app. Already-running MCP helpers may need reconnecting after a development rebuild. _(main session)_
- Document tested harness/operation coverage and unsupported paths. Validate the local desktop and supported agent integrations, without assuming a hosted service. _(main session)_

## Coverage boundaries

This implementation mediates supported agent tool operations, not every process on the device. Automatic skill loading, MCP process startup, prompt attachments, package build/transitive dependency resolution, arbitrary shell programs, interactive follow-on input, unsupported harness tools, and filesystem changes after a check require separate controls. A stopped MCP invocation does not undo a server's startup behavior. Native Windows guardian installation remains outside the existing preview's validated support.

## Rollback

The owner can disable threat matching independently of file and credential protection. Invalid imports leave the previous complete generation active. Original sensor snapshots and user files are not rewritten. Additive storage and policy fields preserve older data. Keep a private profile backup and the previous app bundle before replacing a local build.
