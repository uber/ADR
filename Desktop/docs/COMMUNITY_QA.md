# Community UI improvement loop

This desktop is for the person using agents: recover useful work, understand
installed tools, protect chosen files, and use credentials without putting
their values in model requests. Test those jobs, not just component snapshots.

## Run a disposable UI lab

From `Desktop/`:

```sh
uv run python scripts/community_ui_lab.py \
  --connection-file /tmp/adr-community-ui.json
```

Choose a new connection-file path on each run. Open the printed one-use local
URL using a browser MCP client, such as Playwright MCP. The lab runs the actual
UI and API with sample conversations and inventory. Native credential entry,
plugin-manager commands and opening OS Settings are replaced with synthetic
implementations. Real agent settings, credential values, captured history and
OS permissions are not changed. Stop the lab with Ctrl+C.

Use `--first-run` to inspect onboarding, `--read-error` for an I/O failure,
`--vault-recovery` for interrupted-save, missing-key and legacy-copy cases, and
`--credential-activity` for vault-to-session links and pending/unknown matches.
Use `--threats` for harmless artifact matches, a source-cited custom test feed,
and an actual synthetic pre-tool denial. No fixture artifact is malware or
contacts a remote endpoint.
The inventory fixture has 106 denied paths, intentional
exclusions and a scan limit so grouping can be exercised without scanning the
host. This is synthetic evidence, not a claim about a particular user's access.

Keep the browser profile isolated. Do not copy cookies, use a logged-in profile,
or load real transcripts into public screenshots. A screenshot should be taken
through the browser MCP and visually reviewed, not merely asserted to exist.

## A bounded improvement pass

1. **Observe.** Open the affected page, reproduce the problem with actual
   clicks/typing, and capture its DOM/accessibility state and screenshot.
2. **Choose a user benefit.** Prefer a small complete workflow over unrelated
   features. Assign non-overlapping file ownership when using parallel agents.
3. **Implement.** Preserve original records, existing permissions and unrelated
   work. Keep generated test data separate from real profiles.
4. **Exercise.** Use the browser MCP again. Check keyboard focus, loading/errors,
   narrow and dark layouts, and navigation in both directions.
5. **Review and correct.** Independently review the change, reproduce credible
   findings, and fix them. Repeat until the chosen workflow and its regressions
   pass; do not publish automatically or keep an unbounded mutation loop running.

Model-driven work should use the developer's authorized model and launcher.
Never commit provider credentials, private prompts, session logs, internal
launchers or user data into this repository.

## Scenarios worth keeping

- Search a tool-result keyword; combine agent, project and date filters; open
  a result; find the matching passage; go Back with filters and focus intact.
- Find a resumed conversation under its actual activity day. Search a word
  in its native title together with a word in its transcript.
- Open parent/sub-agent work at the beginning, preserve reading position on
  refresh, and copy an answer using a clipboard stub in synthetic tests.
- Review grouped inventory failures and load every omitted detail. Distinguish
  permission errors, I/O failures, missing optional paths and deliberate skips.
- Open the first-run access guide without automatically granting permissions,
  starting capture, or claiming Full Disk Access was enabled.
- Save a credential, use its alias, recover an interrupted save, and check
  missing-key/corrupt-storage explanations. Never print a real value.
- Open a credential-use session link, read its transcript, and go Back. Pending
  captures and ambiguous/older activity must not offer a link to an unrelated session.
- Verify native encryption, concurrent reads, late migration cancellation,
  output filtering and retained originals with disposable native fixtures.

## Automated complements

```sh
uv run pytest -q
uv run ruff check adr_desktop tests scripts
uv run python scripts/ui_qa.py
uv run python scripts/navigation_qa.py
uv run python scripts/sessions_ui_qa.py
uv run python scripts/credential_activity_ui_qa.py
uv run python scripts/threats_ui_qa.py
uv run python scripts/build_macos.py
dist/ADR.app/Contents/MacOS/ADR --self-test
dist/ADR.app/Contents/MacOS/ADR --vault-self-test
uv run python scripts/package_smoke.py
```

Automated checks complement hands-on MCP exploration. Native permission grants,
real-profile migration and clean-machine release behavior are separate
acceptance checks; a mocked Settings opener is not proof of an OS grant.
