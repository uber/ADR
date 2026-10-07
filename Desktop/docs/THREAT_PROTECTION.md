# Known-malicious artifact protection

Open **Malicious artifacts** under **Protection** in ADR Desktop. Connected,
loaded hooks can stop supported operations that match the local threat list.
The feature is enabled by default and has its own owner-controlled switch;
turning it off does not change file rules or credential protection.

This is exact, local blocklist matching—not a malware classifier, package
resolver, or operating-system sandbox. An unfamiliar artifact is not blocked
merely because it is unfamiliar. A non-match is not a safety certificate.

## What is in the list?

The bundled [artifact list](../adr_desktop/data/malicious_artifacts.json) is
separate from Detection's behavioral threat taxonomy. Its initial four records
cover eight exact malicious package releases and one published malicious binary
hash, with links to primary public disclosures.

The baseline currently has **zero skill-manifest hashes and zero MCP endpoint
indicators**. The matcher supports both, but they require reviewed additions.
The `postmark-mcp` record is a version-specific npm package indicator, not a rule
against every server or tool using the name “Postmark.”

The UI reports actual counts and source publication times. Importing an old
list does not make its intelligence newly published. This is a small baseline,
not a claim of comprehensive or current threat coverage.

## Supported identities

| Kind | What establishes a match |
|---|---|
| `skill_sha256` | SHA-256 of the complete raw bytes of a verified `SKILL.md` manifest |
| `file_sha256` | SHA-256 of the complete raw bytes of a referenced regular file |
| `package` | npm or PyPI ecosystem, registry, normalized package name, and an exact listed version; an explicit `all_versions: true` is broader |
| `mcp_endpoint` | Exact normalized, literal MCP endpoint URL |

Hashes are not computed from just frontmatter, a preview, normalized line
endings, or a directory name. A manifest hash does not cover the skill's
supporting scripts and assets. Referenced files are inspected with bounded
descriptor reads and checked for changes during the read; partial files do
not produce a purported complete hash.

Package matching does not confuse npm scopes or aliases with a different
package. PyPI name punctuation is normalized, while exact release suffixes
remain significant. Private indexes, overrides, unresolved versions, and
unsupported configuration are not guessed into public-package identities.
`latest`, ranges, archives, Git URLs, and local source trees do not establish
an exact registry release. An all-version record deliberately covers future
and unversioned use of that exact registry/name and requires explicit feed
author intent.

MCP display names and tool-name substrings are not indicators. ADR resolves
supported current settings and provenance before comparing endpoints or
package launch commands. Query-bearing URLs, substitutions, ambiguous aliases,
and unsupported settings remain unassessed. URL path case and meaningful
trailing slashes are preserved; the matcher does not contact the endpoint.

## Operations checked

The adapters currently check:

- Direct `Read`, `read_file`, and `view` file operands.
- Supported `Skill`/`skill` invocations that resolve to a unique local manifest.
- Literal `cat`, `head`, and `tail` reads, and the numeric-range form
  `sed -n '1,260p' SKILL.md`. The entire file is hashed, not just the displayed
  lines.
- Literal npm install/add, npx/npm-exec, pip/Python `-m pip`, and supported
  uv-pip/uv-tool/uvx commands, including the recognized exact package and
  registry options.
- Supported static shell wrappers and simple command sequences. An earlier
  opaque program can change resolution state, so ADR does not infer later
  package identity from stale assumptions.
- Referenced literal executable/script files in supported command forms.
- MCP tool calls whose unique configured endpoint or launch identity can be
  established from supported user/project JSON, JSONC, or TOML settings.
- Credential-backed commands executed through `adr_run_command`, using the
  native runner's actual clean-environment contract.

The same check is composed with file protection. Existing file denies remain
denies, a known-malicious match cannot be overridden by an earlier approval,
and ordinary passes return an empty hook result rather than bypassing the
harness's own permission system.

After native approval, the hook rereads the policy and rechecks in the original
agent environment. The daemon does not treat its own registry or harness-root
settings as the caller's. Vault commands are separately rechecked immediately
before native execution. Model/native denial messages are fixed text, not
instructions copied from the threat feed.

Pure remediation writes/deletes are not blocked merely because the old file's
hash is listed. ADR does not delete, quarantine, start, or uninstall an artifact.

## Check installed items

**Check installed items** performs an explicit local check of known skill roots,
supported MCP configurations, recorded project locations, and compatible
inventory candidates. It is independent of Sensor collection.

Findings include the matching identity, source evidence, and local location.
A unique inventory association offers a link to that exact AI inventory item;
ambiguous associations stay unlinked. Findings are not labeled “blocked.”
**Blocked activity** contains actual feature-denial receipts, not routine tool
calls or every inventory item.

The check is bounded: up to 24 project roots, 128 skill roots, 512 regular-file
reads, 512 candidate skill manifests, 32 MiB of file data, and 100 findings, with a soft
four-second work budget. Individual regular-file checks are capped at 8 MiB.
Unfinished, unreadable, unsupported, and limited work is reported as partial,
not silently called clean. This is not an exhaustive package/dependency or
whole-disk scan. Underlying filesystem calls can still be delayed by the OS.

A list update marks older scan results stale until another check completes.
Runtime blocking uses the current policy; it does not trust a previous scan's
display labels or negative results.

## Add your own reviewed intelligence

In **Setup & settings → Protection → Custom artifact list**, choose
**Import local list**, select a JSON file, review the preview, and confirm.
The Malicious artifacts page keeps intelligence details expandable and focuses
on matches and actual blocked activity. The import replaces only the previous custom list; bundled
intelligence is retained. The file is sent only to the authenticated local
ADR process, not to a cloud service.

The schema uses these document fields:

```json
{
  "schema_version": 1,
  "feed_id": "my-reviewed-artifacts",
  "revision": 1,
  "published_at": "2026-10-05T00:00:00Z",
  "indicators": []
}
```

Each indicator requires `id`, `status` (`active` or `revoked`), `kind`, `summary`,
`references` (HTTPS URLs), and a kind-specific `target`:

```json
{
  "id": "reviewed-release",
  "status": "active",
  "kind": "package",
  "summary": "Version-specific public disclosure; other versions are not covered.",
  "references": [
    "https://postmarkapp.com/blog/information-regarding-malicious-postmark-mcp-package"
  ],
  "target": {
    "ecosystem": "npm",
    "registry": "https://registry.npmjs.org",
    "name": "postmark-mcp",
    "versions": ["1.0.16"]
  }
}
```

For hashes, `target` contains a lowercase, 64-character `sha256`. For endpoints,
it contains a literal query-free `url` without userinfo or fragments. Package
targets require either a nonempty `versions` list or explicit
`all_versions: true`, not an omitted version interpreted as “all.”

To withdraw a custom record, keep its identity, set `status: "revoked"`, and add
a nonempty `revoked_reason`. A custom list cannot impersonate the bundled
namespace or revoke a bundled record.

Imports and the combined generation are limited to 512 KiB and 2,000 records.
Unknown fields/kinds, duplicate JSON keys or IDs, invalid versions/URLs,
excessive depth, and oversized data reject the entire update. The previous
accepted policy remains active. A failed bundled refresh retains the last
accepted generation and shows a warning rather than presenting an empty list.

Lists are inert data: no regexes, commands, executable probes, templates, or
network lookups. Sources and summaries render as text; references are opened
only when the owner chooses to follow them. Source-control updates to the
bundled list require reviewed evidence and validation. Do not submit private
skill bodies, private indicators, credentials, or copied internal incident
material to the public repository.

## Privacy and authority

- Matching is offline. ADR does not send files, hashes, package lists, sessions,
  or findings to external services.
- Only the owner UI can import intelligence or change the switch. MCP and hook
  capabilities cannot disable it or edit the list.
- One validated generation is embedded in the atomically published private
  policy. Invalid changes and stale UI revisions cannot silently overwrite it.
- Block receipts retain identifiers and verified feed labels, not raw commands,
  outputs, skill bodies, MCP headers, environment values, or URL credentials.
- Audit delivery from an offline hook is best-effort. Absence of a recorded
  block is not proof that no hook denied an operation.

## Limits to keep in mind

Pre-tool protection is not interception of automatic skill loading or MCP
process startup. A tool-call block cannot undo code a server ran at startup.
Plugin-manifest catalogs, prompt attachments, arbitrary generated scripts,
interactive follow-on stdin, unrecognized package-manager options, transitive
or build dependencies, and resolver-selected versions are not completely
mediated. Hash/config checks cannot eliminate a later filesystem check/use race.

The current native guardian is validated on macOS; existing POSIX support and
harness-specific limitations remain as described in [Hooks](HOOKS.md). Native
Windows guardian installation is not claimed by this preview. Missing/untrusted
hooks or bypassed harness paths provide no enforcement.

## Safe local verification

```sh
uv run pytest -q tests/test_threat_feed.py tests/test_artifact_identity.py \
  tests/test_threat_enforcement.py tests/test_threat_protection.py
uv run python scripts/threats_ui_qa.py
uv run python scripts/community_ui_lab.py --threats
```

The lab uses harmless synthetic skill bytes and an unreachable example
endpoint in a disposable profile. Tests never install real malware. Its UI
findings and denial receipt exercise the actual matcher and local API without
changing real agent configuration or reading real credentials.
