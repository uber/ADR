# Desktop development CI and preview builds

Desktop work targets `desktop-dev` until community launch. The
`Desktop CI` workflow runs on every push to that branch, every pull request
targeting it, and manual runs. There is no path filter that could leave a
required check waiting indefinitely after a documentation-only change.

## What runs

| Check | Coverage |
| --- | --- |
| Lint and workflow validation | Python lint, browser/adapter JavaScript syntax, actionlint, and unchanged lockfiles |
| Desktop tests | The full unit/API/guardian/synthetic CLI suite on Linux with Python 3.11 and 3.13, and macOS with Python 3.11 |
| Shared component tests | The complete Sensor and Discovery suites in their own locked environments on Linux |
| Browser workflows | Overview, navigation, session retrieval, credential-to-session links, malicious artifacts, and Security reviews, using real loopback APIs and synthetic data |
| macOS preview | Separate Apple Silicon and Intel builds, frozen parser/dependency checks, archive extraction, signature verification, native self-tests, and packaged-core/MCP/guardian smoke checks |
| Desktop CI | A stable aggregate check that fails if any required job fails, is cancelled, or is skipped |

The test jobs are independent, and matrices use `fail-fast: false`. A Linux
failure does not cancel macOS testing. Preview packaging starts only after
lint and test jobs succeed. A newer push cancels an older run for the same
branch or pull request; jobs also have explicit time limits.

The native desktop target remains macOS. Linux tests validate the Python core
and POSIX integrations, not a Linux desktop application. This workflow does not
claim native Windows support.

## Dependencies and source fidelity

The shared setup action pins uv and uses `uv sync --locked --extra dev`.
An outdated lockfile fails rather than being rewritten or silently accepted.
GitHub Actions are pinned to commit SHAs, checkout does not persist GitHub
credentials, and the workflow has read-only repository permissions.

Sensor and Discovery are editable local dependencies in Desktop's uv
environment. Tests and PyInstaller therefore see the source in this checkout,
not a cached wheel from an earlier local development session. Their standalone
CI jobs still use their own package definitions and lockfiles.
The build supplies explicit source roots to PyInstaller and rejects a bundle
missing any Sensor parser or required runtime module before creating the app.

The uv cache holds dependency downloads/builds, not the application profile or
test results. No production credentials, provider sign-ins, captured
conversations, native permission grants, or real model requests are required.
Fixtures isolate agent configuration roots instead of inheriting a runner's
`XDG_CONFIG_HOME`, `CODEX_HOME`, or Claude configuration.

## Inspecting a failure

Open the failed job before rerunning it. Every test leg retains a JUnit report
for seven days. Browser artifacts also contain each suite's log, synthetic
screenshots, a Playwright trace, and screenshots captured when a test fails.
Browser suites continue after another suite fails so one run can expose more
than the first problem.

Downloaded traces can be opened locally:

```sh
uv run --locked python -m playwright show-trace path/to/trace.zip
```

These diagnostics come only from disposable sample profiles. Do not substitute
real captured conversations or a logged-in browser in a CI fixture.

## Trying a preview

For a successful `desktop-dev` push or manual branch run, open the workflow's
**Artifacts** section and choose:

- `adr-desktop-dev-macos-arm64-<commit>` for Apple Silicon.
- `adr-desktop-dev-macos-x86_64-<commit>` for Intel.

Use a run whose aggregate **Desktop CI** check is green. Each artifact contains
an inner application ZIP and `SHA256SUMS`; verify the checksum from that
directory with `shasum -a 256 -c SHA256SUMS`. The application ZIP is created with
`ditto` and tested after extraction, retaining its executable permissions and
bundle structure.

Preview archives are retained for fourteen days. The app's `Info.plist` records
its package version, CI build number, development channel, and source commit.
PR runs test packaging but do not upload downloadable application previews.

**These are ad-hoc-signed developer builds, not notarized public releases.**
They are not automatically installed or sent to existing users. No GitHub
Release, package-registry upload, updater rollout, signing certificate, or
notarization credential is configured. Public distribution and its signing
requirements are a separate launch decision.

## Reproducing checks locally

From `Desktop/`:

```sh
uv sync --locked --extra dev --python 3.11
uv run --locked ruff check adr_desktop tests scripts
uv run --locked pytest -q
uv run --locked python -m playwright install chromium
uv run --locked python scripts/ui_qa.py --output test-results/ui
uv run --locked python scripts/navigation_qa.py --output test-results/navigation
uv run --locked python scripts/sessions_ui_qa.py --output test-results/sessions
uv run --locked python scripts/credential_activity_ui_qa.py --output test-results/credentials
uv run --locked python scripts/threats_ui_qa.py --output test-results/artifacts
uv run --locked python scripts/reviews_ui_qa.py --output test-results/reviews
```

On macOS, use a separate destination so testing does not replace a running app:

```sh
uv run --locked python scripts/build_macos.py --output dist/ADR-CI-preview.app
dist/ADR-CI-preview.app/Contents/MacOS/ADR --self-test
uv run --locked python scripts/package_smoke.py --app dist/ADR-CI-preview.app
```

Native self-tests include the local encrypted vault and use disposable data.
The packaged smoke test never enables capture or invokes a real model.

If branch protection is enabled, **Desktop CI** is the intended required check.
This workflow does not change repository access rules or branch protection.
