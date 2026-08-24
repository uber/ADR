"""Provision a guest and prove the tools actually landed.

This is the step before any measurement: install what the manifest says, then
verify each entry independently, so "the environment is ready" is a checked
claim rather than an assumption. Nothing here imports the collector - whether
the tools are discoverable is a separate question from whether they are there.
"""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .. import manifest as manifest_module
from ..install.bodies import body_for, substitute
from ..manifest import Entry

OK, MISSING, SKIPPED, FAILED = "ok", "missing", "skipped", "failed"

#: Families that need a vendor installer, a desktop session, a sign-in or model
#: weights. Reported `skipped` with the reason rather than counted as failures.
UNATTENDED = {
    "app-installer": "vendor installer needs a desktop session",
    "vscode-ext": "needs VS Code installed first",
    "service": "starts a listener and pulls model weights",
    "channel-variant": "second channel via nvm/fnm/usr-merge",
    "identity": "sign-in cannot be scripted",
    "runtime-state": "processes must outlive the run",
    "non-ai-app": "vendor installer needs a desktop session",
    "vendor-binary": "download url unresolved in sources.toml",
}

#: Distribution package names are not the binaries they install.
BINARIES = {"nodejs": ("node", "npm"), "python3-pipx": ("pipx", "python3"),
            "docker": ("docker",), "git": ("git",)}


@dataclass
class Step:
    id: str
    name: str
    family: str
    status: str
    detail: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "name": self.name, "family": self.family,
                "status": self.status, "detail": self.detail}


@dataclass
class Report:
    platform: str
    steps: List[Step] = field(default_factory=list)

    def of(self, status: str) -> List[Step]:
        return [s for s in self.steps if s.status == status]

    @property
    def counts(self) -> Dict[str, int]:
        tally: Dict[str, int] = {}
        for step in self.steps:
            tally[step.status] = tally.get(step.status, 0) + 1
        return tally

    @property
    def ready(self) -> bool:
        """Ready means nothing failed and nothing expected is missing."""
        return not self.of(FAILED) and not self.of(MISSING)

    def as_dict(self) -> Dict[str, Any]:
        return {"platform": self.platform, "ready": self.ready, "counts": self.counts,
                "steps": [s.as_dict() for s in self.steps]}


def provision(driver, platform: str, *, canaries: Optional[Dict[str, str]] = None,
              only: Sequence[str] = (), manifest=None, log=print) -> Report:
    """Install every automatable entry, then verify each one independently."""
    manifest = manifest or manifest_module.load()
    canaries = canaries or _canaries(manifest)
    report = Report(platform=platform)

    entries = manifest.for_platform(platform)
    if only:
        entries = [e for e in entries if e.family in only]

    for entry in entries:
        if entry.family in UNATTENDED:
            report.steps.append(Step(entry.id, entry.name, entry.family, SKIPPED,
                                     UNATTENDED[entry.family]))
            continue
        try:
            step = _install(driver, entry, platform, canaries)
        except Exception as failure:  # noqa: BLE001 - one bad entry is not a dead run
            step = Step(entry.id, entry.name, entry.family, FAILED,
                        f"{type(failure).__name__}: {failure}")
        report.steps.append(step)
        log(f"  {step.status:8s} {step.id:12s} {step.name}"
            + (f"  - {step.detail}" if step.detail else ""))
    return report


def _install(driver, entry: Entry, platform: str, canaries: Dict[str, str]) -> Step:
    family = entry.family
    if family == "baseline-prereq":
        return _verify_only(driver, entry)
    if family == "npm-global":
        return _npm(driver, entry)
    if family == "pipx":
        return _pipx(driver, entry)
    if family in ("declare-mcp", "artifact"):
        return _write(driver, entry, platform, canaries)
    if family == "scheduler":
        return _scheduler(driver, entry)
    return Step(entry.id, entry.name, family, SKIPPED, f"no provisioner for {family}")


def _verify_only(driver, entry: Entry) -> Step:
    """Already in the image. Verified, never installed.

    Verified against the binaries a package provides rather than the row's
    display name: ``command -v "Node.js"`` fails on a machine that has node.
    """
    if entry.verify:
        result = driver.sh(entry.verify)
        return Step(entry.id, entry.name, entry.family, OK if result.ok else MISSING,
                    _first_line(result.stdout) or entry.verify)

    package = str(entry.install.get("package") or "")
    candidates = BINARIES.get(package) or (entry.install.get("binary"), package,
                                           entry.name.split()[0].lower())
    candidates = [str(c) for c in candidates if c]
    found = [_first_line(driver.sh(f"command -v {shlex.quote(c)}").stdout)
             for c in candidates if driver.sh(f"command -v {shlex.quote(c)}").ok]
    if found:
        return Step(entry.id, entry.name, entry.family, OK, " ".join(found))
    return Step(entry.id, entry.name, entry.family, MISSING, f"none of {candidates} on PATH")


def _npm(driver, entry: Entry) -> Step:
    package, version = entry.install.get("package"), entry.install.get("version")
    if not package:
        return Step(entry.id, entry.name, entry.family, FAILED, "no package")
    if not version:
        return Step(entry.id, entry.name, entry.family, FAILED, "unpinned")

    spec = shlex.quote(f"{package}@{version}")
    installed = driver.sh(f"npm install -g {spec} --no-fund --no-audit", timeout=900)

    if not installed.ok:
        # npm links the bin before running postinstall, so a failed postinstall
        # leaves a dangling symlink that `command -v` and `ls` both report as
        # present. Remove it: an environment carrying a broken link is worse
        # than one that is honestly missing a tool.
        binary = entry.install.get("binary") or str(package).rsplit("/", 1)[-1]
        driver.sh(f"test -e {shlex.quote(str(binary))} || "
                  f"rm -f \"$(command -v {shlex.quote(str(binary))} 2>/dev/null)\" 2>/dev/null || true")
        return Step(entry.id, entry.name, entry.family, FAILED,
                    _npm_error(installed.stdout + installed.stderr)
                    or f"npm exited {installed.returncode}")
    return _verify_binary(driver, entry, version)


def _pipx(driver, entry: Entry) -> Step:
    package = entry.install.get("package") or entry.install.get("source")
    version = entry.install.get("version")
    spec = f"{package}=={version}" if version else str(package)
    installed = driver.sh(f"pipx install --force {shlex.quote(spec)}", timeout=900)
    if not installed.ok:
        return Step(entry.id, entry.name, entry.family, FAILED,
                    _first_line(installed.stderr) or f"pipx exited {installed.returncode}")
    return _verify_binary(driver, entry, version)


def _verify_binary(driver, entry: Entry, version: Optional[str]) -> Step:
    """Installed is not the same claim as runnable."""
    binary = entry.install.get("binary") or entry.name
    found = driver.sh(f"command -v {shlex.quote(str(binary))}")
    if not found.ok:
        return Step(entry.id, entry.name, entry.family, MISSING,
                    f"{binary} not on PATH after install")

    detail = found.stdout.strip()
    if entry.verify:
        ran = driver.sh(entry.verify, timeout=120)
        reported = _first_line(ran.stdout) or _first_line(ran.stderr)
        if reported:
            detail = f"{detail} ({reported})"
            if version and version not in reported:
                detail += f" - pinned {version}"
    return Step(entry.id, entry.name, entry.family, OK, detail)


def _needs_root(driver, entry: Entry, target: str) -> bool:
    """A path outside the user's home is a path the user cannot write.

    Checked by location as well as by the manifest's ``privileged`` flag,
    because a declaration inherits its site's path and a managed policy site
    lives under /etc whether or not the row remembered to say so.
    """
    return bool(entry.privileged) or not target.startswith(driver.home.rstrip("/") + "/")


def _run(driver, script: str, *, root: bool):
    return driver.sh(f"sudo -n sh -c {shlex.quote(script)}" if root else script)


def _write(driver, entry: Entry, platform: str, canaries: Dict[str, str]) -> Step:
    path = entry.path_for(platform)
    if not path:
        return Step(entry.id, entry.name, entry.family, SKIPPED, f"no path on {platform}")

    block = entry.create or {}
    kind = str(block.get("kind") or ("declare" if entry.declare else "file")).lower()
    target = driver.expand(path)
    quoted = shlex.quote(target)
    root = _needs_root(driver, entry, target)

    if kind == "directory":
        result = _run(driver, f"mkdir -p {quoted}", root=root)
        check = f"test -d {quoted}"
    elif kind == "symlink":
        link_to = str(block.get("target") or block.get("symlink_to") or "")
        result = _run(driver, f'mkdir -p "$(dirname {quoted})" && '
                              f"ln -sfn {shlex.quote(link_to)} {quoted}", root=root)
        # A dangling symlink is the point of N-09, so -L rather than -e.
        check = f"test -L {quoted}"
    elif kind == "append":
        line = _append_line(entry, canaries)
        quoted_line = shlex.quote(line)
        result = _run(driver, f"touch {quoted} && grep -qF {quoted_line} {quoted} || "
                              f"printf '%s\\n' {quoted_line} >> {quoted}", root=root)
        check = f"grep -qF {quoted_line} {quoted}"
    else:
        body = body_for(entry, canaries)
        if kind == "merge":
            body = _merged(driver, target, body)
        result = _run(driver, f'mkdir -p "$(dirname {quoted})" && cat > {quoted} '
                              f"<<'ADR_HARNESS_EOF'\n{body}\nADR_HARNESS_EOF", root=root)
        check = f"test -s {quoted}"

    if not result.ok:
        return Step(entry.id, entry.name, entry.family, FAILED,
                    _first_line(result.stderr) or f"exited {result.returncode}")
    if not _run(driver, check, root=root).ok:
        return Step(entry.id, entry.name, entry.family, MISSING, f"{path} absent after write")
    if block.get("mode"):
        _run(driver, f"chmod {shlex.quote(str(block['mode']))} {quoted}", root=root)
    return Step(entry.id, entry.name, entry.family, OK, path)


def _append_line(entry: Entry, canaries: Dict[str, str]) -> str:
    """An append row adds a line to a profile; it does not replace the profile."""
    variable = entry.create.get("variable")
    value = substitute(str(entry.create.get("value", "")), canaries)
    if variable:
        return f"export {variable}={value}"
    return substitute(str(entry.create.get("body", "")), canaries)


def _merged(driver, target: str, body: str) -> str:
    """Merge into what is already there rather than replacing it.

    Four hook rows write into the same settings file, two of them onto the same
    event. Overwriting would leave only whichever ran last, and the environment
    would look correct while carrying a fraction of what the manifest asked for.
    """
    existing = driver.sh(f"cat {shlex.quote(target)} 2>/dev/null")
    if not existing.ok or not existing.stdout.strip():
        return body
    try:
        current = json.loads(existing.stdout)
        incoming = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return body
    if not isinstance(current, dict) or not isinstance(incoming, dict):
        return body
    return json.dumps(_deep_merge(current, incoming), indent=2, sort_keys=True)


def _deep_merge(current: Any, incoming: Any) -> Any:
    """Recursive, because the thing worth preserving is nested.

    A shallow update replaces ``hooks.PreToolUse`` wholesale, which silently
    discards every hook another row already registered on that event.
    """
    if isinstance(current, dict) and isinstance(incoming, dict):
        merged = dict(current)
        for key, value in incoming.items():
            merged[key] = _deep_merge(current[key], value) if key in current else value
        return merged
    if isinstance(current, list) and isinstance(incoming, list):
        return current + [item for item in incoming if item not in current]
    return incoming


def _scheduler(driver, entry: Entry) -> Step:
    """cron is scriptable here; launchd and schtasks belong to other guests."""
    method = str(entry.state.get("method") or "").lower()
    command = str(entry.state.get("command") or "")
    if method != "cron":
        return Step(entry.id, entry.name, entry.family, SKIPPED, f"{method} not scriptable here")

    line = f"{entry.state.get('schedule', '0 * * * *')} {command} # adr-harness-{entry.id}"
    added = driver.sh("( crontab -l 2>/dev/null | grep -v "
                      f"adr-harness-{entry.id}; echo {shlex.quote(line)} ) | crontab -")
    if not added.ok:
        return Step(entry.id, entry.name, entry.family, FAILED, _first_line(added.stderr))
    present = driver.sh(f"crontab -l 2>/dev/null | grep -qF adr-harness-{entry.id}")
    return Step(entry.id, entry.name, entry.family, OK if present.ok else MISSING, line)


def _canaries(manifest) -> Dict[str, str]:
    from .synthesize import canary_values

    return canary_values(manifest)


def _npm_error(text: str) -> str:
    """The line that says what actually went wrong, not the first line of noise."""
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    for line in lines:
        if "Failed to setup" in line or "notarget" in line or "404 Not Found" in line:
            return line
    for line in lines:
        if "code" in line and ("ERR" in line or "error" in line):
            return line
    return _first_line(text)


def _first_line(text: str) -> str:
    stripped = (text or "").strip()
    return stripped.splitlines()[0].strip() if stripped else ""


def write_report(report: Report, path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report.as_dict(), handle, indent=2, sort_keys=True)
        handle.write("\n")


__all__ = ["BINARIES", "FAILED", "MISSING", "OK", "Report", "SKIPPED", "Step",
           "UNATTENDED", "provision", "write_report"]
