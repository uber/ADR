"""Executing the manifest, and writing down what actually happened.

Two jobs, and the second is the one the scorer depends on. The runner installs
what it can, and then records - per entry id - what the machine really ended up
with. ``manifest.actual.json``, not the manifest, is what scoring compares
against: an install that failed, or that a vendor no longer ships here, must
never be scored as a miss.
"""

import json
import os
import posixpath
import secrets
import tempfile
from typing import Any, Dict, List, Optional

from ..manifest import CANARY_REF, Entry, Manifest
from .recipes import for_family

#: Entries are not independent, so execution follows dependency order rather
#: than manifest order. Step 6 after step 3 is the subtle one: several MCP
#: declaration sites live inside an application's own config directory, and
#: writing M-SITE-08 before JetBrains exists creates a path the collector may
#: treat differently from one the application itself created.
ORDER = (
    ("baseline-prereq",),                 # 1  already in the image, verified only
    ("npm-global", "pipx", "vendor-binary"),  # 2  binaries on PATH
    ("app-installer", "non-ai-app"),      # 3  VS Code must exist before its extensions
    ("vscode-ext",),                      # 4  depends on step 3
    ("service",),                         # 5  start, wait for port, pull model
    ("declare-mcp",),                     # 6  config sites depend on their host app
    ("artifact",),                        # 7  files and links
    ("channel-variant",),                 # 8  second installs, after the first ones
    ("scheduler", "identity"),            # 9  states that persist without a process
    ("runtime-state",),                   # 10 last: processes must be alive at scan #2
)


class Context:
    """Everything a recipe needs about the guest it is installing into."""

    def __init__(self, driver: Any, manifest: Manifest, platform: str, home: str,
                 canaries: Optional[Dict[str, str]] = None, scratch: Optional[str] = None):
        self.driver = driver
        self.manifest = manifest
        self.platform = platform
        self.home = home
        self.canaries = canaries if canaries is not None else plant_canaries(manifest)
        self.scratch = scratch or tempfile.mkdtemp(prefix="adr-e2e-")

    def expand(self, path: Optional[str]) -> str:
        """Resolve the manifest's spelling of home into this guest's."""
        if not path:
            return ""
        text = str(path).replace("~", self.home).replace("%USERPROFILE%", self.home)
        return text.replace("%APPDATA%", posixpath.join(self.home, "AppData/Roaming"))

    def path_for(self, entry: Entry, site: Optional[str] = None) -> str:
        """Where this entry writes on this OS, absolute.

        Only the M-SITE rows carry a path, because they are the rows whose
        subject *is* the path. Every other declaration - the nine launch forms,
        the special cases - says which site it declares in and inherits that
        site's file, so the location of a config file is stated once and a
        vendor moving it is a one-line change.
        """
        own = entry.path_for(self.platform)
        if own and not site:
            return self.expand(own)
        site = site or entry.declare.get("site")
        if not site:
            return self.expand(own)
        owner = _site_owner(self.manifest, site)
        return self.expand(self.manifest.by_id(owner).path_for(self.platform))

    def substitute(self, value: Any) -> Any:
        """Replace ``{{canary:name}}`` with this run's value for that canary.

        Substituted here rather than in each recipe so a credential exists in
        exactly one place: the run directory. A recipe that built its own would
        plant a value the redaction check never searches for, and the run would
        report a clean check it never made.
        """
        if not isinstance(value, str):
            return value
        return CANARY_REF.sub(lambda match: self.canaries.get(match.group(1), match.group(0)), value)

    def scratch_file(self, remote: str) -> str:
        return os.path.join(self.scratch, remote.replace("/", "_").replace(":", "_"))


class Runner:
    """One pass over the applicable manifest, in dependency order."""

    def __init__(self, context: Context):
        self.context = context
        self.outcomes: List[Dict[str, Any]] = []

    def run(self) -> Dict[str, Any]:
        entries = self.context.manifest.for_platform(self.context.platform)
        self._prepare(entries)
        for family_group in ORDER:
            for entry in [item for item in entries if item.family in family_group]:
                self.outcomes.append(self._execute(entry))
        self._propagate_dependencies()
        return self.actual()

    def _execute(self, entry: Entry) -> Dict[str, Any]:
        recipe = for_family(entry.family)
        try:
            outcome = recipe.execute(self.context, entry)
        except Exception as exc:  # a recipe that raises must not take the run with it
            return {"id": entry.id, "status": "failed", "family": entry.family,
                    "catalog_id": entry.catalog_id,
                    "reason": "%s: %s" % (exc.__class__.__name__, exc)}
        return outcome.to_dict()

    def _prepare(self, entries: List[Entry]) -> None:
        """Create what the manifest's declarations point at.

        Every M-SITE row declares a server whose command is a real file. A
        declaration pointing at a command that does not exist is a different
        test from the one the manifest describes, and the collector is entitled
        to treat the two differently.
        """
        from .. import install  # local import keeps the module import graph acyclic
        del install
        from .bodies import probe_server
        needed = {self.context.expand("~/dev/tools/adr-probe-server.js"): probe_server(),
                  self.context.expand("~/dev/tools/my-server.js"): probe_server()}
        for path, content in needed.items():
            self.context.driver.write(path, content)

    def _propagate_dependencies(self) -> None:
        """An entry whose dependency never installed was never really attempted.

        Recorded ``unimplemented`` rather than ``failed``: the entry did not
        fail, the thing it needed was never there. Scoring it as a miss would
        blame the collector for the harness's own gap - and a variant of a tool
        that was never installed once proves nothing about duplication.
        """
        status = {row["id"]: row["status"] for row in self.outcomes}
        for row in self.outcomes:
            entry = self.context.manifest.by_id(row["id"])
            blockers = [item for item in list(entry.depends_on) +
                        ([entry.variant_of] if entry.variant_of else [])
                        if status.get(item) not in ("installed", None)]
            if blockers and row["status"] == "installed":
                row["status"] = "unimplemented"
                row["reason"] = "depends on %s, which is %s" % (blockers[0], status[blockers[0]])

    def actual(self) -> Dict[str, Any]:
        counts: Dict[str, int] = {}
        for row in self.outcomes:
            counts[row["status"]] = counts.get(row["status"], 0) + 1
        return {
            "os": self.context.platform,
            "home": self.context.home,
            "image": getattr(self.context.driver, "image", ""),
            "applicable": len(self.context.manifest.for_platform(self.context.platform)),
            "installed": counts.get("installed", 0),
            "unavailable": counts.get("unavailable", 0),
            "failed": counts.get("failed", 0),
            "unimplemented": counts.get("unimplemented", 0),
            "entries": self.outcomes,
        }


def plant_canaries(manifest: Manifest) -> Dict[str, str]:
    """Generate this run's credential values from the declared shapes.

    Fresh per run and never committed: a credential checked into a repository is
    a credential, even a fake one. The shapes mirror real vendor formats closely
    enough to exercise shape-driven redaction, and every one carries a marker no
    issuer emits so it can never be mistaken for a live key.
    """
    values = {}
    for declaration in manifest.canaries:
        shape = declaration["shape"]
        if "{random:" in shape:
            width = int(shape.split("{random:")[1].split("}")[0])
            shape = shape.split("{random:")[0] + secrets.token_hex(width)[:width] + \
                shape.split("}", 1)[1] if "}" in shape else shape
        values[declaration["name"]] = shape
    return values


def _site_owner(manifest: Manifest, site: str) -> str:
    """The M-SITE row that owns a config file, so a multi-site entry can reuse it."""
    for entry in manifest:
        if entry.declare.get("site") == site:
            return entry.id
    raise KeyError(site)


def write_actual(actual: Dict[str, Any], run_dir: str) -> str:
    os.makedirs(run_dir, exist_ok=True)
    path = os.path.join(run_dir, "manifest.actual.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(actual, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return path
