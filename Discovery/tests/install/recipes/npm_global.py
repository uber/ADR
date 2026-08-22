"""``npm i -g`` - nine CLI agents, one command, one of the cheapest families."""

from typing import Any

from .base import Outcome, Recipe


class NpmGlobalRecipe(Recipe):
    family = "npm-global"

    def execute(self, context: Any, entry: Any) -> Outcome:
        if entry.install.get("unresolved"):
            return self._outcome(entry, "unimplemented",
                                 reason="source unresolved: %s" % entry.install["unresolved"])
        package = entry.install["package"]
        version = entry.install["version"]
        installed = context.driver.run(["npm", "install", "-g", "%s@%s" % (package, version)],
                                       timeout=600)
        if not installed.ok:
            return self._outcome(entry, "failed", version=version,
                                 reason="npm install failed: %s" % installed.stderr.strip()[:200])

        binary = entry.install.get("binary") or package.rsplit("/", 1)[-1]
        located = context.driver.run(["command", "-v", binary])
        if not located.ok or not located.text():
            # Installed but not on PATH is a harness failure, not a detection
            # one: the collector cannot be asked about a binary the shell itself
            # cannot find.
            return self._outcome(entry, "failed", version=version,
                                 reason="%s not on PATH after install" % binary)

        # The canonical path, because usr-merge and version-manager shims mean
        # the first spelling on PATH is often not the file itself - and the
        # scorer compares the collector's `install_path` against this one.
        path = context.driver.realpath(located.text())
        return self._outcome(entry, "installed", version=self._version(context, entry, version),
                             path=path, method="npm")

    def _version(self, context: Any, entry: Any, pinned: str) -> str:
        """What the machine says, falling back to what we asked for.

        A tool that prints its version differently from the version we pinned is
        worth recording as the tool prints it: the collector reads the machine,
        not the manifest, and scoring it against the manifest would be scoring
        it against something it never saw.
        """
        if not entry.verify:
            return pinned
        result = context.driver.shell(entry.verify)
        if not result.ok or not result.text():
            return pinned
        for token in result.text().replace("v", " ").split():
            if token[:1].isdigit():
                return token
        return pinned
