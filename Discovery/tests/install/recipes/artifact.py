"""``artifact`` - 24 entries, every one of them a file the collector must notice.

Skills, commands, hooks, instruction files, a plugin directory, a malformed
bundle, two lookalike scripts and a dangling symlink. No installer, no network:
the whole family is file creation, which is why it is built first alongside
``declare-mcp``.

Four creation shapes, and the distinction between them matters. ``merge`` is
not ``file``: two hook entries write the same ``settings.json``, and a recipe
that overwrote would silently delete the first and report it as a miss.
"""

import json
import os
import posixpath
from typing import Any, Dict

from .. import bodies, writers
from .base import Outcome, Recipe


class ArtifactRecipe(Recipe):
    family = "artifact"

    def execute(self, context: Any, entry: Any) -> Outcome:
        block = entry.create
        path = context.path_for(entry)
        if not path:
            return self._outcome(entry, "failed",
                                 reason="no %s path for %s" % (context.platform, entry.id))
        kind = block.get("kind", "file")
        try:
            handler = getattr(self, "_" + kind)
        except AttributeError:
            return self._outcome(entry, "failed", reason="unknown create kind %r" % kind)

        handler(context, entry, path)
        if block.get("mode") and context.platform != "win":
            (context.driver.sudo if entry.privileged else context.driver.run)(
                ["chmod", block["mode"], path])

        # Verify, always. A write that silently did not land - no permission, a
        # missing parent, a transport that does not elevate - would otherwise be
        # recorded `installed`, and the scorer would report the collector missing
        # a file that was never there. That is the worst failure this harness can
        # have: it manufactures a defect in the thing it is measuring.
        if not context.driver.exists(path):
            return self._outcome(entry, "failed", path=path,
                                 reason="wrote %s but it is not there afterwards" % path)
        return self._outcome(entry, "installed", path=path, method="agent_artifact")

    # -- the four shapes ----------------------------------------------

    def _file(self, context: Any, entry: Any, path: str) -> None:
        context.driver.write(path, self._body(context, entry, path), privileged=entry.privileged)

    def _directory(self, context: Any, entry: Any, path: str) -> None:
        name = posixpath.basename(path.rstrip("/"))
        for filename, content in bodies.plugin(name).items():
            context.driver.write(posixpath.join(path.rstrip("/"), filename), content)

    def _merge(self, context: Any, entry: Any, path: str) -> None:
        """A hook joins a settings file rather than replacing it."""
        fragment = bodies.hook(entry.create["event"], context.substitute(entry.create["command"]))
        existing: Dict[str, Any] = {}
        if context.driver.exists(path):
            local = context.scratch_file(path)
            context.driver.pull(path, local)
            try:
                with open(local, encoding="utf-8") as handle:
                    existing = json.load(handle)
            except (OSError, ValueError):
                existing = {}
        context.driver.write(path, writers.as_json(writers.merge(existing, fragment)))

    def _append(self, context: Any, entry: Any, path: str) -> None:
        """AG-12: a key exported from a shell profile that already exists."""
        addition = bodies.shell_export(entry.create["variable"],
                                       context.substitute(entry.create["value"]))
        if context.platform == "win":
            addition = "\n# %s\n$env:%s = \"%s\"\n" % (
                bodies.MARKER, entry.create["variable"], context.substitute(entry.create["value"]))
        existing = ""
        if context.driver.exists(path):
            local = context.scratch_file(path)
            context.driver.pull(path, local)
            try:
                with open(local, encoding="utf-8") as handle:
                    existing = handle.read()
            except OSError:
                existing = ""
        context.driver.write(path, existing + addition)

    def _symlink(self, context: Any, entry: Any, path: str) -> None:
        """N-09: a link to a target that does not exist, left dangling on purpose."""
        target = entry.create["target"]
        context.driver.mkdir(posixpath.dirname(path), privileged=entry.privileged)
        if context.platform == "win":
            context.driver.shell("New-Item -ItemType SymbolicLink -Force -Path %r -Target %r"
                                 % (path, target))
        elif entry.privileged:
            context.driver.sudo(["ln", "-sfn", target, path])
        else:
            context.driver.run(["ln", "-sfn", target, path])

    # -- content -------------------------------------------------------

    def _body(self, context: Any, entry: Any, path: str) -> str:
        name = posixpath.basename(path)
        stem = os.path.splitext(name)[0]
        body = entry.create.get("body", "instructions")
        if body in ("backup_script", "llm_wrapper", "malformed_bundle"):
            return getattr(bodies, body)()
        return getattr(bodies, body)(stem)
