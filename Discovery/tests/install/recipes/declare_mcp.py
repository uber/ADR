"""``declare-mcp`` - 27 entries, no installer, the most inference exercised.

An MCP server exists because a config file says so. So this recipe writes the
config file the host application would have written, in the format that
application uses, at the path it uses on this OS - and nothing else. No package
is fetched, no process is started, nothing is granted network access.

That is the whole point of building this family first: it covers the two dozen
entries where the collector does the most guessing, and it needs no package
manager, no vendor installer, no GUI session and no network to do it.
"""

import json
from typing import Any, Dict, List

from .. import writers
from .base import Outcome, Recipe

#: How each site spells "here are my MCP servers". A site whose shape is wrong
#: produces a file the collector reads as empty, which would score as a missed
#: site and blame the collector for the harness's own mistake.
SITE_SHAPES = {
    "claude-code": ("json", ["mcpServers"]),
    "claude-desktop": ("json", ["mcpServers"]),
    "cursor": ("json", ["mcpServers"]),
    "windsurf": ("json", ["mcpServers"]),
    "vscode": ("json", ["servers"]),
    "cline": ("json", ["mcpServers"]),
    "zed": ("json", ["context_servers"]),
    "jetbrains": ("json", ["mcpServers"]),
    "opencode": ("json", ["mcp"]),
    "codex": ("toml", ["mcp_servers"]),
    "goose": ("yaml", ["extensions"]),
    "managed-claude-code": ("json", ["mcpServers"]),
    "managed-adr": ("json", ["mcpServers"]),
    "project": ("json", ["mcpServers"]),
}


class DeclareMcpRecipe(Recipe):
    family = "declare-mcp"

    def execute(self, context: Any, entry: Any) -> Outcome:
        declared = entry.declare
        sites = declared.get("sites") or [declared.get("site")]
        written: List[str] = []

        for site in sites:
            if site not in SITE_SHAPES:
                return self._outcome(entry, "failed", reason="unknown declaration site %r" % site)
            path = context.path_for(entry, site=site)
            if not path:
                return self._outcome(entry, "failed",
                                     reason="no %s path for site %r" % (context.platform, site))
            self._declare_at(context, entry, site, path)
            if not context.driver.exists(path):
                return self._outcome(entry, "failed", path=path,
                                     reason="declared in %s but the file is not there" % path)
            written.append(path)

        # M-SP-02 writes two files on purpose - a managed one and a user one -
        # and the *managed* path is the one precedence says wins, so that is the
        # path recorded. Recording the user path would make the scorer expect
        # the wrong scope for an entry that exists to test scope.
        return self._outcome(entry, "installed", path=written[0], method="config",
                             extra={"paths": written} if len(written) > 1 else {})

    def _declare_at(self, context: Any, entry: Any, site: str, path: str) -> None:
        shape, keys = SITE_SHAPES[site]
        document: Dict[str, Any] = {}
        for key in reversed(keys):
            document = {key: {entry.declare["server_name"]: self._server(context, entry, site)}} \
                if not document else {key: document}
        privileged = bool(entry.privileged) or site.startswith("managed-")
        if shape == "json":
            existing = self._read_json(context, path)
            content = writers.as_json(writers.merge(existing, document))
        elif shape == "toml":
            content = writers.as_toml(document)
        else:
            content = writers.as_yaml(document)
        context.driver.write(path, content, privileged=privileged)

    def _read_json(self, context: Any, path: str) -> Dict[str, Any]:
        """Merge rather than overwrite: nine M-PIN rows share ~/.claude.json.

        A recipe that wrote the file whole would leave one server declared and
        eight missing, and the run would report eight misses that never
        happened.
        """
        if not context.driver.exists(path):
            return {}
        local = context.scratch_file(path)
        context.driver.pull(path, local)
        try:
            with open(local, encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, ValueError):
            return {}

    def _server(self, context: Any, entry: Any, site: str) -> Dict[str, Any]:
        """The server block, with canaries substituted for their real values."""
        declared = entry.declare
        block: Dict[str, Any] = {}
        if declared.get("url"):
            block["url"] = declared["url"]
            block["type"] = declared.get("transport", "sse")
        else:
            block["command"] = declared["command"]
            block["args"] = [context.substitute(arg) for arg in declared.get("args", [])]
        for key in ("env", "headers"):
            if declared.get(key):
                block[key] = {name: context.substitute(value)
                              for name, value in declared[key].items()}
        return block
