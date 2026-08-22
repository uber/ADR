"""Group S - skills, commands, hooks, plugins, rules and instruction files."""

from .cases_tools import count, none_of
from .framework import World, assets, has

CASES = {}


def case(case_id):
    def register(fn):
        CASES[case_id] = fn
        return fn
    return register


def artifact(snapshot, kind, name=None):
    matches = assets(snapshot, kind=kind)
    if name:
        matches = [a for a in matches if a.name == name]
    if len(matches) != 1:
        raise AssertionError("expected 1 %s%s, got %d: %s"
                             % (kind, " named " + name if name else "", len(matches),
                                [a.name for a in matches]))
    return matches[0]


def one_artifact(kind, name=None, **fields):
    def check(snapshot):
        asset = artifact(snapshot, kind, name)
        for key, value in fields.items():
            if key == "factors":
                got = asset.risk.get("factors", [])
                if not set(value).issubset(set(got)):
                    return "factors %r, expected to contain %r" % (got, value)
                continue
            got = {"scope": asset.config_scope}.get(key, getattr(asset, key, None))
            if got != value:
                return "%s == %r, expected %r" % (key, got, value)
        return True
    return has("one %s %s %s" % (kind, name or "", fields), check)


SKILL = """---
name: deploy-prod
description: Ship the current branch to production
version: 1.2.0
---

Run the deploy script and watch the rollout.
"""


# -- S.1 skills -----------------------------------------------------------

@case("S-01")
def s01():
    w = World().file("~/.claude/skills/deploy-prod/SKILL.md", SKILL)
    return w, [one_artifact("skill", "deploy-prod", scope="personal", owner="alice"),
               has("description captured",
                   lambda s: artifact(s, "skill").risk.get("description")
                   == "Ship the current branch to production")]


@case("S-02")
def s02():
    w = World().file("~/dev/payments/.claude/skills/run-migrations/SKILL.md",
                     "---\nname: run-migrations\n---\nbody\n")
    return w, [one_artifact("skill", "run-migrations", scope="project"),
               has("install path is inside the repo",
                   lambda s: "/dev/payments/" in artifact(s, "skill").install_path)]


@case("S-03")
def s03():
    w = World().file("~/.claude/skills/rotate/SKILL.md", "---\nname: rotate\n---\nbody\n")
    w.file("~/.claude/skills/rotate/scripts/rotate.sh", "#!/bin/sh\n")
    w.file("~/.claude/skills/rotate/assets/template.json", "{}")
    return w, [one_artifact("skill", "rotate", factors=["bundled_executable"]),
               has("helper paths recorded",
                   lambda s: sorted(artifact(s, "skill").risk.get("helpers", []))
                   == ["rotate.sh", "template.json"])]


@case("S-04")
def s04():
    w = World().json("~/.claude/plugins/acme-tools/.claude-plugin/plugin.json",
                     {"name": "acme-tools", "author": "Acme", "version": "1.0.0"})
    w.file("~/.claude/plugins/acme-tools/skills/rotate-keys/SKILL.md",
           "---\nname: rotate-keys\n---\nbody\n")
    return w, [one_artifact("plugin", "acme-tools"),
               one_artifact("skill", "rotate-keys", scope="plugin"),
               has("skill records its plugin",
                   lambda s: artifact(s, "skill").risk.get("plugin") == "acme-tools")]


@case("S-05")
def s05():
    w = World().json("~/.claude/plugins/bundle/.claude-plugin/plugin.json", {"name": "bundle"})
    w.file("~/.claude/plugins/bundle/skills/a/SKILL.md", "---\nname: a\n---\nbody\n")
    w.file("~/.claude/plugins/bundle/agents/reviewer.md", "---\nname: reviewer\n---\nbody\n")
    w.json("~/.claude/plugins/bundle/hooks/hooks.json",
           {"hooks": {"PreToolUse": [{"matcher": "Bash",
                                      "hooks": [{"type": "command", "command": "echo hi"}]}]}})
    return w, [one_artifact("plugin", "bundle"), one_artifact("skill", "a"),
               one_artifact("agent_definition", "reviewer"), one_artifact("hook"),
               has("bundled surfaces record the plugin",
                   lambda s: artifact(s, "hook").risk.get("plugin") == "bundle")]


@case("S-06")
def s06():
    w = World()
    w.file("~/.claude/skills/deploy/SKILL.md", "---\nname: deploy\n---\npersonal\n")
    w.file("~/dev/payments/.claude/skills/deploy/SKILL.md", "---\nname: deploy\n---\nproject\n")
    w.json("~/.claude/plugins/p/.claude-plugin/plugin.json", {"name": "p"})
    w.file("~/.claude/plugins/p/skills/deploy/SKILL.md", "---\nname: deploy\n---\nplugin\n")
    return w, [count(3, kind="skill"),
               has("the project one is effective",
                   lambda s: [a.config_scope for a in assets(s, kind="skill")
                              if a.risk.get("effective")] == ["project"])]


@case("S-07")
def s07():
    body = "---\nname: big\nversion: 2.0\n---\n" + "line\n" * 400
    w = World().file("~/.claude/skills/big/SKILL.md", body)
    return w, [one_artifact("skill", "big", version="2.0"),
               has("line count recorded",
                   lambda s: artifact(s, "skill").risk.get("line_count", 0) > 400),
               has("body absent from the snapshot",
                   lambda s: "line\nline\nline" not in s.to_json())]


@case("S-08")
def s08():
    w = World().file("~/.claude/skills/broken/SKILL.md", "---\nname: broken\nno terminator\n")
    return w, [one_artifact("skill", "broken"),
               has("an error names the file",
                   lambda s: any("front matter" in e.get("message", "") for e in s.errors))]


@case("S-09")
def s09():
    w = World().file("~/.claude/skills/fetcher/SKILL.md",
                     "---\nname: fetcher\n---\nRun: curl -s https://vendor.example/data?k=CANARY\n")
    return w, [one_artifact("skill", "fetcher", factors=["external_network"]),
               has("host recorded without the query string",
                   lambda s: artifact(s, "skill").risk.get("network_hosts")
                   == ["https://vendor.example/data"]),
               has("body not captured", lambda s: "CANARY" not in s.to_json())]


@case("S-10")
def s10():
    w = World(policy={"plugin_registries": ["https://plugins.corp.example"]})
    w.json("~/.claude/plugins/community/.claude-plugin/plugin.json",
           {"name": "community", "source": "https://github.com/someone/marketplace"})
    return w, [one_artifact("plugin", "community", factors=["third_party_marketplace"]),
               has("source recorded",
                   lambda s: artifact(s, "plugin").risk.get("source")
                   == "https://github.com/someone/marketplace")]


# -- S.2 commands, output styles, plugins ---------------------------------

@case("S-11")
def s11():
    w = World().file("~/.claude/commands/ship.md", "Ship it\n")
    return w, [one_artifact("command", "ship", scope="personal")]


@case("S-12")
def s12():
    w = World()
    w.file("~/.claude/commands/deploy/staging.md", "staging\n")
    w.file("~/.claude/commands/deploy/prod.md", "prod\n")
    return w, [count(2, kind="command"),
               has("namespaced names",
                   lambda s: sorted(a.name for a in assets(s, kind="command"))
                   == ["deploy:prod", "deploy:staging"])]


@case("S-13")
def s13():
    w = World().file("~/.claude/output-styles/terse.md", "Be terse\n")
    return w, [one_artifact("output_style", "terse")]


@case("S-14")
def s14():
    w = World().json("~/.claude/plugins/acme/.claude-plugin/plugin.json",
                     {"name": "acme", "author": "Acme Inc", "version": "3.1.0",
                      "source": "https://github.com/acme/marketplace"})
    return w, [one_artifact("plugin", "acme", version="3.1.0"),
               has("author recorded",
                   lambda s: artifact(s, "plugin").risk.get("author") == "Acme Inc")]


@case("S-15")
def s15():
    w = World().json("~/.claude/plugins/acme/.claude-plugin/plugin.json", {"name": "acme"})
    w.json("~/.claude/plugins/acme/.mcp.json",
           {"mcpServers": {"a": {"command": "node", "args": ["a.js"]},
                           "b": {"command": "node", "args": ["b.js"]}}})
    return w, [count(2, kind="mcp_server"),
               has("each records the plugin it came from",
                   lambda s: all(a.risk.get("plugin") == "acme"
                                 for a in assets(s, kind="mcp_server")))]


@case("S-16")
def s16():
    w = World()
    w.file("~/.codex/prompts/refactor.md", "refactor\n")
    w.file("~/.gemini/commands/explain.md", "explain\n")
    return w, [count(2, kind="command"),
               has("host apps recorded",
                   lambda s: sorted(a.risk.get("host_app") for a in assets(s, kind="command"))
                   == ["codex", "gemini-cli"])]


# -- S.3 hooks ------------------------------------------------------------

@case("S-17")
def s17():
    w = World().json("~/.claude/settings.json",
                     {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
                         {"type": "command", "command": "~/.claude/hooks/audit.sh"}]}]}})
    w.file("~/.claude/hooks/audit.sh", "#!/bin/sh\necho audited\n")
    return w, [one_artifact("hook", factors=["executes_on_every_turn"]),
               has("event, matcher and handler recorded",
                   lambda s: (artifact(s, "hook").risk.get("event"),
                              artifact(s, "hook").risk.get("matcher"),
                              artifact(s, "hook").risk.get("handler"))
                   == ("PreToolUse", "Bash", "command")),
               has("script target resolved",
                   lambda s: artifact(s, "hook").risk.get("target", "").endswith("audit.sh"))]


@case("S-18")
def s18():
    events = ["SessionStart", "UserPromptSubmit", "PostToolUse", "SubagentStop",
              "PreCompact", "FileChanged", "PermissionDenied", "WorktreeCreate"]
    hooks = {event: [{"hooks": [{"type": "command", "command": "echo x"}]}] for event in events}
    hooks["FutureEventName"] = [{"hooks": [{"type": "command", "command": "echo y"}]}]
    w = World().json("~/.claude/settings.json", {"hooks": hooks})
    return w, [count(9, kind="hook"),
               has("every event recorded verbatim",
                   lambda s: set(a.risk["event"] for a in assets(s, kind="hook"))
                   == set(events) | {"FutureEventName"}),
               has("an unknown event is flagged, not dropped",
                   lambda s: [a.risk.get("event_known") for a in assets(s, kind="hook")
                              if a.risk["event"] == "FutureEventName"] == [False])]


@case("S-19")
def s19():
    w = World().json("~/.claude/settings.json",
                     {"hooks": {"PostToolUse": [{"hooks": [
                         {"type": "http", "url": "https://vendor.example/collect?k=CANARY"}]}]}})
    return w, [one_artifact("hook", factors=["external_egress"]),
               has("destination recorded without the query",
                   lambda s: artifact(s, "hook").risk.get("destination")
                   == "https://vendor.example/collect"),
               has("no canary in the output", lambda s: "CANARY" not in s.to_json())]


@case("S-20")
def s20():
    w = World().json("~/.claude/settings.json", {"hooks": {
        "PreToolUse": [{"hooks": [{"type": "mcp_tool", "server": "audit-server"}]}],
        "Stop": [{"hooks": [{"type": "prompt", "prompt": "check"}]}],
        "SubagentStop": [{"hooks": [{"type": "agent", "agent": "verifier"}]}]}})
    return w, [count(3, kind="hook"),
               has("handler types recorded",
                   lambda s: sorted(a.risk["handler"] for a in assets(s, kind="hook"))
                   == ["agent", "mcp_tool", "prompt"]),
               has("the agent handler spawns a subagent",
                   lambda s: "spawns_subagent" in
                   [a for a in assets(s, kind="hook") if a.risk["handler"] == "agent"][0].risk["factors"]),
               has("the mcp_tool handler records its server",
                   lambda s: [a for a in assets(s, kind="hook")
                              if a.risk["handler"] == "mcp_tool"][0].risk.get("server")
                   == "audit-server")]


@case("S-21")
def s21():
    hook = {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "echo x"}]}]}}
    w = World().json("~/.claude/settings.json", hook)
    w.json("~/dev/payments/.claude/settings.json", hook)
    w.json("~/dev/payments/.claude/settings.local.json", hook)
    return w, [count(3, kind="hook"),
               has("three scopes including the gitignored local file",
                   lambda s: sorted(a.risk["scope"] for a in assets(s, kind="hook"))
                   == ["personal", "project", "project_local"])]


@case("S-22")
def s22():
    w = World().json("~/.claude/settings.json",
                     {"hooks": {"Stop": [{"hooks": [
                         {"type": "command", "command": "/Users/alice/.claude/hooks/gone.sh"}]}]}})
    return w, [one_artifact("hook", flags=["command_missing"])]


@case("S-23")
def s23():
    w = World().json("~/.claude/settings.json",
                     {"hooks": {"PostToolUse": [{"hooks": [
                         {"type": "command", "command": "~/.claude/hooks/sync.sh"}]}]}})
    w.file("~/.claude/hooks/sync.sh", "#!/bin/sh\ncp -r . ~/Library/Backups/CANARYDATA\n")
    return w, [one_artifact("hook", factors=["writes_outside_workspace"]),
               has("file contents are not captured",
                   lambda s: "CANARYDATA" not in s.to_json())]


@case("S-24")
def s24():
    w = World().json("~/.claude/plugins/watch/.claude-plugin/plugin.json", {"name": "watch"})
    w.json("~/.claude/plugins/watch/hooks/hooks.json",
           {"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "echo x"}]}]}})
    return w, [one_artifact("hook"),
               has("plugin recorded", lambda s: artifact(s, "hook").risk.get("plugin") == "watch")]


# -- S.4 instruction and rules files --------------------------------------

@case("S-25")
def s25():
    w = World().file("~/dev/payments/AGENTS.md", "# Build\nrun make\n")
    return w, [one_artifact("instructions", "AGENTS.md", scope="project"),
               has("format recorded, content not",
                   lambda s: artifact(s, "instructions").risk.get("format") == "agents.md"
                   and "run make" not in s.to_json())]


@case("S-26")
def s26():
    w = World()
    w.file("~/.claude/CLAUDE.md", "personal\n")
    w.file("~/dev/payments/CLAUDE.md", "project\n")
    return w, [count(2, kind="instructions"),
               has("both scopes present",
                   lambda s: sorted(a.risk["scope"] for a in assets(s, kind="instructions"))
                   == ["personal", "project"])]


@case("S-27")
def s27():
    w = World()
    w.file("~/dev/payments/GEMINI.md", "gemini\n")
    w.file("~/dev/payments/.github/copilot-instructions.md", "copilot\n")
    return w, [count(2, kind="instructions"),
               has("formats and hosts recorded",
                   lambda s: sorted(a.risk["format"] for a in assets(s, kind="instructions"))
                   == ["copilot-instructions", "gemini.md"])]


@case("S-28")
def s28():
    w = World()
    w.file("~/dev/payments/.cursor/rules/security.mdc",
           "---\nglobs: src/**/*.ts\n---\nBe careful\n")
    w.file("~/dev/payments/.cursorrules", "legacy rules\n")
    return w, [one_artifact("rules", "security.mdc"),
               one_artifact("instructions", ".cursorrules"),
               has("glob scope recorded",
                   lambda s: artifact(s, "rules").risk.get("globs") == "src/**/*.ts"),
               has("legacy format marked",
                   lambda s: artifact(s, "instructions").risk["format"] == "cursorrules-legacy")]


@case("S-29")
def s29():
    w = World().file("~/dev/payments/.windsurfrules", "rules\n")
    return w, [one_artifact("instructions", ".windsurfrules"),
               has("format is windsurfrules",
                   lambda s: artifact(s, "instructions").risk["format"] == "windsurfrules")]


@case("S-30")
def s30():
    w = World()
    w.file("~/dev/payments/CLAUDE.md", "See @AGENTS.md and @docs/style.md\n")
    w.file("~/dev/payments/AGENTS.md", "shared\n")
    return w, [has("imports recorded as edges",
                   lambda s: [a for a in assets(s, kind="instructions")
                              if a.name == "CLAUDE.md"][0].risk.get("imports")
                   == ["AGENTS.md", "docs/style.md"])]


@case("S-31")
def s31():
    w = World()
    for index in range(12):
        w.dir("~/dev/repo%d" % index)
        if index < 9:
            w.file("~/dev/repo%d/AGENTS.md" % index, "x\n")
    return w, [count(9, kind="instructions")]


# -- S.5 must not be invented ---------------------------------------------

@case("S-32")
def s32():
    w = World()
    w.file("~/.claude/notes.md", "just notes\n")
    w.file("~/.claude/shell-snapshots/snapshot-zsh-1786.sh", "#!/bin/zsh\n")
    return w, [none_of(kind="skill"), none_of(kind="command"), none_of(kind="hook")]


@case("S-33")
def s33():
    w = World().dir("~/.claude/skills").dir("~/.claude/commands").dir("~/.claude")
    return w, [none_of(kind="skill"),
               has("no errors", lambda s: s.errors == [] or s.errors),
               has("the tool itself is still discovered",
                   lambda s: any(a.catalog_id == "claude-code" for a in s.assets))]


@case("S-34")
def s34():
    w = World().file("~/dev/blog/posts/writing-claude-skills.md",
                     "Example:\n```\n---\nname: example\n---\nbody\n```\n")
    return w, [none_of(kind="skill")]


@case("S-35")
def s35():
    w = World().file("~/dev/payments/node_modules/some-plugin/skills/vendored/SKILL.md",
                     "---\nname: vendored\n---\nbody\n")
    return w, [none_of(kind="skill")]


@case("S-36")
def s36():
    w = World()
    w.file("~/Documents/CANARY-plan.md", "secret plan\n")
    w.file("~/Desktop/CANARY-notes.md", "secret notes\n")
    w.file("~/.claude/skills/ok/SKILL.md", "---\nname: ok\n---\nbody\n")
    return w, [one_artifact("skill", "ok"),
               has("personal paths never appear", lambda s: "CANARY" not in s.to_json())]
