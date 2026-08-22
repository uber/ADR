"""Group AG - AI agents: running, defined, scheduled, delegated and disowned."""

from .cases_tools import count, none_of
from .framework import World, assets, has, queued

CASES = {}


def case(case_id):
    def register(fn):
        CASES[case_id] = fn
        return fn
    return register


def agent(snapshot, catalog_id="claude-code", kind=None):
    matches = [a for a in snapshot.assets
               if a.catalog_id == catalog_id and (kind is None or a.kind == kind)]
    if len(matches) != 1:
        raise AssertionError("expected 1 %s%s, got %d: %s"
                             % (catalog_id, " " + kind if kind else "", len(matches),
                                [(a.name, a.kind) for a in matches]))
    return matches[0]


def one_agent(catalog_id="claude-code", kind=None, **fields):
    def check(snapshot):
        asset = agent(snapshot, catalog_id, kind)
        for key, value in fields.items():
            if key == "factors":
                got = asset.risk.get("factors", [])
                if not set(value).issubset(set(got)):
                    return "factors %r, expected to contain %r" % (got, value)
                continue
            got = {"sessions": asset.risk.get("session_count"),
                   "mode": asset.risk.get("mode"),
                   "schedule": asset.risk.get("schedule")}.get(key, getattr(asset, key, None))
            if got != value:
                return "%s == %r, expected %r" % (key, got, value)
        return True
    return has("one %s %s %s" % (catalog_id, kind or "", fields), check)


def claude_on_path(world):
    world.path("/opt/homebrew/bin").file("/opt/homebrew/bin/claude")
    return world


# -- AG.1 running agents --------------------------------------------------

@case("AG-01")
def ag01():
    w = claude_on_path(World()).proc(100, "/opt/homebrew/bin/claude", user="alice")
    return w, [one_agent(liveness="running", owner="alice"),
               has("runtime channel present",
                   lambda s: "runtime" in agent(s).channels)]


@case("AG-02")
def ag02():
    w = claude_on_path(World()).proc(100, "claude", user="alice")
    return w, [count(1, catalog_id="claude-code"), one_agent(liveness="running")]


@case("AG-03")
def ag03():
    w = World().proc(100, "/opt/homebrew/bin/claude", user="alice")
    return w, [one_agent(flags=["exe_missing"], liveness="running")]


@case("AG-04")
def ag04():
    w = claude_on_path(World())
    for pid in range(100, 106):
        w.proc(pid, "/opt/homebrew/bin/claude", user="alice")
    for pid in range(200, 203):
        w.proc(pid, "/opt/homebrew/bin/claude", user="bob")
    return w, [count(2, catalog_id="claude-code"),
               has("session counts per owner",
                   lambda s: sorted((a.owner, a.risk.get("session_count"))
                                    for a in assets(s, catalog_id="claude-code"))
                   == [("alice", 6), ("bob", 3)])]


@case("AG-05")
def ag05():
    w = claude_on_path(World())
    w.proc(100, "/opt/homebrew/bin/claude",
           argv=["claude", "-p", "review the backlog", "--dangerously-skip-permissions"])
    return w, [one_agent(factors=["unattended_run", "permission_bypass"]),
               has("flag names kept, prompt dropped",
                   lambda s: "--dangerously-skip-permissions" in agent(s).risk.get("argv", [])
                   and "review the backlog" not in s.to_json())]


@case("AG-06")
def ag06():
    w = claude_on_path(World())
    w.proc(100, "/opt/homebrew/bin/claude", argv=["claude", "--permission-mode", "sandbox"])
    return w, [one_agent(mode="sandbox"),
               has("sandbox is not recorded as a bypass",
                   lambda s: "permission_bypass" not in agent(s).risk.get("factors", []))]


@case("AG-07")
def ag07():
    w = claude_on_path(World())
    w.file("/Users/alice/dev/payments/.git/HEAD", "ref: refs/heads/main\n")
    for index, pid in enumerate((100, 101, 102)):
        worktree = "/Users/alice/dev/payments-wt%d" % index
        w.file("%s/.git" % worktree,
               "gitdir: /Users/alice/dev/payments/.git/worktrees/wt%d\n" % index)
        w.proc(pid, "/opt/homebrew/bin/claude", cwd=worktree, user="alice")
    return w, [one_agent(sessions=3),
               has("three sessions in one repository",
                   lambda s: agent(s).risk.get("repositories") == ["/Users/alice/dev/payments"]),
               has("worktrees recorded",
                   lambda s: len(agent(s).risk.get("worktrees", [])) == 3)]


@case("AG-08")
def ag08():
    w = claude_on_path(World())
    w.file("/opt/homebrew/bin/npx")
    w.proc(1, "/opt/homebrew/bin/claude")
    w.proc(2, "/opt/homebrew/bin/npx", argv=["npx", "-y", "mcp-a@1.0.0"], ppid=1)
    w.proc(3, "/opt/homebrew/bin/npx", argv=["npx", "-y", "mcp-b@1.0.0"], ppid=1)
    return w, [count(2, kind="mcp_server"),
               has("both bound to the agent",
                   lambda s: all(a.parent_agent == "claude-code"
                                 for a in assets(s, kind="mcp_server")))]


@case("AG-09")
def ag09():
    running = claude_on_path(World()).proc(100, "/opt/homebrew/bin/claude")
    installed = claude_on_path(World())
    residue = World().dir("/Users/alice/.claude")
    return running, [one_agent(liveness="running"),
                     has("installed and idle",
                         lambda s: agent(installed.scan()).liveness == "installed"),
                     has("state only",
                         lambda s: agent(residue.scan()).liveness == "declared_only")]


@case("AG-10")
def ag10():
    w = World().proc(100, "/usr/local/bin/docker",
                     argv=["docker", "run", "-v", "/Users/alice/dev/payments:/work",
                           "ghcr.io/acme/claude-code-devbox:1.0"])
    return w, [one_agent(flags=["containerized"], install_method="container"),
               has("image and mount recorded",
                   lambda s: agent(s).risk.get("image", "").startswith("ghcr.io/acme/claude-code")
                   and bool(agent(s).risk.get("mounts")))]


@case("AG-11")
def ag11():
    w = World(platform="windows",
              locations=[{"kind": "wsl", "name": "Ubuntu", "root": "/wsl/Ubuntu",
                          "home": "/home/alice"}])
    w.file("/wsl/Ubuntu/usr/local/bin/claude")
    w.proc(100, "/wsl/Ubuntu/usr/local/bin/claude", user="alice")
    return w, [one_agent(location="wsl:Ubuntu", liveness="running")]


# -- AG.2 defined agents --------------------------------------------------

DEFINITION = """---
name: code-reviewer
description: Reviews a diff for correctness
tools: Bash, Read, Grep
---
Review carefully.
"""


@case("AG-12")
def ag12():
    w = World().file("~/.claude/agents/code-reviewer.md", DEFINITION)
    return w, [has("one personal agent definition",
                   lambda s: [(a.name, a.risk.get("scope"), a.liveness)
                              for a in assets(s, kind="agent_definition")]
                   == [("code-reviewer", "personal", "declared_only")]),
               has("tool grants recorded",
                   lambda s: assets(s, kind="agent_definition")[0].risk.get("tools")
                   == "Bash, Read, Grep")]


@case("AG-13")
def ag13():
    w = World()
    w.file("~/.claude/agents/migration-runner.md", "---\nname: migration-runner\n---\nx\n")
    w.file("~/dev/payments/.claude/agents/migration-runner.md",
           "---\nname: migration-runner\n---\ny\n")
    return w, [count(2, kind="agent_definition"),
               has("scopes differ",
                   lambda s: sorted(a.risk["scope"] for a in assets(s, kind="agent_definition"))
                   == ["personal", "project"])]


@case("AG-14")
def ag14():
    w = World().file("~/.claude/agents/omni.md",
                     "---\nname: omni\ntools: \"*\"\n---\nx\n")
    return w, [has("unrestricted tools flagged",
                   lambda s: "unrestricted_tools" in
                   assets(s, kind="agent_definition")[0].risk["factors"]),
               has("grant recorded verbatim",
                   lambda s: assets(s, kind="agent_definition")[0].risk["tools"] == "*")]


@case("AG-15")
def ag15():
    w = World().file("~/.claude/agents/deep.md",
                     "---\nname: deep\nmodel: claude-opus-5\n---\nx\n")
    return w, [has("model recorded",
                   lambda s: assets(s, kind="agent_definition")[0].risk.get("model")
                   == "claude-opus-5")]


@case("AG-16")
def ag16():
    w = World().json("~/.claude/plugins/reviewers/.claude-plugin/plugin.json",
                     {"name": "reviewers"})
    w.file("~/.claude/plugins/reviewers/agents/a.md", "---\nname: a\n---\nx\n")
    w.file("~/.claude/plugins/reviewers/agents/b.md", "---\nname: b\n---\nx\n")
    return w, [count(2, kind="agent_definition"),
               has("plugin recorded on both",
                   lambda s: all(a.risk.get("plugin") == "reviewers"
                                 for a in assets(s, kind="agent_definition")))]


@case("AG-17")
def ag17():
    w = World().file("~/.cursor/agents/refactorer.md", "---\nname: refactorer\n---\nx\n")
    return w, [has("host app recorded",
                   lambda s: assets(s, kind="agent_definition")[0].risk.get("host_app")
                   == "cursor")]


# -- AG.3 scheduled and delegated -----------------------------------------

@case("AG-18")
def ag18():
    w = claude_on_path(World())
    w.plist("~/Library/LaunchAgents/com.alice.nightly-claude.plist",
            {"Label": "com.alice.nightly-claude",
             "ProgramArguments": ["/opt/homebrew/bin/claude", "-p", "review the backlog"],
             "StartCalendarInterval": {"Hour": 3, "Minute": 0}})
    return w, [has("one scheduled agent",
                   lambda s: len(assets(s, kind="scheduled_agent")) == 1),
               has("schedule captured",
                   lambda s: assets(s, kind="scheduled_agent")[0].risk.get("schedule") == "at 03:00"),
               has("unattended, prompt dropped, flag kept",
                   lambda s: "unattended_run" in assets(s, kind="scheduled_agent")[0].risk["factors"]
                   and "review the backlog" not in s.to_json()
                   and "-p" in assets(s, kind="scheduled_agent")[0].risk.get("argv", []))]


@case("AG-19")
def ag19():
    w = World().run("crontab", "0 * * * * /opt/homebrew/bin/codex exec 'triage'\n")
    return w, [has("one scheduled codex agent",
                   lambda s: [(a.catalog_id, a.risk.get("schedule"))
                              for a in assets(s, kind="scheduled_agent")]
                   == [("codex", "0 * * * *")])]


@case("AG-20")
def ag20():
    linux = World(platform="linux")
    linux.file("/home/alice/.config/systemd/user/agent.timer",
               "[Timer]\nOnCalendar=daily\n")
    linux.file("/home/alice/.config/systemd/user/agent.service",
               "[Service]\nExecStart=/usr/local/bin/claude -p nightly\n")
    win = World(platform="windows",
                scheduled_tasks=[{"name": "NightlyClaude", "schedule": "daily 03:00",
                                  "argv": ["C:/Users/alice/.local/bin/claude.exe", "-p", "x"]}])
    return linux, [has("systemd timer found",
                       lambda s: [a.risk.get("schedule") for a in assets(s, kind="scheduled_agent")]
                       == ["daily"]),
                   has("windows scheduled task found",
                       lambda s: [a.risk.get("schedule")
                                  for a in assets(win.scan(), kind="scheduled_agent")]
                       == ["daily 03:00"])]


@case("AG-21")
def ag21():
    w = World().file("~/dev/payments/.github/workflows/triage.yml", """
name: triage
on:
  schedule:
    - cron: "0 6 * * *"
jobs:
  triage:
    steps:
      - run: npx -y @anthropic-ai/claude-code -p "triage issues"
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
""")
    return w, [has("one ci agent",
                   lambda s: len(assets(s, kind="ci_agent")) == 1),
               has("trigger and repository recorded",
                   lambda s: (assets(s, kind="ci_agent")[0].risk.get("trigger"),
                              assets(s, kind="ci_agent")[0].risk.get("repository"))
                   == ("schedule", "/Users/alice/dev/payments")),
               has("declared secrets recorded by name",
                   lambda s: assets(s, kind="ci_agent")[0].risk.get("secrets")
                   == ["ANTHROPIC_API_KEY"])]


@case("AG-22")
def ag22():
    w = claude_on_path(World())
    w.plist("~/Library/LaunchAgents/com.alice.claude-login.plist",
            {"Label": "com.alice.claude-login", "RunAtLoad": True,
             "ProgramArguments": ["/opt/homebrew/bin/claude", "serve"]})
    return w, [has("runs at login",
                   lambda s: "runs_at_login" in assets(s, kind="scheduled_agent")[0].flags)]


@case("AG-23")
def ag23():
    base = "~/Library/Application Support/Claude/local-agent-mode-sessions/alice/org"
    w = World()
    w.file("%s/agent/local_ditto_9f2c/audit.jsonl" % base, '{"type":"start"}\n')
    w.file("%s/local_abc123/audit.jsonl" % base, '{"type":"start"}\n')
    return w, [count(2, kind="agent"),
               has("dispatch distinguished from interactive",
                   lambda s: sorted(bool(a.flags) for a in assets(s, kind="agent"))
                   == [False, True])]


@case("AG-24")
def ag24():
    w = World().json("~/.claude/cloud-sessions.json",
                     [{"task": "refactor", "runner": "vendor-cloud"},
                      {"task": "tests", "runner": "vendor-cloud"}])
    return w, [has("one cloud agent with its session count",
                   lambda s: [(a.kind, a.location, a.risk.get("session_count"))
                              for a in assets(s, kind="cloud_agent")]
                   == [("cloud_agent", "remote", 2)])]


@case("AG-25")
def ag25():
    w = World().sock(3001, pid=500).http(3001, "/v1/models", {"data": [{"id": "x"}]})
    w.proc(500, "/usr/local/bin/openhands")
    return w, [has("self-hosted platform found by port and binary",
                   lambda s: [(a.catalog_id, a.kind) for a in assets(s, catalog_id="openhands")]
                   == [("openhands", "agent_platform")])]


# -- AG.4 identity, usage and credentials ---------------------------------

@case("AG-26")
def ag26():
    w = World(policy={"corporate_domains": ["corp.example"]})
    w.json("~/.claude/.credentials.json",
           {"claudeAiOauth": {"account": "alice@gmail.com", "accessToken": "oauth-CANARY"}})
    return w, [has("personal account flagged",
                   lambda s: agent(s).risk.get("account_type") == "personal"
                   and "personal_account" in agent(s).risk.get("factors", [])),
               has("token never recorded", lambda s: "oauth-CANARY" not in s.to_json())]


@case("AG-27")
def ag27():
    w = World().file("~/.zshrc", 'export ANTHROPIC_API_KEY="sk-ant-CANARYKEY123456"\n')
    return w, [has("auth method and provider recorded",
                   lambda s: agent(s).risk.get("auth_method") == "api_key"
                   and agent(s).risk.get("credential_kinds") == ["anthropic"]),
               has("value absent", lambda s: "CANARYKEY123456" not in s.to_json())]


@case("AG-28")
def ag28():
    w = claude_on_path(World()).path("/usr/local/bin")
    w.file("/usr/local/bin/codex")
    w.used("claude-code", "2026-08-16T09:12:00Z")
    return w, [one_agent(last_used="2026-08-16T09:12:00Z"),
               has("telemetry channel on the used one",
                   lambda s: "telemetry" in agent(s).channels),
               has("the unused one has no last_used and no telemetry channel",
                   lambda s: agent(s, "codex").last_used is None
                   and "telemetry" not in agent(s, "codex").channels)]


@case("AG-29")
def ag29():
    w = claude_on_path(World())
    return w, [one_agent(last_used=None, liveness="installed")]


@case("AG-30")
def ag30():
    w = World()
    w.file("~/dev/helpdesk-bot/.env", "ANTHROPIC_API_KEY=sk-ant-x\n")
    for index in range(40):
        w.file("~/dev/helpdesk-bot/sessions/s%d.jsonl" % index,
               '{"role":"user","content":"hi"}\n')
    return w, [has("queued with its usage attached",
                   lambda s: queued(s, "helpdesk-bot")
                   and queued(s, "helpdesk-bot")[0].get("sessions") == 40),
               has("usage raises priority",
                   lambda s: queued(s, "helpdesk-bot")[0].get("priority", 0)
                   > queued(s, "helpdesk-bot")[0]["score"])]


@case("AG-31")
def ag31():
    w = claude_on_path(World(policy={"sensitive_repos": ["/Users/alice/dev/payments"]}))
    w.file("/Users/alice/dev/payments/.git/HEAD", "ref: refs/heads/main\n")
    w.file("/Users/alice/dev/payments/secrets.txt", "CANARYSECRET\n")
    w.proc(100, "/opt/homebrew/bin/claude", cwd="/Users/alice/dev/payments", user="alice")
    return w, [one_agent(factors=["sensitive_repository"]),
               has("repository recorded",
                   lambda s: agent(s).risk.get("repositories") == ["/Users/alice/dev/payments"]),
               has("no file contents captured", lambda s: "CANARYSECRET" not in s.to_json())]


# -- AG.5 open world, and what is not an agent ----------------------------

@case("AG-32")
def ag32():
    w = World()
    w.file("~/dev/helpdesk-bot/.env", "ANTHROPIC_API_KEY=sk-ant-x\n")
    w.file("~/dev/helpdesk-bot/sessions/a.jsonl", '{"role":"user","content":"hi"}\n')
    return w, [has("queued with both signals and a high score",
                   lambda s: queued(s, "helpdesk-bot")
                   and sorted(queued(s, "helpdesk-bot")[0]["signals"])
                   == ["credential_affinity", "state_shape"]
                   and queued(s, "helpdesk-bot")[0]["score"] >= 0.8)]


@case("AG-33")
def ag33():
    w = World().path("/usr/local/bin")
    w.file("/usr/local/bin/acmecode")
    w.file("~/.acmecode/sessions/a.jsonl", '{"role":"user","content":"hi"}\n')
    return w, [has("queued on state shape",
                   lambda s: queued(s, "acmecode")
                   and "state_shape" in queued(s, "acmecode")[0]["signals"]),
               none_of(catalog_id="claude-code")]


@case("AG-34")
def ag34():
    w = World()
    w.file("~/dev/analytics/pyproject.toml", '[project]\ndependencies = ["anthropic"]\n')
    w.file("~/dev/analytics/main.py", "import anthropic\n")
    return w, [none_of(kind="cli_agent"),
               has("not queued as an agent", lambda s: not queued(s, "analytics"))]


@case("AG-35")
def ag35():
    w = World()
    w.proc(1, "/bin/bash", argv=["bash", "-c", "make test"])
    w.proc(2, "/opt/homebrew/bin/rg", argv=["rg", "--json", "x"])
    w.proc(3, "/opt/homebrew/bin/node", argv=["node", "build.js"])
    w.proc(4, "/usr/local/bin/agent-editor", argv=["agent-editor"])
    return w, [none_of(kind="cli_agent"), none_of(kind="mcp_server")]


@case("AG-36")
def ag36():
    w = claude_on_path(World())
    w.proc(1, "/usr/local/bin/tmux", argv=["tmux", "server"])
    for pid in range(10, 30):
        w.proc(pid, "/bin/zsh", argv=["zsh"], ppid=1)
    w.proc(31, "/opt/homebrew/bin/claude", ppid=1, user="alice")
    return w, [count(1, catalog_id="claude-code"), one_agent(sessions=1)]
