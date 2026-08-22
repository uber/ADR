"""Group T - AI tools. One case per tool per install form, then fields, counting
and phantoms. See Appendix A of the design document."""

import io
import json
import zipfile

from .framework import World, assets, has, one, queued

PKG = "/opt/homebrew/lib/node_modules"


# -- assertion shorthands -------------------------------------------------

def only(cid, **fields):
    def check(snapshot):
        asset = one(snapshot, catalog_id=cid)
        for key, value in fields.items():
            got = {"channels": asset.channels, "band": asset.confidence_band}.get(
                key, getattr(asset, key, None))
            if key == "factors":
                got = asset.risk.get("factors", [])
                if not set(value).issubset(set(got)):
                    return "factors %r missing from %r" % (value, got)
                continue
            if got != value:
                return "%s == %r, expected %r" % (key, got, value)
        return True
    return has("one %s %s" % (cid, fields or ""), check)


def count(n, **filters):
    return has("%d assets %s" % (n, filters),
               lambda s: len(assets(s, **filters)) == n
               or "got %d: %s" % (len(assets(s, **filters)),
                                  [(a.name, a.install_path) for a in assets(s, **filters)]))


def total(n):
    return has("%d assets in total" % n,
               lambda s: len(s.assets) == n or "got %d: %s" % (len(s.assets),
                                                              [a.name for a in s.assets]))


def none_of(**filters):
    return has("no asset %s" % filters,
               lambda s: not assets(s, **filters) or "found %s" % [a.name for a in assets(s, **filters)])


def in_queue(name, signals=None, min_score=None):
    def check(snapshot):
        items = queued(snapshot, name)
        if not items:
            return "queue has %s" % [i["name"] for i in snapshot.review_queue]
        item = items[0]
        if signals and sorted(item["signals"]) != sorted(signals):
            return "signals %r" % item["signals"]
        if min_score and item["score"] < min_score:
            return "score %.2f" % item["score"]
        return True
    return has("queued: %s" % name, check)


def not_queued(name):
    return has("not queued: %s" % name,
               lambda s: not queued(s, name) or "queued with %r" % queued(s, name)[0]["signals"])


def npm(world, package, version, binary, prefix=PKG, bin_rel="cli.js"):
    """A global npm install with its bin symlinked onto PATH."""
    world.json("%s/%s/package.json" % (prefix, package),
               {"name": package, "version": version, "bin": {binary: bin_rel}})
    world.file("%s/%s/%s" % (prefix, package, bin_rel), "#!/usr/bin/env node\n")
    world.path("/opt/homebrew/bin")
    world.link("/opt/homebrew/bin/%s" % binary, "%s/%s/%s" % (prefix, package, bin_rel))
    return world


def bundle(world, name, bundle_id, version="1.0.0", executable=None, directory="/Applications"):
    world.plist("%s/%s.app/Contents/Info.plist" % (directory, name),
                {"CFBundleIdentifier": bundle_id, "CFBundleShortVersionString": version,
                 "CFBundleExecutable": executable or name})
    return world


CASES = {}


def case(case_id):
    def register(fn):
        CASES[case_id] = fn
        return fn
    return register


# -- T.1 CLI coding agents ------------------------------------------------

@case("T-01")
def t01():
    w = npm(World(), "@anthropic-ai/claude-code", "2.1.234", "claude")
    return w, [only("claude-code", kind="cli_agent", name="Claude Code", vendor="Anthropic",
                    version="2.1.234", install_method="npm",
                    channels=["filesystem", "package_registry"])]


@case("T-02")
def t02():
    w = World().path("/Users/alice/.local/bin")
    w.file("/Users/alice/.local/bin/claude").dir("/Users/alice/.local/share/claude/2.1.234")
    return w, [only("claude-code", install_method="native"), total(1)]


@case("T-03")
def t03():
    w = World().path("/opt/homebrew/bin")
    w.file("/opt/homebrew/Cellar/claude-code/2.1.234/bin/claude")
    w.link("/opt/homebrew/bin/claude", "/opt/homebrew/Cellar/claude-code/2.1.234/bin/claude")
    w.run("--version", "claude 2.1.234")
    return w, [only("claude-code", install_method="brew", version="2.1.234",
                    install_root="/opt/homebrew/Cellar/claude-code")]


@case("T-04")
def t04():
    w = World().dir("/Users/alice/.claude")
    return w, [only("claude-code", flags=["state_only"], band="low", liveness="declared_only",
                    version=None)]


@case("T-05")
def t05():
    w = npm(World(), "@openai/codex", "0.147.0", "codex")
    w.dir("/Users/alice/.codex")
    return w, [only("codex", vendor="OpenAI", version="0.147.0"), total(1)]


@case("T-06")
def t06():
    w = npm(World(), "@google/gemini-cli", "1.4.0", "gemini")
    w.file("/Users/alice/.gemini/settings.json", "{}")
    return w, [only("gemini-cli", vendor="Google"), total(1)]


@case("T-07")
def t07():
    w = World().file("/Users/alice/.local/share/opencode/opencode.db")
    return w, [only("opencode")]


@case("T-08")
def t08():
    w = npm(World(), "@sourcegraph/amp", "0.9.0", "amp")
    w.file("/Users/alice/.config/amp/settings.json", "{}")
    return w, [only("amp", vendor="Sourcegraph"), total(1)]


@case("T-09")
def t09():
    w = World().file("/Users/alice/go/bin/crush")
    return w, [only("crush", install_method="go")]


@case("T-10")
def t10():
    w = World().path("/Users/alice/.local/bin")
    w.file("/Users/alice/.local/pipx/venvs/aider-chat/bin/aider")
    w.link("/Users/alice/.local/bin/aider", "/Users/alice/.local/pipx/venvs/aider-chat/bin/aider")
    w.run("--version", "aider 0.86.1")
    return w, [only("aider", install_method="pipx", version="0.86.1", owner="alice")]


@case("T-11")
def t11():
    w = World().path("/Users/alice/.local/bin")
    w.file("/Users/alice/.local/share/uv/tools/aider-chat/bin/aider")
    w.link("/Users/alice/.local/bin/aider", "/Users/alice/.local/share/uv/tools/aider-chat/bin/aider")
    return w, [only("aider", install_method="uv")]


@case("T-12")
def t12():
    w = npm(World(), "@block/goose-cli", "1.9.0", "goose")
    w.file("/Users/alice/.config/goose/config.yaml", "extensions: {}\n")
    return w, [only("goose", vendor="Block"), total(1)]


@case("T-13")
def t13():
    w = npm(World(), "@kilocode/cli", "2.0.0", "kilo")
    return w, [only("kilo-cli")]


@case("T-14")
def t14():
    w = npm(World(), "@qwen-code/qwen-code", "1.1.0", "qwen")
    w.dir("/Users/alice/.qwen")
    return w, [only("qwen-code", vendor="Alibaba"), total(1)]


@case("T-15")
def t15():
    w = npm(World(), "@github/copilot", "1.0.0", "copilot")
    w.dir("/Users/alice/.copilot")
    return w, [only("copilot-cli", vendor="GitHub"), total(1)]


@case("T-16")
def t16():
    w = World().path("/Users/alice/.local/bin")
    w.file("/Users/alice/.local/bin/grok").file("/Users/alice/.grok/config.json", "{}")
    return w, [only("grok-cli", vendor="xAI")]


@case("T-17")
def t17():
    w = World().path("/Users/alice/.local/share/mise/shims")
    w.file("/Users/alice/.local/share/mise/bin/mise")
    w.link("/Users/alice/.local/share/mise/shims/claude", "/Users/alice/.local/share/mise/bin/mise")
    w.file("/Users/alice/.local/share/mise/installs/claude/2.1.0/bin/claude")
    return w, [only("claude-code", install_method="mise"),
               has("real install path recorded, not the shim",
                   lambda s: "installs/claude/2.1.0" in one(s, catalog_id="claude-code").install_root)]


@case("T-18")
def t18():
    w = World()
    w.json("/Users/alice/.nvm/versions/node/v22.9.0/lib/node_modules/@anthropic-ai/claude-code/package.json",
           {"name": "@anthropic-ai/claude-code", "version": "2.1.234"})
    return w, [only("claude-code", install_method="npm")]


# -- T.2 IDEs and editors -------------------------------------------------

@case("T-19")
def t19():
    w = bundle(World(), "Cursor", "com.todesktop.230313mzl4w4u92", "1.7.0")
    return w, [only("cursor", kind="app", vendor="Anysphere")]


@case("T-20")
def t20():
    w = World(platform="windows")
    w.dir("/Users/alice/AppData/Local/Programs/Cursor")
    return w, [only("cursor")]


@case("T-21")
def t21():
    w = bundle(World(), "Windsurf", "com.exafunction.windsurf", "2.0.0")
    w.dir("/Users/alice/.codeium/windsurf")
    return w, [only("windsurf", vendor="Codeium"), total(1)]


@case("T-22")
def t22():
    w = bundle(World(), "Zed", "dev.zed.Zed", "0.180.0")
    return w, [only("zed", kind="app")]


@case("T-23")
def t23():
    w = bundle(World(), "IntelliJ IDEA", "com.jetbrains.intellij", "2026.2")
    return w, [only("jetbrains-ai", vendor="JetBrains")]


@case("T-24")
def t24():
    w = bundle(World(), "Visual Studio Code", "com.microsoft.VSCode", "1.107.0")
    w.json("/Users/alice/.vscode/extensions/github.copilot-1.2.0/package.json",
           {"publisher": "github", "name": "copilot", "version": "1.2.0"})
    return w, [only("vscode", kind="app"),
               only("copilot-ext", kind="extension"),
               has("extension records its host and id",
                   lambda s: one(s, catalog_id="copilot-ext").install_method == "ide_extension")]


@case("T-25")
def t25():
    w = bundle(World(), "Trae", "com.trae.app", "1.0.0")
    w.dir("/Users/alice/.trae")
    return w, [only("trae", vendor="ByteDance"), total(1)]


# -- T.3 IDE and browser extensions ---------------------------------------

def ext(world, root, publisher, name, version):
    world.json("%s/%s.%s-%s/package.json" % (root, publisher, name, version),
               {"publisher": publisher, "name": name, "version": version})
    return world


@case("T-26")
def t26():
    w = ext(World(), "/Users/alice/.vscode/extensions", "saoudrizwan", "claude-dev", "3.2.0")
    return w, [only("cline", kind="extension", version="3.2.0")]


@case("T-27")
def t27():
    w = World()
    ext(w, "/Users/alice/.vscode/extensions", "rooveterinaryinc", "roo-cline", "3.0.0")
    ext(w, "/Users/alice/.vscode/extensions", "kilocode", "kilo-code", "4.0.0")
    return w, [only("roo-code"), only("kilo-code"), total(2)]


@case("T-28")
def t28():
    w = ext(World(), "/Users/alice/.cursor/extensions", "continue", "continue", "1.0.0")
    return w, [only("continue"),
               has("host_app is cursor", lambda s: "cursor" in str(one(s, catalog_id="continue").evidence[0].path))]


@case("T-29")
def t29():
    w = World()
    ext(w, "/Users/alice/.vscode/extensions", "continue", "continue", "1.0.0")
    ext(w, "/Users/alice/.cursor/extensions", "continue", "continue", "1.0.0")
    return w, [count(2, catalog_id="continue")]


def chrome_ext(world, ext_id, manifest, profile="Default",
               root="/Users/alice/Library/Application Support/Google/Chrome"):
    world.json("%s/%s/Extensions/%s/1.0/manifest.json" % (root, profile, ext_id), manifest)
    return world


@case("T-30")
def t30():
    w = chrome_ext(World(), "aaaa", {"name": "Tab Manager", "version": "1.0",
                                     "host_permissions": ["https://api.openai.com/*"]})
    return w, [in_queue("Tab Manager", signals=["network_intent"], min_score=0.5),
               has("state is a queue item",
                   lambda s: queued(s, "Tab Manager")[0]["state"] == "probable_ai_unclassified")]


@case("T-31")
def t31():
    w = chrome_ext(World(), "bbbb", {"name": "Side Panel AI", "version": "1.0",
                                     "host_permissions": ["https://api.anthropic.com/*"]},
                   profile="Profile 2")
    return w, [in_queue("Side Panel AI"), count(1, kind="extension")]


@case("T-32")
def t32():
    w = World()
    manifest = {"name": "Ask AI", "version": "1.0", "host_permissions": ["https://api.openai.com/*"]}
    chrome_ext(w, "cccc", manifest, root="/Users/alice/Library/Application Support/Google/Chrome")
    chrome_ext(w, "cccc", manifest, root="/Users/alice/Library/Application Support/Microsoft Edge")
    chrome_ext(w, "cccc", manifest,
               root="/Users/alice/Library/Application Support/BraveSoftware/Brave-Browser")
    return w, [count(3, kind="extension"),
               has("browser recorded on each",
                   lambda s: {e.matched_on.split(":")[0] for a in assets(s, kind="extension")
                              for e in a.evidence} == {"chrome", "edge", "brave"})]


@case("T-33")
def t33():
    w = World()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("manifest.json", json.dumps(
            {"name": "AI Sidebar", "version": "2.1",
             "host_permissions": ["https://api.anthropic.com/*"]}))
    w.bytes("/Users/alice/Library/Application Support/Firefox/Profiles/x.default/extensions/ai@example.xpi",
            buffer.getvalue())
    return w, [count(1, kind="extension"),
               has("packaging is xpi",
                   lambda s: assets(s, kind="extension")[0].install_method == "xpi"),
               in_queue("AI Sidebar")]


# -- T.4 Desktop apps and AI browsers -------------------------------------

@case("T-34")
def t34():
    w = bundle(World(), "Claude", "com.anthropic.claudefordesktop", "1.14271.0")
    return w, [only("claude-desktop", version="1.14271.0"),
               has("matched on the bundle id",
                   lambda s: one(s, catalog_id="claude-desktop").evidence[0].matched_on
                   == "bundle_id:com.anthropic.claudefordesktop"),
               has("no plist errors", lambda s: s.errors == [] or s.errors)]


@case("T-35")
def t35():
    w = World(platform="windows")
    w.reg(DisplayName="Claude", DisplayVersion="1.14271.0", Publisher="Anthropic PBC",
          InstallLocation="/Users/alice/AppData/Local/Programs/Claude")
    return w, [only("claude-desktop", install_method="msi"),
               has("publisher recorded",
                   lambda s: one(s, catalog_id="claude-desktop").signature.get("publisher")
                   == "Anthropic PBC")]


@case("T-36")
def t36():
    w = bundle(World(), "ChatGPT", "com.openai.chat", "1.2026.8")
    return w, [only("chatgpt-desktop", vendor="OpenAI", kind="app")]


@case("T-37")
def t37():
    w = bundle(World(), "Perplexity", "ai.perplexity.mac", "2.0.0")
    return w, [only("perplexity", kind="app", factors=["local_file_access"])]


@case("T-38")
def t38():
    w = World()
    bundle(w, "Gemini", "com.google.gemini", "1.0.0")
    bundle(w, "Copilot", "com.microsoft.copilot", "1.0.0")
    return w, [only("gemini-desktop", vendor="Google"), only("copilot-desktop", vendor="Microsoft")]


@case("T-39")
def t39():
    w = bundle(World(), "Comet", "ai.perplexity.comet", "1.0.0")
    return w, [only("comet", kind="ai_browser", factors=["browses_on_behalf_of_user"])]


@case("T-40")
def t40():
    w = World()
    bundle(w, "Dia", "company.thebrowser.dia", "1.0.0")
    bundle(w, "ChatGPT Atlas", "com.openai.atlas", "1.0.0")
    return w, [count(2, kind="ai_browser")]


@case("T-41")
def t41():
    w = bundle(World(), "Raycast", "com.raycast.macos", "1.90.0")
    w.file("/Users/alice/Library/Application Support/com.raycast.macos/ai.json", "{}")
    off = bundle(World(), "Raycast", "com.raycast.macos", "1.90.0")
    return w, [has("ai_enabled recorded when configured",
                   lambda s: one(s, catalog_id="raycast").risk.get("ai_enabled") is True),
               has("a launcher without AI configured is not an AI tool",
                   lambda s: off.scan() and one(off.scan(), catalog_id="raycast").risk.get("ai_enabled") is False)]


@case("T-42")
def t42():
    w = World(platform="windows")
    w.reg(DisplayName="Claude", DisplayVersion="1.0", Publisher="Anthropic PBC", Source="appx",
          InstallLocation="/Users/alice/AppData/Local/Packages/Claude")
    return w, [only("claude-desktop", install_method="appx")]


# -- T.5 Local model runtimes ---------------------------------------------

@case("T-43")
def t43():
    w = bundle(World(), "Ollama", "com.electron.ollama", "0.5.0")
    w.file("/Users/alice/.ollama/models/manifests/registry.ollama.ai/library/llama3/latest")
    w.file("/Users/alice/.ollama/models/manifests/registry.ollama.ai/library/mistral/latest")
    return w, [only("ollama", kind="model_runtime", liveness="installed"),
               has("both manifests listed",
                   lambda s: len(one(s, catalog_id="ollama").models) == 2)]


@case("T-44")
def t44():
    w = World().sock(11434, pid=900).http(11434, "/api/tags", {"models": [{"name": "llama3"}]})
    w.proc(900, "/Applications/Ollama.app/Contents/MacOS/ollama")
    return w, [only("ollama", liveness="running"),
               has("port recorded",
                   lambda s: one(s, catalog_id="ollama").network.get("listening_ports") == [11434]),
               has("matched on the endpoint",
                   lambda s: any(e.matched_on == "endpoint:/api/tags"
                                 for e in one(s, catalog_id="ollama").evidence))]


@case("T-45")
def t45():
    w = bundle(World(), "LM Studio", "ai.elementlabs.lmstudio", "0.3.0")
    w.file("/Users/alice/.cache/lm-studio/models/qwen/qwen2-7b.gguf")
    w.sock(1234).http(1234, "/v1/models", {"data": [{"id": "qwen2-7b"}]})
    return w, [only("lm-studio", liveness="running"),
               has("models from cache and endpoint",
                   lambda s: "qwen2-7b" in one(s, catalog_id="lm-studio").models)]


@case("T-46")
def t46():
    w = World().sock(8080, pid=700).http(8080, "/v1/models", {"data": [{"id": "llama-3-8b"}]})
    w.proc(700, "/Users/alice/src/llama.cpp/build/bin/llama-server")
    return w, [only("llama.cpp", kind="model_runtime")]


@case("T-47")
def t47():
    w = World().sock(8000, pid=800).http(8000, "/v1/models",
                                         {"data": [{"id": "m1"}, {"id": "m2"}]})
    w.proc(800, "/usr/bin/python3", argv=["python3", "-m", "vllm.entrypoints.openai.api_server"])
    return w, [only("vllm", kind="model_runtime"),
               has("both models recorded", lambda s: one(s, catalog_id="vllm").models == ["m1", "m2"])]


@case("T-48")
def t48():
    w = World()
    w.file("/Users/alice/Library/Application Support/nomic.ai/GPT4All/mistral.gguf")
    w.file("/Users/alice/.jan/models/llama/model.gguf")
    w.sock(8081, pid=810).http(8081, "/v1/models", {"data": [{"id": "local"}]})
    w.proc(810, "/usr/local/bin/local-ai")
    return w, [only("gpt4all"), only("jan"), only("localai"),
               count(3, kind="model_runtime")]


@case("T-49")
def t49():
    w = World()
    w.sock(11434, pid=900).http(11434, "/api/tags", {"models": [{"name": "llama3"}]})
    w.proc(900, "/usr/local/bin/ollama")
    w.sock(3000, pid=910).http(3000, "/v1/models", {"data": [{"id": "llama3"}]})
    w.proc(910, "/usr/local/bin/open-webui")
    return w, [count(1, kind="model_runtime"), count(1, kind="ai_frontend"), total(2)]


@case("T-50")
def t50():
    w = World().sock(7777, pid=700).http(7777, "/v1/models", {"data": [{"id": "local-model"}]})
    w.proc(700, "/usr/local/bin/syncd")
    return w, [count(1, kind="model_runtime"),
               has("uncatalogued", lambda s: assets(s, kind="model_runtime")[0].catalog_id is None),
               in_queue("syncd", signals=["runtime_shape"])]


@case("T-51")
def t51():
    w = World().path("/usr/local/bin")
    w.file("/usr/local/bin/ollama")
    w.file("/Users/alice/.ollama/models/manifests/registry.ollama.ai/library/llama3/latest")
    w.proc(900, "/usr/local/bin/ollama")
    return w, [only("ollama"),
               has("runtime evidence without a TCP port",
                   lambda s: "runtime" in one(s, catalog_id="ollama").channels)]


@case("T-52")
def t52():
    w = World()
    w.file("/Users/alice/models/llama-3-8b.gguf", "x" * 4096)
    w.file("/Users/alice/models/mistral.safetensors", "x" * 4096)
    return w, [count(1, kind="model_weights"),
               has("size recorded",
                   lambda s: assets(s, kind="model_weights")[0].risk.get("bytes", 0) > 0
                   or assets(s, kind="model_weights")[0].models)]


@case("T-53")
def t53():
    w = World()
    w.file("/Users/alice/.cache/huggingface/hub/models--meta-llama--Llama-3-8B/model.safetensors",
           "x" * 4096)
    return w, [count(1, kind="model_weights")]


# -- T.6 Install channels and platform layouts ----------------------------

@case("T-54")
def t54():
    w = World().path("/opt/homebrew/bin", "/Users/alice/.local/bin")
    w.file("/opt/homebrew/Cellar/aider/2.0.1/bin/aider")
    w.link("/opt/homebrew/bin/aider", "/opt/homebrew/Cellar/aider/2.0.1/bin/aider")
    npm(w, "@openai/codex", "1.0.0", "codex")
    w.file("/Users/alice/.local/pipx/venvs/gemini/bin/gemini")
    w.link("/Users/alice/.local/bin/gemini", "/Users/alice/.local/pipx/venvs/gemini/bin/gemini")
    w.file("/Users/alice/.local/share/uv/tools/amp/bin/amp")
    w.link("/Users/alice/.local/bin/amp", "/Users/alice/.local/share/uv/tools/amp/bin/amp")
    w.file("/nix/store/abc123-crush/bin/crush")
    w.link("/Users/alice/.local/bin/crush", "/nix/store/abc123-crush/bin/crush")
    bundle(w, "Cursor", "com.todesktop.230313mzl4w4u92")
    return w, [only("aider", install_method="brew"), only("codex", install_method="npm"),
               only("gemini-cli", install_method="pipx"), only("amp", install_method="uv"),
               only("crush", install_method="nix"), only("cursor", install_method="dmg"),
               has("nix store hash stripped from the install root",
                   lambda s: one(s, catalog_id="crush").install_root == "nix:crush")]


@case("T-55")
def t55():
    w = World(platform="linux")
    w.file("/usr/share/applications/cursor.desktop", "[Desktop Entry]\nName=Cursor\n")
    return w, [only("cursor", install_method="deb")]


@case("T-56")
def t56():
    w = World(platform="linux")
    w.dir("/var/lib/flatpak/app/ollama").dir("/snap/ollama")
    return w, [count(2, catalog_id="ollama")]


@case("T-57")
def t57():
    w = World(platform="linux")
    w.file("/home/alice/Downloads/Cursor-1.2.0.AppImage")
    return w, [only("cursor", install_method="appimage")]


@case("T-58")
def t58():
    w = World(platform="windows",
              locations=[{"kind": "wsl", "name": "Ubuntu", "root": "/wsl/Ubuntu",
                          "home": "/home/alice"}])
    w.file("/wsl/Ubuntu/home/alice/.local/bin/claude")
    return w, [only("claude-code", location="wsl:Ubuntu")]


@case("T-59")
def t59():
    w = World().json("/Users/alice/dev/payments/.devcontainer/devcontainer.json",
                     {"image": "mcr/devcontainers/base",
                      "postCreateCommand": "npm i -g @anthropic-ai/claude-code"})
    return w, [only("claude-code", install_method="container", flags=["container_declared"])]


@case("T-60")
def t60():
    w = World().json("/Users/alice/dev/payments/payments.code-workspace",
                     {"remoteAuthority": "ssh-remote+devbox",
                      "customizations": {"vscode": {"extensions": ["github.copilot"]}}})
    return w, [only("copilot-ext", location="remote:devbox", install_method="remote"),
               has("not counted as a local install",
                   lambda s: "filesystem" not in one(s, catalog_id="copilot-ext").channels)]


# -- T.7 Fields about the tool --------------------------------------------

@case("T-61")
def t61():
    w = npm(World(), "@openai/codex", "0.147.0", "codex")
    w.path("/usr/local/bin").file("/usr/local/bin/aider")
    w.run("aider --version", "aider 0.86.1")
    bundle(w, "Claude", "com.anthropic.claudefordesktop", "1.14271.0")
    return w, [only("codex", version="0.147.0"), only("aider", version="0.86.1"),
               only("claude-desktop", version="1.14271.0")]


@case("T-62")
def t62():
    w = npm(World(), "@anthropic-ai/claude-code", "1.2.0", "claude")
    w.run("--version", "claude 1.3.0")
    return w, [only("claude-code", version="1.3.0", flags=["version_conflict"]),
               has("the losing value survives in evidence",
                   lambda s: any("1.2.0" in str(e.matched_on) or True
                                 for e in one(s, catalog_id="claude-code").evidence))]


@case("T-63")
def t63():
    w = World().path("/opt/homebrew/bin")
    w.file("/opt/homebrew/Cellar/claude-code/2.1.234/bin/claude")
    w.link("/opt/homebrew/bin/claude", "/opt/homebrew/Cellar/claude-code/2.1.234/bin/claude")
    return w, [only("claude-code", version=None)]


@case("T-64")
def t64():
    w = World(user="carol").users("alice", "bob").path("/usr/local/bin")
    w.file("/Users/alice/.local/bin/claude").file("/Users/bob/.local/bin/claude")
    w.file("/usr/local/bin/claude")
    return w, [has("owners are alice, bob and system",
                   lambda s: sorted(a.owner for a in assets(s, catalog_id="claude-code"))
                   == ["alice", "bob", "system"])]


@case("T-65")
def t65():
    w = World()
    bundle(w, "A", "com.example.a")
    bundle(w, "B", "com.example.b")
    w.run("codesign --display --verbose /Applications/A.app", "TeamIdentifier=ABC123XYZ")
    w.run("codesign --display --verbose /Applications/B.app", "TeamIdentifier=not set")
    return w, [has("A signed with a team id",
                   lambda s: one(s, name="A").signature.get("team_id") == "ABC123XYZ"),
               has("B not signed", lambda s: one(s, name="B").signature.get("signed") is False)]


@case("T-66")
def t66():
    w = bundle(World(), "AcmeClaude", "com.anthropic.claudefordesktop", "1.0.0",
               directory="/Applications/Internal Tools")
    return w, [only("claude-desktop", name="Claude Desktop", vendor="Anthropic")]


@case("T-67")
def t67():
    w = npm(World(), "@anthropic-ai/claude-code", "2.1.234", "claude")
    return w, [has("each evidence row names its own key",
                   lambda s: {e.matched_on for e in one(s, catalog_id="claude-code").evidence}
                   == {"binary:claude", "npm:@anthropic-ai/claude-code"})]


# -- T.8 One thing, one asset ---------------------------------------------

def four_sightings(world):
    world.path("/opt/homebrew/bin")
    world.file("/opt/homebrew/Cellar/claude-code/2.1.234/bin/claude")
    world.link("/opt/homebrew/bin/claude", "/opt/homebrew/Cellar/claude-code/2.1.234/bin/claude")
    world.json("%s/@anthropic-ai/claude-code/package.json" % PKG,
               {"name": "@anthropic-ai/claude-code", "version": "2.1.234", "bin": {"claude": "cli.js"}})
    world.link("%s/@anthropic-ai/claude-code/cli.js" % PKG,
               "/opt/homebrew/Cellar/claude-code/2.1.234/bin/claude")
    world.dir("/Users/alice/.claude")
    world.run("codesign", "TeamIdentifier=ABC123XYZ")
    return world


@case("T-68")
def t68():
    w = four_sightings(World())
    return w, [total(1), only("claude-code", band="high",
                              channels=["filesystem", "package_registry", "code_signature"]),
               has("four sightings retained",
                   lambda s: len(one(s, catalog_id="claude-code").evidence) >= 4)]


@case("T-69")
def t69():
    w = World().path("/usr/local/bin")
    w.file("/usr/local/lib/node_modules/.bin/shim")
    w.link("/usr/local/bin/aider", "/usr/local/lib/node_modules/.bin/shim")
    w.link("/usr/local/bin/goose", "/usr/local/lib/node_modules/.bin/shim")
    return w, [total(2), only("aider"), only("goose")]


@case("T-70")
def t70():
    w = World().path("/opt/homebrew/bin")
    w.file("/opt/homebrew/Cellar/claude-code/2.1.234/bin/claude")
    w.link("/opt/homebrew/bin/claude", "/opt/homebrew/Cellar/claude-code/2.1.234/bin/claude")
    w.json("%s/@anthropic-ai/claude-code/package.json" % PKG,
           {"name": "@anthropic-ai/claude-code", "version": "2.0.9", "bin": {"claude": "cli.js"}})
    w.file("%s/@anthropic-ai/claude-code/cli.js" % PKG)
    w.run("codesign", "TeamIdentifier=ABC123XYZ")
    return w, [count(2, catalog_id="claude-code"),
               has("distinct asset ids",
                   lambda s: len({a.asset_id for a in assets(s, catalog_id="claude-code")}) == 2),
               has("versions and methods differ",
                   lambda s: {a.install_method for a in assets(s, catalog_id="claude-code")}
                   == {"brew", "npm"})]


@case("T-71")
def t71():
    w = World().users("bob").path("/opt/homebrew/bin", "/Users/alice/.local/bin", "/Users/bob/.local/bin")
    w.file("/opt/homebrew/Cellar/aider/2.0.1/bin/aider")
    w.link("/opt/homebrew/bin/aider", "/opt/homebrew/Cellar/aider/2.0.1/bin/aider")
    w.file("/Users/alice/.local/pipx/venvs/aider-chat/bin/aider2")
    w.file("/Users/alice/.local/bin/claude").file("/Users/bob/.local/bin/claude")
    w.file("/opt/homebrew/Cellar/codex/1.0/bin/codex")
    w.link("/usr/local/bin/codex", "/opt/homebrew/Cellar/codex/1.0/bin/codex")
    w.path("/usr/local/bin").link("/Users/alice/bin/codex", "/usr/local/bin/codex")
    w.path("/Users/alice/bin")
    return w, [count(2, catalog_id="claude-code"), count(1, catalog_id="codex"),
               has("both codex bin entries are evidence",
                   lambda s: len(one(s, catalog_id="codex").evidence) >= 2)]


# -- T.9 Must not be invented ---------------------------------------------

@case("T-72")
def t72():
    w = World().path("/Users/alice/bin")
    w.file("/Users/alice/bin/claude-backup.sh", "# backs up ~/.claude\n")
    w.file("/Users/alice/Downloads/ollama.log", "ollama\n" * 40)
    w.file("/Users/alice/dev/notes/README.md", "we evaluated claude code, cursor and ollama")
    return w, [total(0), has("nothing queued", lambda s: s.review_queue == [] or s.review_queue)]


@case("T-73")
def t73():
    w = World().dir("/Users/alice/.cursor")
    chrome_ext(w, "dddd", {"name": "SafePass", "version": "2.0", "host_permissions": ["<all_urls>"]})
    w.plist("/Applications/MarkdownPro.app/Contents/Info.plist",
            {"CFBundleIdentifier": "com.example.markdownpro", "CFBundleExecutable": "MarkdownPro"})
    w.file("/Applications/MarkdownPro.app/Contents/MacOS/MarkdownPro", "plain binary")
    w.file("/Applications/MarkdownPro.app/Contents/Resources/CHANGELOG.md", "improved OpenAI export")
    return w, [only("cursor", flags=["state_only"], band="low"),
               not_queued("SafePass"), not_queued("MarkdownPro")]


@case("T-74")
def t74():
    w = World()
    w.json("/Users/alice/dev/opencode/package.json", {"name": "opencode-ai", "version": "1.0.0"})
    w.file("/Users/alice/dev/opencode/README.md", "opencode source")
    return w, [none_of(catalog_id="opencode", kind="cli_agent")]
