"""Exercise vault-to-session navigation with synthetic credentials and captures."""

import argparse
import json
import socket
import tempfile
import threading
import time
from contextlib import ExitStack
from pathlib import Path

import uvicorn
from playwright.sync_api import expect, sync_playwright
from qa_support import browser_evidence, isolated_agent_profile
from ui_qa import SyntheticNative, seed

from adr_desktop.api import create_app
from adr_desktop.config import prepare_state_dir, utcnow
from adr_desktop.credential_activity import record_session
from adr_desktop.runtime import Runtime

NATIVE_SESSION = "11111111-2222-4333-8444-555555555555"
TITLE = "Check a release with the saved credential"


def seed_credential_activity(runtime):
    if not runtime.environment_vault.entries():
        runtime.environment_vault.create("Sample token", "SAMPLE_TOKEN")
    grant = runtime.create_grant("Codex · sample activity", kind="agent", confirm_agent=True)
    principal = runtime.store.one("SELECT * FROM grants WHERE id=?", (grant["id"],))

    def execute():
        return runtime.environment_vault.execute(principal, "pwd", str(Path.home()))

    def capture(receipt, native, title):
        payload = {
            "source": "codex", "session_id": f"codex_{native}", "username": "synthetic",
            "timestamp": utcnow(), "project_path": "/workspace/sample", "model": "example-model",
            "chat_history": [
                {"role": "user", "content": title, "tools": []},
                {"role": "assistant", "content": "[Assistant used tools]", "tools": [{
                    "tool_name": "mcp__adr__adr_run_command", "arguments": {"command": "pwd"},
                    "result": json.dumps(receipt),
                }]},
                {"role": "assistant", "content": "The sample request completed. No value was returned.",
                 "tools": []},
            ],
        }
        runtime.store.ingest(payload)
        return runtime.store._identity("codex", "synthetic", payload["session_id"])

    linked = execute()
    identifier = capture(linked, NATIVE_SESSION, TITLE)
    record_session(runtime.store, linked["run_id"], grant["id"], "codex", NATIVE_SESSION)
    pending = execute()
    record_session(
        runtime.store, pending["run_id"], grant["id"], "codex", "66666666-7777-4888-8999-000000000000",
    )
    execute()  # An older/unattributed run must not be assigned the newest session.
    ambiguous = execute()
    capture(ambiguous, "sample-copy-one", "An unattributed copied result")
    capture(ambiguous, "sample-copy-two", "Another unattributed copied result")
    return identifier


def check_navigation(page, base, identifier, screenshots):
    page.get_by_role("heading", name="Credential vault", exact=True).wait_for()
    activity = page.locator(".card").filter(
        has=page.get_by_role("heading", name="Recent credential use", exact=True),
    )
    expect(activity.locator(".credential-use-row")).to_have_count(4)
    link = activity.get_by_role("link", name=f"Open session codex_{NATIVE_SESSION}: {TITLE}", exact=True)
    expect(link).to_have_attribute("href", f"/sessions/{identifier}")
    expect(activity).to_contain_text("Session log not captured yet")
    expect(activity).to_contain_text("Session not recorded")
    expect(activity).to_contain_text("Session could not be uniquely identified")
    expect(activity.locator("a")).to_have_count(1)
    link.scroll_into_view_if_needed()
    page.screenshot(path=str(screenshots / "credential-session-desktop.png"), full_page=True)
    link.focus()
    expect(link).to_be_focused()
    link.press("Enter")
    page.get_by_role("heading", name=TITLE, exact=True).wait_for()
    assert page.url == f"{base}/sessions/{identifier}"
    expect(page.locator(".conversation")).to_contain_text(TITLE)
    assert page.evaluate("window.scrollY") < 10
    page.screenshot(path=str(screenshots / "credential-session-transcript.png"), full_page=True)
    page.go_back()
    page.get_by_role("heading", name="Credential vault", exact=True).wait_for()
    expect(activity.locator("a")).to_have_count(1)
    for width, scheme in ((390, "light"), (390, "dark"), (1440, "dark")):
        page.set_viewport_size({"width": width, "height": 1000})
        page.emulate_media(color_scheme=scheme)
        link.scroll_into_view_if_needed()
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        assert link.bounding_box()["width"] <= width
        page.screenshot(path=str(screenshots / f"credential-session-{width}-{scheme}.png"), full_page=True)
    # A direct/reloaded URL uses the internal ADR ID, not the native harness ID.
    page.goto(f"{base}/sessions/{identifier}")
    page.get_by_role("heading", name=TITLE, exact=True).wait_for()
    page.reload()
    page.get_by_role("heading", name=TITLE, exact=True).wait_for()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    screenshots = args.output or Path(tempfile.mkdtemp(prefix="adr-credential-activity-images-"))
    screenshots.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="adr-credential-activity-") as folder:
        home = Path(folder) / "home"
        home.mkdir()

        with isolated_agent_profile(home):
            runtime = Runtime(
                prepare_state_dir(Path(folder) / "state"), SyntheticNative(), start_collectors=False,
            )
            seed(runtime)
            identifier = seed_credential_activity(runtime)
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(64)
            runtime.port = listener.getsockname()[1]
            base = f"http://127.0.0.1:{runtime.port}"
            server = uvicorn.Server(uvicorn.Config(
                create_app(runtime), log_level="warning", access_log=False, proxy_headers=False,
            ))
            worker = threading.Thread(target=lambda: server.run(sockets=[listener]), daemon=True)
            worker.start()
            for _ in range(100):
                if server.started:
                    break
                time.sleep(0.02)
            errors = []
            try:
                with sync_playwright() as playwright, ExitStack() as evidence:
                    browser = playwright.chromium.launch()
                    context = browser.new_context(viewport={"width": 1440, "height": 1100})
                    evidence.enter_context(browser_evidence(context, screenshots))
                    page = context.new_page()
                    page.on("pageerror", lambda error: errors.append(str(error)))
                    page.goto(f"{base}/credentials#ticket={runtime.new_ticket()}")
                    check_navigation(page, base, identifier, screenshots)
                assert not errors, errors
                print(json.dumps({"credential_activity_ui": "passed", "screenshots": str(screenshots)}))
            finally:
                server.should_exit = True
                worker.join(timeout=5)
                runtime.close()
                listener.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
