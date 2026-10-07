"""Synthetic vault-variable UX checks. No real credentials or Keychain writes."""

import json

from playwright.sync_api import expect


def check_environment_vault(page, runtime, screenshots):
    page.locator('a[data-route="/credentials"]').click()
    page.get_by_role("button", name="Add credential", exact=True).click()
    modal = page.get_by_role("dialog", name="Add a credential", exact=True)
    expect(modal.locator('input[type="password"], input[name="secret"], input[name="origin"]')).to_have_count(
        0
    )
    modal.get_by_label("Name", exact=True).fill("Synthetic database")
    expect(modal.get_by_label("Environment variable", exact=True)).to_have_value("SYNTHETIC_DATABASE")
    modal.get_by_label("Environment variable", exact=True).fill("MY_PASSWORD")
    modal.get_by_label("Name", exact=True).fill("Synthetic password")
    expect(modal.get_by_label("Environment variable", exact=True)).to_have_value("MY_PASSWORD")
    page.screenshot(path=str(screenshots / "synthetic-environment-add.png"), full_page=True)
    with page.expect_response(
        lambda response: (
            response.url.endswith("/api/environment-credentials") and response.request.method == "POST"
        )
    ) as created:
        modal.get_by_role("button", name="Continue to secure window", exact=True).click()
    assert created.value.status == 200
    assert created.value.request.post_data_json == {
        "name": "Synthetic password",
        "env_name": "MY_PASSWORD",
    }
    row = page.locator(".environment-row").filter(has_text="Synthetic password")
    expect(row).to_contain_text("$MY_PASSWORD")
    row.get_by_role("button", name="Use in code", exact=True).click()
    examples = page.get_by_role("dialog", name="Use $MY_PASSWORD", exact=True)
    expect(examples).to_contain_text('os.environ["MY_PASSWORD"]')
    expect(examples).to_contain_text("process.env.MY_PASSWORD")
    expect(examples).to_contain_text("adr_run_command")
    examples.get_by_role("button", name="Done", exact=True).click()
    expect(row.get_by_role("button", name="Allow agent use", exact=True)).to_have_count(0)
    expect(row).to_contain_text("Encrypted local copy ready.")
    expect(page.get_by_role("button", name="Refresh storage", exact=True)).to_be_hidden()
    grants = runtime.store.rows("SELECT * FROM grants WHERE kind='agent' AND revoked=0")
    assert len(grants) == 4
    assert not runtime.store.rows("SELECT * FROM grants WHERE kind='execution'")
    for grant in grants:
        assert grant["history_scope"] == "device" and grant["approval_mode"] == "automatic"
        assert grant["project"] == "" and json.loads(grant["credentials"]) == ["*"]
        assert len(runtime.environment_vault.permitted(grant)) == 1
    page.get_by_role("button", name="Add credential", exact=True).click()
    next_entry = page.get_by_role("dialog", name="Add a credential", exact=True)
    expect(next_entry).to_contain_text("Every agent connected through the ADR plugin")
    next_entry.get_by_role("button", name="Close dialog", exact=True).click()
    response = page.request.post(
        f"http://127.0.0.1:{runtime.port}/api/hooks/prompt-check",
        headers={"Authorization": "Bearer " + runtime.hook_token},
        data={"harness": "codex", "prompt": "Use synthetic-browser-password-123"},
    )
    assert response.status == 200 and response.json()["blocked"]
    assert "synthetic-browser-password-123" not in response.text()
    # Hook activity updates automatically; there is no global refresh control.
    expect(page.get_by_role("heading", name="Prompts stopped", exact=True)).to_be_visible(timeout=10000)
    expect(page.locator("#page")).to_contain_text("Use $MY_PASSWORD instead.")
    assert "synthetic-browser-password-123" not in page.locator("#page").inner_text()
    page.screenshot(path=str(screenshots / "synthetic-environment-vault.png"), full_page=True)
    page.set_viewport_size({"width": 390, "height": 900})
    page.emulate_media(color_scheme="dark")
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    page.screenshot(path=str(screenshots / "synthetic-environment-vault-dark.png"), full_page=True)
    page.set_viewport_size({"width": 1440, "height": 1040})
    page.emulate_media(color_scheme="light")

    # An interrupted native save can finish after the original request.
    # Keep the recovery-only storage recheck available without showing it
    # as an everyday action for healthy entries.
    entry = runtime.store.one("SELECT id FROM environment_credentials WHERE env_name='MY_PASSWORD'")
    runtime.store.execute(
        "UPDATE environment_credentials SET state='unconfirmed' WHERE id=?", (entry["id"],)
    )
    runtime.native.local_ids.discard(entry["id"])
    page.reload()
    expect(row).to_contain_text("The save was not confirmed")
    expect(page.get_by_role("button", name="Refresh storage", exact=True)).to_be_visible()
    runtime.native.local_ids.add(entry["id"])
    page.get_by_role("button", name="Refresh storage", exact=True).click()
    recover = row.get_by_role("button", name="Recover saved entry", exact=True)
    expect(recover).to_be_visible()
    recover.click()
    confirmation = page.get_by_role("dialog", name="Recover this saved credential?", exact=True)
    expect(confirmation).to_be_visible()
    assert runtime.store.one(
        "SELECT state FROM environment_credentials WHERE id=?", (entry["id"],)
    )["state"] == "unconfirmed"
    confirmation.get_by_role("button", name="Cancel", exact=True).click()
    recover.click()
    with page.expect_response("**/api/vault/recover") as recovered:
        confirmation.get_by_role("button", name="Recover saved entry", exact=True).click()
    assert recovered.value.status == 200
    assert recovered.value.request.post_data_json == {"ids": [entry["id"]], "confirm": True}
    expect(confirmation).to_have_count(0)
    expect(row).to_contain_text("Encrypted local copy ready.")
    assert runtime.store.one(
        "SELECT state FROM environment_credentials WHERE id=?", (entry["id"],)
    )["state"] == "active"
    expect(page.locator(".connection-summary")).to_have_count(0)
