"""Synthetic inventory browser checks; never read the user's inventory."""

from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import expect


def check_inventory(page, runtime, screenshots):
    original = runtime.store.settings().get("inventory_snapshot")
    assets = [
        {
            "name": f"Synthetic skill {index:03}",
            "kind": "skill",
            "liveness": "declared_only",
            "install_path": f"/workspace/synthetic/.claude/skills/example-{index}/SKILL.md",
        }
        for index in range(207)
    ]
    assets += [
        {
            "name": "Codex / ChatGPT",
            "catalog_id": "codex-desktop",
            "kind": "app",
            "liveness": "installed",
            "install_path": "/Applications/Synthetic Codex.app",
        },
        {
            "name": "Claude Code",
            "catalog_id": "claude-code",
            "kind": "cli_agent",
            "liveness": "installed",
            "install_path": "/workspace/synthetic/very-long-application-location/"
            "release-with-a-deliberately-long-unbroken-folder-name-for-responsive-layout-tests/bin/claude",
            "version": "1.2.3-synthetic-release",
        },
        {
            "name": "PostToolUse hook 2",
            "kind": "hook",
            "liveness": "declared_only",
            "install_path": "/workspace/synthetic/.claude/settings.json",
        },
    ]
    snapshot = {
        "assets": assets,
        "review_queue": [
            {
                "suspected_name": "Codex CLI",
                "suspected_catalog_id": "codex-cli",
                "candidate_kind": "binary",
                "path": "/workspace/synthetic/bin/codex",
            }
        ],
        "coverage": {
            "denied": [
                {"path": f"/workspace/synthetic/restricted/{index}", "reason": "Permission denied"}
                for index in range(22)
            ] + [
                {"path": "/workspace/synthetic/Documents", "reason": "personal_path"},
            ],
            "boundaries_hit": [
                {
                    "path": "/workspace/synthetic/projects",
                    "boundary": "budget_exhausted",
                    "detail": "Entry cap reached",
                },
                {"path": "/workspace/synthetic/node_modules", "boundary": "scope_excluded"},
            ],
            "unavailable": [{"provider": "dns_cache", "reason": "Not exposed on this platform"}],
            "truncated": [{"path": "/workspace/synthetic/large.json", "kept": 100, "true_count": 200}],
            "probes": [{
                "name": "extractor", "status": "degraded", "detail": "Synthetic manifest could not be parsed",
            }],
        },
    }
    runtime.store.setting("inventory_snapshot", snapshot)
    try:
        page.locator('a[data-route="/inventory"]').click()
        page.get_by_role("heading", name="AI inventory", exact=True).wait_for()
        expect(page.locator(".inventory-table tbody tr")).to_have_count(25)
        expect(page.get_by_text("Some locations could not be checked", exact=True)).to_have_count(0)
        page.get_by_role("button", name="Next inventory page", exact=True).click()
        expect(page.locator(".inventory-table tbody tr").first).to_contain_text("Synthetic skill 025")
        assert parse_qs(urlsplit(page.url).query)["page"] == ["1"]

        search = page.get_by_role("searchbox", name="Search inventory", exact=True)
        search.fill("Synthetic skill 206")
        expect(page.locator(".inventory-table tbody tr")).to_have_count(1)
        expect(page.locator(".inventory-table tbody tr")).to_contain_text("Synthetic skill 206")
        assert "page" not in parse_qs(urlsplit(page.url).query)
        page.reload()
        expect(page.get_by_role("searchbox", name="Search inventory", exact=True)).to_have_value(
            "Synthetic skill 206"
        )
        expect(page.locator(".inventory-table tbody tr")).to_have_count(1)
        search.fill("")

        kinds = page.get_by_role("combobox", name="Inventory type", exact=True)
        kinds.select_option("applications")
        expect(page.locator(".inventory-table tbody tr")).to_have_count(3)
        expect(page.locator(".inventory-table").get_by_text("Desktop app", exact=True)).to_have_count(1)
        expect(page.locator(".inventory-table").get_by_text("CLI agent", exact=True)).to_have_count(1)
        unverified = page.get_by_role("row").filter(has=page.get_by_text("Unverified executable", exact=True))
        expect(unverified.get_by_text("Unverified", exact=True)).to_have_count(1)
        expect(unverified.get_by_text("Installed", exact=True)).to_have_count(0)
        expect(page.locator(".inventory-mark")).to_have_count(3)
        assert page.locator(".inventory-mark").evaluate_all(
            "nodes => nodes.every(node => node.getAttribute('aria-hidden') === 'true')"
        )
        input_box = search.bounding_box()
        glyph_box = page.locator(".inventory-search > .icon").bounding_box()
        padding = search.evaluate("node => parseFloat(getComputedStyle(node).paddingLeft)")
        assert input_box["x"] + padding >= glyph_box["x"] + glyph_box["width"] + 6

        page.locator(".inventory-coverage > summary").click()
        restricted = page.locator(".coverage-location").filter(
            has=page.locator("summary").filter(has_text="22 paths")
        )
        restricted.locator(":scope > summary").click()
        expect(restricted.locator(".inventory-coverage-row")).to_have_count(20)
        restricted.get_by_role("button", name="Show more paths (2 remaining)", exact=True).click()
        expect(restricted.locator(".inventory-coverage-row")).to_have_count(22)
        expect(page.locator(".inventory-coverage-group > summary").filter(
            has_text="Skipped or unavailable locations"
        )).to_have_count(1)
        expect(page.locator(".inventory-coverage-group > summary").filter(
            has_text="Scan limits (1)"
        )).to_have_count(1)
        page.locator(".inventory-coverage > summary").click()
        page.screenshot(path=str(screenshots / "synthetic-inventory-improved.png"), full_page=True)

        kinds.select_option("hook")
        expect(page.locator(".inventory-table tbody tr")).to_have_count(1)
        expect(page.locator(".inventory-table")).to_contain_text("Claude · After tool use")
        expect(page.locator(".inventory-table")).to_contain_text("/workspace/synthetic/.claude/settings.json")
        expect(page.get_by_text("PostToolUse hook 2", exact=True)).to_have_count(0)
        kinds.select_option("applications")

        for width in (640, 390):
            page.set_viewport_size({"width": width, "height": 1000})
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            assert page.locator(".inventory-table").evaluate("node => node.scrollWidth <= node.clientWidth")
            for status in ("Installed", "Unverified"):
                badges = page.locator(".inventory-table").get_by_text(status, exact=True)
                for badge in badges.all():
                    expect(badge).to_be_visible()
                    assert badge.evaluate(
                        "node => { const box = node.getBoundingClientRect(); "
                        "return box.left >= 0 && box.right <= innerWidth && "
                        "node.scrollWidth <= node.clientWidth; }"
                    )
            version = page.locator(".inventory-table").get_by_text("1.2.3-synthetic-release", exact=True)
            expect(version).to_be_visible()
            assert version.evaluate(
                "node => { const box = node.getBoundingClientRect(); return box.right <= innerWidth; }"
            )
            path = page.locator(".inventory-item .path").filter(has_text="very-long-application-location")
            expect(path).to_be_visible()
            assert path.evaluate("node => node.scrollWidth <= node.clientWidth")
            page.emulate_media(color_scheme="light")
            page.screenshot(path=str(screenshots / f"synthetic-inventory-narrow-{width}.png"), full_page=True)
            page.emulate_media(color_scheme="dark")
            page.screenshot(path=str(screenshots / f"synthetic-inventory-dark-{width}.png"), full_page=True)
        page.emulate_media(color_scheme="light")
        page.set_viewport_size({"width": 1440, "height": 1040})

        search.fill("unmatched synthetic query")
        page.get_by_role("heading", name="No matching items", exact=True).wait_for()
        page.get_by_role("button", name="Clear filters", exact=True).click()
        expect(page.locator(".inventory-table tbody tr")).to_have_count(25)
        expect(search).to_have_value("")
        expect(kinds).to_have_value("")
    finally:
        runtime.store.setting("inventory_snapshot", original)
