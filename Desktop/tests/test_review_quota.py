import pytest

from adr_desktop.review_quota import admission, claude_quota, codex_quota, combine_claude

NOW = 1_800_000_000


def quota(used=10, weekly=20):
    return codex_quota(
        {
            "rateLimitsByLimitId": {
                "codex": {
                    "primary": {"usedPercent": used, "resetsAt": NOW + 3600, "windowDurationMins": 300},
                    "secondary": {
                        "usedPercent": weekly,
                        "resetsAt": NOW + 86400,
                        "windowDurationMins": 10080,
                    },
                }
            }
        },
        now=NOW,
    )


def decision(snapshot, spare=True, **kwargs):
    return admission(snapshot, provider="codex", reserve=35, spare_only=spare, now=NOW, **kwargs)


def test_every_bucket_and_weekly_window_constrains_spare_capacity():
    assert decision(quota())["allowed"]
    assert not decision(quota(used=5, weekly=99))["allowed"]
    raw = {
        "rateLimitsByLimitId": {
            "fast": {"primary": {"usedPercent": 5, "resetsAt": NOW + 60, "windowDurationMins": 300}},
            "other": {"primary": {"usedPercent": 95, "resetsAt": NOW + 60, "windowDurationMins": 300}},
        }
    }
    assert not decision(codex_quota(raw, now=NOW))["allowed"]


@pytest.mark.parametrize(
    "snapshot",
    [
        None,
        {},
        {"provider": "claude", "windows": []},
        {**quota(), "observed_at": NOW - 301},
        {**quota(), "complete": False},
        {**quota(), "windows": [{**quota()["windows"][0], "resets_at": NOW}]},
    ],
)
def test_missing_partial_stale_cross_provider_or_expired_quota_is_not_spare(snapshot):
    assert not decision(snapshot)["allowed"]


def test_budget_mode_allows_unknown_but_never_a_reported_limit():
    assert decision(None, spare=False)["allowed"]
    assert not decision(quota(weekly=100), spare=False)["allowed"]
    assert not decision({**quota(weekly=100), "observed_at": NOW - 900}, spare=False)["allowed"]


def test_claude_uses_subscription_not_context_window_fields():
    value = claude_quota(
        {
            "context_window": {"used_percentage": 1},
            "rate_limits": {"five_hour": {"used_percentage": 40, "resets_at": NOW + 60}},
        },
        now=NOW,
    )
    assert not value["complete"]
    assert value["windows"][0]["used_percent"] == 40
    complete = claude_quota(
        {
            "rate_limits": {
                "five_hour": {"used_percentage": 40, "resets_at": NOW + 60},
                "seven_day": {"used_percentage": 70, "resets_at": NOW + 86400},
            }
        },
        now=NOW,
    )
    assert complete["complete"]


@pytest.mark.parametrize("bad", [float("nan"), -1, 101, True, "20"])
def test_bad_provider_percentages_are_unknown(bad):
    assert not quota(used=bad)["complete"]
    assert not decision(quota(used=bad))["allowed"]


def test_forecast_needs_samples_and_stays_within_account_reset_window():
    current = {**quota(used=40), "account": "one"}
    history = [
        {**quota(used=used), "observed_at": NOW - age, "account": "one"}
        for age, used in ((1800, 5), (1200, 10), (900, 20))
    ]
    assert not decision(current, history=history)["allowed"]
    assert decision(current, history=[{**x, "account": "another"} for x in history])["allowed"]
    assert decision(current, history=[{**x, "during_review": True} for x in history])["allowed"]
    assert decision(
        {**current, "review_generation": "after"},
        history=[{**x, "review_generation": "before"} for x in history],
    )["allowed"]


def test_claude_repeated_callbacks_do_not_fake_freshness_or_erase_newer_usage():
    original = {
        **claude_quota(
            {
                "rate_limits": {
                    "five_hour": {"used_percentage": 20, "resets_at": NOW + 3600},
                    "seven_day": {"used_percentage": 30, "resets_at": NOW + 86400},
                }
            },
            now=NOW,
        ),
        "account": "one",
    }
    repeated = {**original, "observed_at": NOW + 900}
    assert combine_claude(original, repeated, now=NOW + 900)["observed_at"] == NOW
    partial = {
        **repeated,
        "complete": False,
        "windows": [
            {**original["windows"][0], "used_percent": 25},
        ],
    }
    result = combine_claude(original, partial, now=NOW + 900)
    assert result["complete"] and result["observed_at"] == NOW
    assert result["windows"][0]["used_percent"] == 25
    stale_status = combine_claude(result, repeated, now=NOW + 901)
    assert stale_status["windows"][0]["used_percent"] == 25
    assert stale_status["observed_at"] == NOW
    assert admission(result, provider="claude", reserve=35, spare_only=True, now=NOW + 900)["allowed"]
    assert not admission(result, provider="claude", reserve=35, spare_only=True, now=NOW + 1801)["allowed"]
    switched = combine_claude(result, {**repeated, "account": "another"}, now=NOW + 901)
    assert switched["windows"][0]["used_percent"] == 20
