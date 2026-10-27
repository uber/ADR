"""Session reviews in Desktop: the owner's consent and settings, and what detection's review
coordinator gets from Desktop (the credential check, the activity log and device-idle time)."""

import copy
import uuid

from .config import command_prefix
from .detection.review.coordinator import ReviewCoordinator
from .detection.review.quota import claude_quota, number
from .detection.review.resources import config
from .detection.review.runners import LocalReviewDriver
from .detection.review.usage import connection_status

DEFAULTS = config("defaults")


def validate_preferences(value):
    if set(value) != set(DEFAULTS) | {"revision"}:
        raise ValueError("Invalid review settings")
    for key in ("background", "allow_paid", "consented"):
        if type(value[key]) is not bool:
            raise ValueError("Choose valid review preferences")
    for key, low, high in (
        ("max_tokens", 1000, 100000),
        ("daily_tokens", 1000, 1000000),
        ("daily_jobs", 1, 100),
        ("max_seconds", 30, 600),
        ("reserve_percent", 10, 90),
        ("idle_minutes", 5, 120),
        ("reset_within_hours", 1, 24),
    ):
        if type(value[key]) is not int or not low <= value[key] <= high:
            raise ValueError(f"Choose a valid {key.replace('_', ' ')}")
    if value["max_tokens"] > value["daily_tokens"]:
        raise ValueError("The per-review token limit cannot exceed the 24-hour budget")
    if value["provider"] not in ("claude", "codex") or value["mode"] not in ("budget", "spare"):
        raise ValueError("Choose a supported agent and scheduling mode")
    if (
        not isinstance(value["model"], str)
        or len(value["model"]) > 100
        or any(ord(c) < 32 for c in value["model"])
    ):
        raise ValueError("Choose a valid model name")
    for key in ("max_cost_usd", "daily_cost_usd"):
        if not number(value[key], 0.01, 100):
            raise ValueError("Choose a cost budget between $0.01 and $100")
    if value["max_cost_usd"] > value["daily_cost_usd"]:
        raise ValueError("The per-review cost limit cannot exceed the 24-hour budget")
    if (
        not isinstance(value["projects"], list)
        or len(value["projects"]) > 30
        or any(not isinstance(p, str) or not p or len(p) > 8192 for p in value["projects"])
        or len(set(value["projects"])) != len(value["projects"])
    ):
        raise ValueError("Choose captured projects to review")
    if value["background"] and (not value["consented"] or not value["projects"]):
        raise ValueError("Approve sharing and choose projects before enabling idle reviews")


class NativeIdle:
    """Fills detection's DeviceIdle port from the menu-bar app."""

    def __init__(self, native):
        self.native = native

    def idle_seconds(self):
        return self.native.call("review_idle_status", timeout=2).get("idle_seconds")


class SecurityReviews(ReviewCoordinator):
    def __init__(self, runtime, *, start_worker=False, driver=None):
        self.runtime = runtime
        if "review_preferences" not in runtime.store.settings():
            runtime.store.setting(
                "review_preferences", {**copy.deepcopy(DEFAULTS), "revision": uuid.uuid4().hex}
            )
        super().__init__(
            runtime.store,
            runtime.store,
            NativeIdle(runtime.native),
            driver or LocalReviewDriver(launcher=command_prefix()),
            start_worker=start_worker,
        )

    def preferences(self):
        value = self.store.settings()["review_preferences"]
        validate_preferences(value)
        return value

    def change_settings(self, changes, *, expected_revision, confirm_data_share=False):
        with self.lock:
            current = self.preferences()
            if current["revision"] != expected_revision:
                raise ValueError("Review settings changed. Refresh before saving.")
            if set(changes) - (set(DEFAULTS) - {"consented"}):
                raise ValueError("Unknown review settings")
            if not current["consented"] or any(
                key in changes and changes[key] != current[key]
                for key in ("provider", "model", "projects", "allow_paid")
            ):
                if not confirm_data_share:
                    raise ValueError("Confirm sending selected session evidence through this agent")
            updated = {
                **current,
                **changes,
                "consented": current["consented"] or confirm_data_share,
                "revision": uuid.uuid4().hex,
            }
            validate_preferences(updated)
            self.store.setting("review_preferences", updated)
            # Permission/scope changes take effect for the active worker too.
            if self.active:
                self.cancel.set()
            self.last_probe = 0
        self.store.audit("review_settings_changed", "Security review settings updated")
        return self.status()

    def withheld(self, text, provider):
        return bool(self.runtime.environment_vault.check_prompt(text, provider, record=False).get("blocked"))

    def audit(self, kind, summary, details=None):
        self.store.audit(kind, summary, details)

    def status(self):
        return {**super().status(), "claude_usage_connected": connection_status(self.runtime.state_dir)}


def receive_claude_usage(runtime, value):
    observation = claude_quota(value)
    runtime.reviews.record_quota("claude", observation)
    return {"recorded": True}
