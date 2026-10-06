"""Provider observations and conservative admission; tokens are not quota percent."""

import math
import time

MAX_AGE = 300
# Claude has no equivalent read-only quota RPC here. Its last full CLI
# observation may precede the idle interval; explicitly bound that estimate.
CLAUDE_MAX_AGE = 1800


def number(value, low=0, high=100):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and low <= value <= high
    )


def window(name, used, resets, minutes, now):
    if not (number(used) and number(resets, now + 1, now + 32 * 86400) and number(minutes, 1, 32 * 1440)):
        return None
    return {
        "name": name,
        "used_percent": float(used),
        "resets_at": float(resets),
        "window_minutes": float(minutes),
    }


def codex_quota(payload, *, now=None):
    now = time.time() if now is None else now
    buckets = payload.get("rateLimitsByLimitId")
    malformed_buckets = buckets is not None and not isinstance(buckets, dict)
    if not isinstance(buckets, dict) or not buckets:
        single = payload.get("rateLimits")
        buckets = {"codex": single} if isinstance(single, dict) else {}
    windows, reached, incomplete = [], False, malformed_buckets
    for key, bucket in list(buckets.items())[:32]:
        if not isinstance(key, str) or not isinstance(bucket, dict):
            incomplete = True
            continue
        reached |= bool(bucket.get("rateLimitReachedType"))
        found = False
        for kind in ("primary", "secondary"):
            item = bucket.get(kind)
            if item is None:
                continue
            normalized = window(
                f"{key[:80]} / {kind}",
                item.get("usedPercent") if isinstance(item, dict) else None,
                item.get("resetsAt") if isinstance(item, dict) else None,
                item.get("windowDurationMins") if isinstance(item, dict) else None,
                now,
            )
            if normalized:
                windows.append(normalized)
                found = True
            else:
                incomplete = True
        incomplete |= not found
    return {
        "provider": "codex",
        "observed_at": now,
        "windows": windows,
        "complete": bool(windows) and not incomplete and len(buckets) <= 32,
        "limit_reached": reached,
        "source": "Codex app-server",
    }


def claude_quota(payload, *, now=None):
    """Full status-line observation, not context-window utilization or token counts."""
    now = time.time() if now is None else now
    limits = payload.get("rate_limits", {})
    windows = []
    for name, minutes in (("five_hour", 300), ("seven_day", 10080)):
        value = limits.get(name) if isinstance(limits, dict) else None
        if isinstance(value, dict):
            item = window(name, value.get("used_percentage"), value.get("resets_at"), minutes, now)
            if item:
                windows.append(item)
    return {
        "provider": "claude",
        "observed_at": now,
        "windows": windows,
        "complete": len(windows) == 2,
        "limit_reached": any(w["used_percent"] >= 100 for w in windows),
        "source": "Claude Code status line",
    }


def claude_rate_event(info, *, now=None):
    """A CLI rate-limit event can report one window, not necessarily the whole account."""
    now = time.time() if now is None else now
    if not isinstance(info, dict):
        return None
    kind = info.get("rateLimitType", info.get("rate_limit_type"))
    duration = {"five_hour": 300, "seven_day": 10080}.get(kind)
    utilization = info.get("utilization")
    item = (
        window(
            str(kind),
            utilization * 100 if number(utilization, 0, 1) else None,
            info.get("resetsAt", info.get("resets_at")),
            duration,
            now,
        )
        if duration
        else None
    )
    resets = info.get("resetsAt", info.get("resets_at"))
    return {
        "provider": "claude",
        "observed_at": now,
        "windows": [item] if item else [],
        "complete": False,
        "limit_reached": info.get("status") == "rejected",
        "retry_after": resets if number(resets, now + 1, now + 32 * 86400) else now + 900,
        "source": "Claude Code review process",
    }


def combine_claude(previous, incoming, *, now=None):
    """Do not make repeated UI callbacks fresh or lose newer per-window usage."""
    now = time.time() if now is None else now
    if (
        not isinstance(previous, dict)
        or previous.get("provider") != "claude"
        or previous.get("account") != incoming.get("account")
    ):
        return incoming
    old = {w["name"]: w for w in previous.get("windows", [])}
    new = {w["name"]: w for w in incoming.get("windows", [])}
    full = incoming.get("complete") is True
    can_carry = previous.get("complete") is True and number(
        previous.get("observed_at"),
        now - CLAUDE_MAX_AGE,
        now + 5,
    )
    if not full and not can_carry:
        return incoming
    merged = {} if full else dict(old)
    for name, item in new.items():
        prior = old.get(name)
        if prior and prior["resets_at"] == item["resets_at"]:
            item = {**item, "used_percent": max(prior["used_percent"], item["used_percent"])}
        merged[name] = item
    windows = [merged[name] for name in ("five_hour", "seven_day") if name in merged]
    unchanged = {w["name"]: w for w in windows} == old
    stamp = incoming["observed_at"]
    if not full or unchanged:
        stamp = min(stamp, previous["observed_at"])
    limited = incoming.get("limit_reached") or any(w["used_percent"] >= 100 for w in windows)
    retry = incoming.get("retry_after")
    if (
        previous.get("limit_reached")
        and unchanged
        and number(
            previous.get("retry_after"),
            now + 1,
            now + 32 * 86400,
        )
    ):
        limited = True
        retry = max(retry or 0, previous["retry_after"])
    return {
        **incoming,
        "windows": windows,
        "complete": len(windows) == 2,
        "observed_at": stamp,
        "limit_reached": bool(limited),
        "retry_after": retry,
        "source": "Claude Code observations",
    }


def admission(snapshot, *, provider, reserve, spare_only, history=(), now=None):
    """No observation, expired reset, or partial view may claim spare capacity."""
    now = time.time() if now is None else now
    unknown = {
        "allowed": not spare_only,
        "reason": "Quota unavailable; using your review budget",
        "forecast": None,
    }
    if not isinstance(snapshot, dict) or snapshot.get("provider") != provider:
        return unknown
    # A known exhausted window is not made usable merely by aging past our
    # freshness threshold. Wait for reset or a new provider observation.
    raw_windows = snapshot.get("windows")
    exhausted = [
        w["resets_at"]
        for w in (raw_windows if isinstance(raw_windows, list) else [])
        if isinstance(w, dict)
        and w.get("used_percent") == 100
        and number(w.get("resets_at"), now + 1, now + 32 * 86400)
    ]
    retry = snapshot.get("retry_after")
    if exhausted or (snapshot.get("limit_reached") and number(retry, now + 1, now + 32 * 86400)):
        return {"allowed": False, "reason": "Waiting for the reported usage limit to reset", "forecast": None}
    stamp = snapshot.get("observed_at")
    max_age = CLAUDE_MAX_AGE if provider == "claude" else MAX_AGE
    if not number(stamp, now - max_age, now + 5):
        return {**unknown, "reason": "Quota needs a fresh observation"}
    windows = snapshot.get("windows", [])
    if not isinstance(windows, list) or any(
        not isinstance(w, dict)
        or not window(
            w.get("name", ""),
            w.get("used_percent"),
            w.get("resets_at"),
            w.get("window_minutes"),
            now,
        )
        for w in windows
    ):
        return unknown
    if snapshot.get("limit_reached") or any(w["used_percent"] >= 100 for w in windows):
        return {"allowed": False, "reason": "The agent reported a usage limit", "forecast": None}
    if not spare_only:
        return {"allowed": True, "reason": "Using your review budget", "forecast": None}
    if snapshot.get("complete") is not True or not windows:
        return {**unknown, "reason": "Waiting for all subscription usage windows"}
    forecast = []
    for current in windows:
        # Learn only from observations made outside review jobs for the same
        # account and reset window. A changed/missing identity has no baseline.
        samples = []
        identity = snapshot.get("account")
        for prior in history:
            if (
                not identity
                or prior.get("account") != identity
                or prior.get("during_review")
                or prior.get("review_generation") != snapshot.get("review_generation")
                or not number(prior.get("observed_at"), now - 3600, stamp - 1)
            ):
                continue
            for previous in prior.get("windows", []):
                if (
                    previous.get("name") == current["name"]
                    and previous.get("resets_at") == current["resets_at"]
                    and number(previous.get("used_percent"), 0, current["used_percent"])
                ):
                    samples.append((prior["observed_at"], previous["used_percent"]))
        samples.sort()
        predicted = None
        if len(samples) >= 3 and stamp - samples[0][0] >= 900:
            # Upper recent observed consumption rate, not a claim about intent.
            rates = [(current["used_percent"] - used) / (stamp - observed) for observed, used in samples]
            predicted = min(100.0, max(rates) * (current["resets_at"] - now))
        remaining = 100 - current["used_percent"]
        headroom = remaining - reserve - (predicted or 0) - 5
        forecast.append(
            {
                "name": current["name"],
                "remaining_percent": remaining,
                "predicted_use_percent": predicted,
                "headroom_percent": headroom,
            }
        )
    allowed = all(item["headroom_percent"] > 0 for item in forecast)
    return {
        "allowed": allowed,
        "reason": "Idle capacity available" if allowed else "Keeping capacity for you",
        "forecast": forecast,
    }
