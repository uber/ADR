"""Session reviews: evidence, report schema and validation, the job ledger, budgets and quota,
and idle-time scheduling. Desktop keeps the owner's consent and settings."""

import json
import math
import threading
import time
import uuid

from ...storage.clock import utcnow
from ...storage.files import canonical
from ..ports import DeviceIdle, SessionSource
from .contracts import ERRORS, ReviewError
from .quota import admission, combine_claude, number
from .resources import config, prompt, statements

VERSION = "session-review-v1"
SQL = statements()
REPORT_SCHEMA = config("report_schema")
FINDING = REPORT_SCHEMA["properties"]["findings"]["items"]["properties"]
PROMPT = prompt("review")


class ReviewInputError(ValueError):
    """No evidence was dispatched; automatic work may move to another snapshot."""


def evidence_for(session, max_tokens):
    history = session["payload"].get("chat_history", [])
    if not isinstance(history, list) or not history:
        raise ReviewInputError("This session has no captured messages to review")
    budget = min(28000, max(2000, max_tokens * 2))
    messages, used = [], 0
    for index, message in enumerate(history):
        if not isinstance(message, dict):
            continue
        item = {
            "message_index": index,
            "role": message.get("role", "unknown"),
            "content": message.get("content", ""),
            "tools": message.get("tools", []),
        }
        size = len(canonical(item).encode())
        if used + size > budget or len(messages) >= 200:
            continue
        used += size
        messages.append(item)
    if not messages:
        raise ReviewInputError(
            "The captured messages exceed this review's input budget; increase its token limit"
        )
    coverage = {
        "total_messages": len(history),
        "included_messages": len(messages),
        "message_indexes": [m["message_index"] for m in messages],
        "partial": len(messages) != len(history) or bool(session.get("partial")),
        "capture_partial": bool(session.get("partial")),
        "input_bytes": used,
    }
    text = PROMPT + "\n" + canonical({"coverage": coverage, "messages": messages})
    return text, coverage, {m["message_index"]: canonical(m) for m in messages}


def validate_report(report, evidence):
    if not isinstance(report, dict) or set(report) != {"summary", "findings"}:
        raise ReviewError("invalid_report")
    if not isinstance(report["summary"], str) or not 1 <= len(report["summary"]) <= 1200:
        raise ReviewError("invalid_report")
    findings = report["findings"]
    if not isinstance(findings, list) or len(findings) > 20:
        raise ReviewError("invalid_report")
    expected = set(REPORT_SCHEMA["properties"]["findings"]["items"]["required"])
    for item in findings:
        if not isinstance(item, dict) or set(item) != expected:
            raise ReviewError("invalid_report")
        index = item["message_index"]
        if type(index) is not int or index not in evidence:
            raise ReviewError("invalid_report")
        for key, bound in (("title", 160), ("evidence", 500), ("explanation", 1500), ("suggestion", 1000)):
            if not isinstance(item[key], str) or not 1 <= len(item[key]) <= bound:
                raise ReviewError("invalid_report")
        if (
            any(item[key] not in FINDING[key]["enum"] for key in ("category", "severity", "confidence"))
            or item["evidence"] not in evidence[index]
        ):
            raise ReviewError("invalid_report")
    return report


class ReviewCoordinator:
    """Runs one review at a time on captured sessions, within the owner's budgets and quota.

    ``store`` is the profile database and ``driver`` runs the review CLI (runners.LocalReviewDriver).
    Desktop subclasses this class to supply the owner's settings, the credential check and the
    activity log.
    """

    def __init__(self, store, sessions: SessionSource, device: DeviceIdle, driver, *, start_worker=False):
        self.store = store
        self.sessions = sessions
        self.device = device
        self.driver = driver
        self.lock = threading.RLock()
        self.probe_lock = threading.Lock()
        self.stop = threading.Event()
        self.cancel = threading.Event()
        self.active = None
        self.worker = None
        self.poller = None
        self.scheduler_reason = "Idle reviews are off"
        self.idle_reason = "Waiting for idle time"
        self.last_probe = 0
        self.accounts = {}
        with self.store.transaction() as db:
            db.executescript(SQL["schema"])
            db.execute(SQL["job_interrupt_unfinished"], (utcnow(),))
        if start_worker:
            self.poller = threading.Thread(target=self._loop, daemon=True, name="adr-idle-reviews")
            self.poller.start()

    def preferences(self):
        """The owner's current review settings, validated, with the revision they were saved under."""
        raise NotImplementedError

    def withheld(self, text, provider):
        """Whether text holds a credential or could not be checked; such text is never sent or kept."""
        raise NotImplementedError

    def audit(self, kind, summary, details=None):
        """Record an event in the owner's activity log."""
        raise NotImplementedError

    def ledger(self, now=None):
        cutoff = (time.time() if now is None else now) - 86400
        return self.store.one(SQL["job_ledger"], (cutoff,))

    def quota(self, provider):
        row = self.store.one(SQL["quota_get"], (provider,))
        return json.loads(row["observation"]) if row else None

    def record_quota(self, provider, observation, *, account=None, during_review=False):
        with self.lock:
            return self._record_quota(provider, observation, account=account, during_review=during_review)

    def _record_quota(self, provider, observation, *, account=None, during_review=False):
        if not isinstance(observation, dict) or observation.get("provider") != provider:
            return
        latest = self.store.one(SQL["job_latest_charged"], (provider,))
        observation = {
            **observation,
            "account": account or self.accounts.get(provider, ""),
            "during_review": during_review or self.active is not None,
            "review_generation": latest["id"] if latest else "",
        }
        if provider == "claude":
            observation = combine_claude(self.quota(provider), observation)
        # Only normalized provider fields enter this table; no raw CLI output.
        with self.store.transaction() as db:
            db.execute(SQL["quota_put"], (provider, canonical(observation)))
            db.execute(
                SQL["quota_history_add"], (provider, observation["observed_at"], canonical(observation))
            )
            db.execute(SQL["quota_history_prune"])

    def refresh_quota(self, provider=None):
        with self.probe_lock:
            return self._refresh_quota(provider)

    def _refresh_quota(self, provider=None):
        provider = provider or self.preferences()["provider"]
        if provider not in ("claude", "codex"):
            raise ValueError("Unknown agent")
        result = self.driver.probe(provider, self.stop)
        old = self.accounts.get(provider)
        self.accounts[provider] = result["account"]
        existing = self.quota(provider)
        if (old and old != result["account"]) or (
            existing and existing.get("account") and existing["account"] != result["account"]
        ):
            self.store.execute(SQL["quota_delete"], (provider,))
        if result.get("quota"):
            self.record_quota(provider, result["quota"], account=result["account"])
        return result

    def quota_decision(self, settings):
        provider = settings["provider"]
        rows = self.store.rows(SQL["quota_history"], (provider,))
        history = [json.loads(row["observation"]) for row in rows]
        result = admission(
            self.quota(provider),
            provider=provider,
            reserve=settings["reserve_percent"],
            spare_only=settings["mode"] == "spare",
            history=history,
        )
        if result["allowed"] and settings["mode"] == "spare":
            windows = (self.quota(provider) or {}).get("windows", [])
            if (
                windows
                and min(w["resets_at"] for w in windows) - time.time() > settings["reset_within_hours"] * 3600
            ):
                result = {**result, "allowed": False, "reason": "Waiting until closer to the next reset"}
        return result

    def status(self):
        with self.lock:
            settings = self.preferences()
            jobs = self.store.rows(SQL["job_recent"])
            sessions = self.sessions.describe_sessions(sorted({job["session_id"] for job in jobs}))
            for job in jobs:
                session = sessions.get(job["session_id"], {})
                job["session_title"] = session.get("title")
                job["session_source"] = session.get("source")
                job["coverage"] = json.loads(job["coverage"])
                job["report"] = json.loads(job["report"]) if job["report"] else None
                job["stale"] = session.get("digest") != job["digest"]
            return {
                "settings": settings,
                "available": self.driver.available(),
                "jobs": jobs,
                "budget": self.ledger(),
                "quota": self.quota(settings["provider"]),
                "admission": self.quota_decision(settings),
                "active": self.active,
                "scheduler": self.scheduler_reason,
                "detector": VERSION,
            }

    def summary(self):
        return {
            "active": self.active,
            "scheduler": self.scheduler_reason,
            "latest": self.store.one(SQL["job_latest"]),
        }

    def start(self, session_id, request_id, *, automatic=False):
        try:
            uuid.UUID(request_id)
        except (ValueError, AttributeError, TypeError):
            raise ValueError("Provide a valid review request ID") from None
        with self.lock:
            existing = self.store.one(SQL["job_by_request"], (request_id,))
            if existing:
                if existing["session_id"] != session_id:
                    raise ValueError("That request already refers to another session; open a new review")
                return {"id": existing["id"], "state": existing["state"]}
            if self.stop.is_set() or self.active:
                raise ValueError("A review is already running or ADR is shutting down")
            settings = self.preferences()
            if not settings["consented"]:
                raise ValueError("Set up Security reviews and approve evidence sharing first")
            session = self.sessions.session(session_id)
            if not session:
                raise ValueError("Captured session not found")
            if automatic and (not settings["background"] or session["project"] not in settings["projects"]):
                raise ValueError("This project is not enabled for idle reviews")
            prompt, coverage, evidence = evidence_for(session, settings["max_tokens"])
            if self.withheld(prompt, settings["provider"]):
                raise ReviewInputError(
                    "This review contains credentials or could not be checked; no evidence was sent"
                )
            used = self.ledger()
            cost = math.ceil(settings["max_cost_usd"] * 1e6) if settings["provider"] == "claude" else 0
            if used["tokens"] + settings["max_tokens"] > settings["daily_tokens"]:
                raise ValueError("Not enough review tokens remain in the rolling 24-hour budget")
            if used["jobs"] >= settings["daily_jobs"]:
                raise ValueError("The 24-hour review count limit has been reached")
            if (
                settings["provider"] == "claude"
                and used["cost_usd"] + cost / 1e6 > settings["daily_cost_usd"] + 1e-9
            ):
                raise ValueError("Not enough Claude review cost budget remains")
            identifier = uuid.uuid4().hex
            self.store.execute(
                SQL["job_insert_queued"],
                (
                    identifier,
                    request_id,
                    session_id,
                    session["digest"],
                    VERSION,
                    settings["provider"],
                    settings["model"],
                    utcnow(),
                    time.time(),
                    int(automatic),
                    settings["max_tokens"],
                    cost,
                    canonical(coverage),
                ),
            )
            self.active = identifier
            self.cancel = threading.Event()
            self.worker = threading.Thread(
                target=self._run,
                args=(identifier, prompt, evidence, settings, self.cancel, automatic),
                daemon=True,
                name="adr-security-review",
            )
            self.worker.start()
            return {"id": identifier, "state": "queued"}

    def _run(self, identifier, prompt, evidence, settings, cancel, automatic):
        dispatched = False
        tokens = None
        cost = None
        account = ""

        def progress(value):
            nonlocal tokens, cost
            if number(value.get("tokens"), 0, 10**10):
                tokens = max(tokens or 0, int(value["tokens"]))
                self.store.execute(SQL["job_set_tokens"], (tokens, tokens, identifier))
            if number(value.get("cost_usd"), 0, 1e6):
                cost = max(cost or 0, float(value["cost_usd"]))
                self.store.execute(SQL["job_set_cost"], (cost, math.ceil(cost * 1e6), identifier))
            if isinstance(value.get("session_id"), str) and len(value["session_id"]) <= 512:
                self.store.execute(SQL["job_set_provider_session"], (value["session_id"], identifier))
            if value.get("quota"):
                self.record_quota(settings["provider"], value["quota"], account=account, during_review=True)
                if value["quota"].get("limit_reached"):
                    raise ReviewError("rate_limited")
            if cancel.is_set():
                raise ReviewError("cancelled")
            if tokens is not None and tokens >= settings["max_tokens"]:
                raise ReviewError("token_limit")
            if settings["provider"] == "claude" and cost is not None and cost >= settings["max_cost_usd"]:
                raise ReviewError("cost_limit")

        try:
            probe = self.refresh_quota(settings["provider"])
            account = probe["account"]
            if not probe["subscription"] and not settings["allow_paid"]:
                raise ReviewError("paid_not_allowed")
            decision = self.quota_decision(settings)
            if not decision["allowed"]:
                raise ReviewError(
                    "rate_limited"
                    if (self.quota(settings["provider"]) or {}).get("limit_reached")
                    else "usage_unavailable"
                )
            with self.lock:
                if cancel.is_set() or self.preferences()["revision"] != settings["revision"]:
                    raise ReviewError("cancelled")
                self.store.execute(SQL["job_set_running"], (identifier,))
                dispatched = True
            if automatic:
                threading.Thread(
                    target=self._watch_activity, args=(identifier, cancel, settings), daemon=True
                ).start()
            report = self.driver.run(settings["provider"], prompt, REPORT_SCHEMA, settings, cancel, progress)
            report = validate_report(report, evidence)
            if tokens is None:
                raise ReviewError("usage_unavailable")
            if cancel.is_set():
                raise ReviewError("cancelled")
            if self.withheld(canonical(report), settings["provider"]):
                raise ReviewError("invalid_report")
            # A successful, usage-bearing terminal result may release unused
            # reservation. Missing-cost Claude results retain their cost reserve.
            with self.lock:
                if cancel.is_set():
                    raise ReviewError("cancelled")
                self.store.execute(
                    SQL["job_complete"],
                    (
                        utcnow(),
                        canonical(report),
                        tokens,
                        tokens,
                        cost,
                        math.ceil(cost * 1e6)
                        if cost is not None
                        else (
                            math.ceil(settings["max_cost_usd"] * 1e6)
                            if settings["provider"] == "claude"
                            else 0
                        ),
                        identifier,
                    ),
                )
        except Exception as error:
            code = error.code if isinstance(error, ReviewError) else "cli_failed"
            state = "cancelled" if code == "cancelled" else "failed"
            self.store.execute(
                SQL["job_fail"], (state, utcnow(), ERRORS.get(code, ERRORS["cli_failed"]), identifier)
            )
            if not dispatched:
                self.store.execute(SQL["job_release_charge"], (identifier,))
        finally:
            with self.lock:
                if self.active == identifier:
                    self.active = None
            self.audit(
                "security_review_finished",
                "Security review finished",
                {"id": identifier, "provider": settings["provider"]},
            )

    def cancel_job(self, identifier):
        with self.lock:
            if identifier != self.active:
                raise ValueError("This review is not running")
            self.cancel.set()
        return {"cancellation_requested": True}

    def forget_evidence(self):
        """Called under our lock before history deletion; keep only budget receipts."""
        with self.lock:
            self.cancel.set()
            self.store.execute(
                SQL["job_forget_evidence"],
                (
                    canonical(
                        {
                            "partial": True,
                            "included_messages": 0,
                            "total_messages": 0,
                            "evidence_deleted": True,
                        }
                    ),
                ),
            )

    def _review_runs(self):
        """The (provider, provider session) of each review run, which capture also records as a session."""
        return {
            (row["provider"], row["provider_session_id"])
            for row in self.store.rows(SQL["job_review_runs"])
        }

    def idle(self, minutes):
        try:
            seconds = self.device.idle_seconds()
            if not number(seconds, 0, 365 * 86400) or seconds < minutes * 60:
                self.idle_reason = "Waiting for idle time"
                return False
        except Exception:
            self.idle_reason = "Device idle detection is unavailable; manual reviews still work"
            return False
        # Device-idle alone does not mean an unattended interactive agent is idle.
        cutoff = time.time() - minutes * 60
        hooks_active = self.sessions.hooks_active(cutoff)
        runs = self._review_runs()
        sessions_active = any(
            (session["source"], session["source_session_id"]) not in runs
            for session in self.sessions.active_sessions(cutoff)
        )
        self.idle_reason = "Waiting for observed agent activity to settle"
        return not hooks_active and not sessions_active

    def _watch_activity(self, identifier, cancel, settings):
        while not cancel.wait(5) and not self.stop.is_set():
            with self.lock:
                if self.active != identifier:
                    return
            if not self.idle(settings["idle_minutes"]):
                cancel.set()
                return

    def tick(self):
        settings = self.preferences()
        if not settings["background"]:
            self.scheduler_reason = "Idle reviews are off"
            return
        if self.active:
            self.scheduler_reason = "A security review is running"
            return
        if not self.idle(settings["idle_minutes"]):
            self.scheduler_reason = self.idle_reason
            return
        selected = None
        try:
            reviewed = {
                (row["session_id"], row["digest"])
                for row in self.store.rows(SQL["job_reviewed"], (VERSION,))
            }
            runs = self._review_runs()
            selected = next(
                (
                    session
                    for session in self.sessions.recent_sessions(settings["projects"])
                    if (session["id"], session["digest"]) not in reviewed
                    and (session["source"], session["source_session_id"]) not in runs
                ),
                None,
            )
            if selected is None:
                self.scheduler_reason = "No new sessions in your selected projects"
                return
            used = self.ledger()
            if (
                used["tokens"] + settings["max_tokens"] > settings["daily_tokens"]
                or used["jobs"] >= settings["daily_jobs"]
                or (
                    settings["provider"] == "claude"
                    and used["cost_usd"] + settings["max_cost_usd"] > settings["daily_cost_usd"] + 1e-9
                )
            ):
                self.scheduler_reason = "Waiting for the rolling review budget"
                return
            if time.time() - self.last_probe > 60:
                self.last_probe = time.time()
                self.refresh_quota(settings["provider"])
            decision = self.quota_decision(settings)
            self.scheduler_reason = decision["reason"]
            if not decision["allowed"]:
                return
            self.start(selected["id"], str(uuid.uuid4()), automatic=True)
            self.scheduler_reason = "Reviewing an opted-in session"
        except ReviewInputError as error:
            self.scheduler_reason = str(error)
            if selected:
                self.store.execute(
                    SQL["job_insert_skipped"],
                    (
                        uuid.uuid4().hex,
                        str(uuid.uuid4()),
                        selected["id"],
                        selected["digest"],
                        VERSION,
                        settings["provider"],
                        settings["model"],
                        utcnow(),
                        time.time(),
                        canonical(
                            {
                                "partial": True,
                                "included_messages": 0,
                                "total_messages": selected["message_count"],
                            }
                        ),
                        utcnow(),
                        str(error),
                    ),
                )
        except (ValueError, ReviewError) as error:
            self.scheduler_reason = str(error)
        except Exception:
            self.scheduler_reason = "Reviews paused; check the selected agent and usage settings"

    def _loop(self):
        while not self.stop.wait(30):
            self.tick()

    def close(self):
        self.stop.set()
        self.cancel.set()
        if self.poller:
            self.poller.join(timeout=18)
        if self.worker:
            self.worker.join(timeout=20)
