"""Loopback-only owner UI and separate, least-privilege agent/hook capabilities."""

import json
import re
import secrets
import sqlite3
import sys
import threading
import time
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.concurrency import run_in_threadpool

from . import agent_plugins, hooks
from .approval_queue import APPROVAL_TIMEOUT_SECONDS
from .config import CAPTURE_INTERVAL_SECONDS, MAX_JSON_BYTES, canonical, utcnow
from .credential_activity import RUN_ID, recent_runs, record_session
from .native import NativeTimedOut, NativeUnavailable
from .policy import event_fields
from .protection import evaluate_operation
from .review_process import ReviewError
from .secret_guard import KINDS, detect_credentials
from .security_reviews import receive_claude_usage
from .threat_feed import MAX_FEED_BYTES
from .threat_protection import ThreatStateConflict

COOKIE = "adr_session"


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Bootstrap(Input):
    ticket: str = Field(min_length=1, max_length=128)


class Preferences(Input):
    interval_seconds: int | None = Field(default=None, strict=True)
    history_days: int | None = Field(default=None, ge=1, le=30)
    inventory_enabled: bool | None = None
    onboarding_complete: bool | None = None

    @field_validator("interval_seconds")
    @classmethod
    def capture_interval(cls, value):
        if value is not None and value not in CAPTURE_INTERVAL_SECONDS:
            raise ValueError("Choose a capture interval of 5, 15, 30, or 60 minutes")
        return value


class Rule(Input):
    path: str = Field(min_length=1, max_length=8192)
    action: Literal["ask", "block"]
    kind: Literal["file", "directory"]
    label: str = Field(default="", max_length=100)


class PolicySettings(Input):
    enabled: bool | None = None
    opaque_tools: Literal["ask", "block"] | None = None
    strict_execution: bool | None = Field(default=None, strict=True)


class Credential(Input):
    name: str = Field(min_length=1, max_length=80)
    origin: str = Field(max_length=512)
    auth_type: Literal["bearer", "api_key", "basic"] = "bearer"
    header_name: str = Field(default="Authorization", max_length=64)
    username: str = Field(default="", max_length=200)
    allowed_paths: list[str] = Field(min_length=1, max_length=32)


class Grant(Input):
    name: str = Field(min_length=1, max_length=80)
    project: str = Field(default="", max_length=8192)
    credentials: list[str] = Field(default_factory=list, max_length=32)
    kind: Literal["legacy", "history", "context", "vault", "execution"] = "legacy"
    approval_mode: Literal["ask", "automatic"] = "ask"
    confirm_device_history: bool = False
    confirm_automatic: bool = False
    confirm_execution: bool = False
    confirm_all_environment: bool = False


class EnvironmentCredential(Input):
    name: str = Field(min_length=1, max_length=80)
    env_name: str = Field(min_length=1, max_length=64)


class EnvironmentCommand(Input):
    command: str = Field(min_length=1, max_length=16384)
    cwd: str = Field(default="", max_length=8192)
    timeout_seconds: int = Field(default=30, ge=1, le=60, strict=True)


class VaultMigration(Input):
    ids: list[str] = Field(min_length=1, max_length=128)
    confirm: bool = False

    @field_validator("ids")
    @classmethod
    def credential_ids(cls, value):
        if len(set(value)) != len(value) or any(not re.fullmatch(r"[a-f0-9]{32}", item) for item in value):
            raise ValueError("Choose saved credential entries")
        return value


class MigrationEnrollment(Input):
    confirm: bool = False


class AccessSettings(Input):
    target: Literal["full_disk_access", "files_and_folders", "privacy_security"] = "full_disk_access"


class PromptCheck(Input):
    harness: Literal["claude", "codex"]
    prompt: str = Field(max_length=256 * 1024)


class OutputCheck(Input):
    harness: Literal["claude", "codex", "opencode"]
    text: str = Field(max_length=256 * 1024)


class BrokerRequest(Input):
    credential_id: str = Field(min_length=32, max_length=32)
    path: str = Field(min_length=1, max_length=2048)


class Approval(Input):
    allow: bool


class ArtifactReceipt(Input):
    indicator_id: str = Field(min_length=3, max_length=257, pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    source_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.-]+$")
    kind: Literal["file_sha256", "skill_sha256", "package", "mcp_endpoint"]
    generation: str = Field(pattern=r"^[a-f0-9]{64}$")
    target_display: str = Field(min_length=1, max_length=2048)


class HookEvent(Input):
    harness: Literal["claude", "codex", "opencode", "copilot"]
    decision: Literal["pass", "ask", "deny"]
    reason: str = Field(max_length=1024)
    paths: list[str] = Field(default_factory=list, max_length=16)
    rule_id: str | None = Field(default=None, max_length=64)
    tool: str = Field(default="", max_length=200)
    session_id: str = Field(default="", max_length=512)
    credential_kinds: list[str] = Field(default_factory=list, max_length=16)
    phase: Literal["pre", "post"] = "pre"
    approval_requested: bool = Field(default=False, strict=True)
    artifact: ArtifactReceipt | None = None


class ThreatPreferences(Input):
    enabled: bool = Field(strict=True)
    expected_revision: str = Field(min_length=32, max_length=32, pattern=r"^[a-f0-9]{32}$")

class ReviewPreferences(Input):
    expected_revision: str = Field(pattern=r"^[a-f0-9]{32}$")
    confirm_data_share: bool = Field(default=False, strict=True)
    provider: Literal["claude", "codex"] | None = None
    model: str | None = Field(default=None, max_length=100)
    background: bool | None = Field(default=None, strict=True)
    mode: Literal["budget", "spare"] | None = None
    max_tokens: int | None = Field(default=None, ge=1000, le=100000, strict=True)
    daily_tokens: int | None = Field(default=None, ge=1000, le=1000000, strict=True)
    daily_jobs: int | None = Field(default=None, ge=1, le=100, strict=True)
    max_seconds: int | None = Field(default=None, ge=30, le=600, strict=True)
    max_cost_usd: float | None = Field(default=None, ge=0.01, le=100, strict=True)
    daily_cost_usd: float | None = Field(default=None, ge=0.01, le=100, strict=True)
    allow_paid: bool | None = Field(default=None, strict=True)
    reserve_percent: int | None = Field(default=None, ge=10, le=90, strict=True)
    idle_minutes: int | None = Field(default=None, ge=5, le=120, strict=True)
    reset_within_hours: int | None = Field(default=None, ge=1, le=24, strict=True)
    projects: list[str] | None = Field(default=None, max_length=30)


class ReviewStart(Input):
    session_id: str = Field(min_length=1, max_length=128)
    request_id: str = Field(min_length=32, max_length=36)


class ClaudeUsageWindow(Input):
    used_percentage: float = Field(ge=0, le=100, strict=True)
    resets_at: float = Field(ge=0, strict=True)


class ClaudeReviewUsage(Input):
    rate_limits: dict[Literal["five_hour", "seven_day"], ClaudeUsageWindow]


class ThreatImportPreview(Input):
    document: str = Field(min_length=1, max_length=MAX_FEED_BYTES)
    expected_revision: str = Field(min_length=32, max_length=32, pattern=r"^[a-f0-9]{32}$")


class ThreatImport(ThreatImportPreview):
    confirm: bool = Field(default=False, strict=True)


class HookApproval(Input):
    harness: Literal["codex", "opencode", "copilot"]
    event: dict


class CredentialUseSession(Input):
    run_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    grant_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    harness: Literal["claude", "codex", "opencode"]
    session_id: str = Field(min_length=1, max_length=512, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")


class IntegrationConsent(Input):
    allow_context: bool = False
    allow_credentials: bool = False


class AllIntegrationsConsent(Input):
    allow_agents: bool = False


class IntegrationEnrollment(IntegrationConsent):
    harness: Literal["claude", "codex", "opencode", "copilot", "all"]
    allow_agents: bool = False


def create_app(runtime) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.runtime = runtime
    web_dir = Path(__file__).parent / "web"

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_request, _error):
        # Validation errors normally echo the offending input. A rejected
        # credential/prompt must never be reflected into a tool response.
        return JSONResponse(status_code=422, content={"detail": "Invalid request fields or values"})

    @app.exception_handler(ReviewError)
    async def review_error(_request, error):
        return JSONResponse(status_code=400, content={"detail": str(error)})

    def bearer(request):
        header = request.headers.get("authorization", "")
        return header[7:] if header.startswith("Bearer ") and len(header) < 200 else ""

    def require_owner(request: Request):
        if runtime.is_owner(bearer(request)):
            return
        csrf = runtime.session(request.cookies.get(COOKIE))
        if not csrf:
            raise HTTPException(401, "Open ADR from the menu-bar app to reconnect")
        if request.method not in ("GET", "HEAD") and not secrets.compare_digest(
            request.headers.get("x-adr-csrf", ""), csrf
        ):
            # Only this pre-execution rejection is safe for the browser to retry.
            raise HTTPException(
                403,
                {
                    "code": "csrf_mismatch",
                    "message": "Your browser session changed. Refresh this page and try again.",
                },
            )

    def require_agent(request: Request):
        grant = runtime.grant(bearer(request))
        if not grant:
            raise HTTPException(401, "This agent has no active ADR access grant")
        return grant

    def require_hook(request: Request):
        if not runtime.is_hook(bearer(request)):
            raise HTTPException(401, "Invalid hook capability")

    def history_project(grant):
        if grant["history_scope"] == "device":
            return None
        if grant["history_scope"] == "project":
            return grant["project"]
        raise HTTPException(403, "This connection has no conversation-history access")

    @app.middleware("http")
    async def local_boundary(request: Request, call_next):
        host = request.headers.get("host", "")
        expected = {f"127.0.0.1:{runtime.port}", f"localhost:{runtime.port}"}
        if host not in expected:
            return JSONResponse({"detail": "Invalid local host"}, status_code=403)
        origin = request.headers.get("origin")
        if origin and origin not in {f"http://{item}" for item in expected}:
            return JSONResponse({"detail": "Cross-origin requests are not allowed"}, status_code=403)
        if request.headers.get("sec-fetch-site") == "cross-site":
            return JSONResponse({"detail": "Cross-site requests are not allowed"}, status_code=403)
        try:
            length = int(request.headers.get("content-length", "0"))
        except ValueError:
            return JSONResponse({"detail": "Invalid content length"}, status_code=400)
        if length < 0 or length > MAX_JSON_BYTES:
            return JSONResponse({"detail": "Request is too large"}, status_code=413)
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if request.headers.get("transfer-encoding"):
                return JSONResponse({"detail": "Chunked requests are not accepted"}, status_code=400)
            if length and request.headers.get("content-type", "").split(";")[0] != "application/json":
                return JSONResponse({"detail": "Use application/json"}, status_code=415)
        response = await call_next(request)
        response.headers.update(
            {
                "Content-Security-Policy": (
                    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
                ),
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Cache-Control": "no-store",
            }
        )
        return response

    def error_body(error):
        body = {"detail": str(error)}
        identifier = getattr(error, "adr_run_id", None)
        if isinstance(identifier, str) and RUN_ID.fullmatch(identifier):
            body["run_id"] = identifier
        return body

    @app.exception_handler(ValueError)
    async def value_error(_request, error):
        return JSONResponse(error_body(error), status_code=400)

    @app.exception_handler(PermissionError)
    async def denied(_request, error):
        return JSONResponse(error_body(error), status_code=403)

    @app.exception_handler(NativeUnavailable)
    async def native_unavailable(_request, error):
        return JSONResponse(error_body(error), status_code=503)

    @app.exception_handler(sqlite3.IntegrityError)
    async def conflict(_request, _error):
        return JSONResponse({"detail": "An item with this name already exists"}, status_code=409)

    @app.exception_handler(ThreatStateConflict)
    async def threat_conflict(_request, error):
        return JSONResponse({"detail": str(error)}, status_code=409)

    @app.get("/api/health")
    def health():
        return {
            "service": "adr-desktop",
            "running": True,
            "instance": runtime.instance,
            "interactive_setup": runtime.native.connected,
        }

    @app.post("/api/auth/bootstrap")
    def bootstrap(body: Bootstrap, request: Request, response: Response):
        session, csrf = runtime.consume_ticket(body.ticket, request.cookies.get(COOKIE))
        response.set_cookie(COOKIE, session, httponly=True, samesite="strict", max_age=8 * 3600)
        return {"csrf": csrf}

    @app.get("/api/auth/session")
    def current_session(request: Request):
        csrf = runtime.session(request.cookies.get(COOKIE))
        if not csrf:
            raise HTTPException(401, "Open ADR from the menu-bar app")
        return {"csrf": csrf}

    @app.post("/api/control/open", dependencies=[Depends(require_owner)])
    def open_ui():
        return {"url": f"http://127.0.0.1:{runtime.port}/#ticket={runtime.new_ticket()}"}

    @app.get("/api/status", dependencies=[Depends(require_owner)])
    def status():
        return runtime.status()

    @app.get("/api/threats", dependencies=[Depends(require_owner)])
    def threat_status():
        return runtime.threats.status()

    @app.get("/api/reviews", dependencies=[Depends(require_owner)])
    def reviews():
        return runtime.reviews.status()

    @app.patch("/api/reviews/settings", dependencies=[Depends(require_owner)])
    def review_settings(body: ReviewPreferences):
        values = body.model_dump(exclude_none=True)
        revision = values.pop("expected_revision")
        confirm = values.pop("confirm_data_share")
        return runtime.reviews.change_settings(values, expected_revision=revision, confirm_data_share=confirm)

    @app.post("/api/reviews/quota", dependencies=[Depends(require_owner)])
    def review_quota(_body: Input):
        runtime.reviews.refresh_quota()
        return runtime.reviews.status()

    @app.post("/api/reviews/claude-usage", dependencies=[Depends(require_owner)])
    def review_claude_usage(body: Approval):
        from .review_usage import connect

        with runtime.integration_lock:
            result = connect(runtime.state_dir, enabled=body.allow)
        runtime.store.audit("review_usage_connection", "Claude usage reporting changed",
                            {"connected": result["connected"]})
        return result

    @app.post("/api/reviews/start", dependencies=[Depends(require_owner)])
    def review_start(body: ReviewStart):
        return runtime.reviews.start(body.session_id, body.request_id)

    @app.post("/api/reviews/{identifier}/cancel", dependencies=[Depends(require_owner)])
    def review_cancel(identifier: str, _body: Input):
        return runtime.reviews.cancel_job(identifier)

    @app.post("/api/hooks/review-usage", dependencies=[Depends(require_hook)])
    def review_usage(body: ClaudeReviewUsage):
        return receive_claude_usage(runtime, body.model_dump())

    @app.patch("/api/threats", dependencies=[Depends(require_owner)])
    def threat_settings(body: ThreatPreferences):
        return runtime.threats.change_settings(**body.model_dump())

    @app.post("/api/threats/import/preview", dependencies=[Depends(require_owner)])
    def threat_import_preview(body: ThreatImportPreview):
        return runtime.threats.preview_import(**body.model_dump())

    @app.post("/api/threats/import", dependencies=[Depends(require_owner)])
    def threat_import(body: ThreatImport):
        return runtime.threats.import_feed(**body.model_dump())

    @app.post("/api/threats/check", dependencies=[Depends(require_owner)])
    def threat_check(body: Input):
        return runtime.threats.check_installed()

    @app.get("/api/overview", dependencies=[Depends(require_owner)])
    def overview():
        result = runtime.store.overview()
        result["totals"]["rules"] = len(runtime.policy["rules"])
        return result

    @app.get("/api/sessions", dependencies=[Depends(require_owner)])
    def sessions(
        source: str = "", q: str = "", limit: int = 50, offset: int = 0, grouped: bool = True,
        project: str | None = Query(default=None, max_length=8192),
        since: str = Query(default="", max_length=40), before: str = Query(default="", max_length=40),
    ):
        if len(q) > 200 or len(source) > 80:
            raise HTTPException(400, "Search is too long")
        return runtime.store.sessions(
            source=source, query=q, limit=limit, offset=offset, grouped=grouped,
            project=project, since=since, before=before, previews=True,
        )

    @app.get("/api/sessions/filters", dependencies=[Depends(require_owner)])
    def session_filters():
        return runtime.store.session_filters()

    @app.get("/api/history/search", dependencies=[Depends(require_owner)])
    def search_history(
        q: str = Query(min_length=1, max_length=200),
        source: str = Query(default="", max_length=80),
        limit: int = Query(default=20, ge=1, le=50),
        offset: int = Query(default=0, ge=0, le=100000),
        project: str | None = Query(default=None, max_length=8192),
        since: str = Query(default="", max_length=40), before: str = Query(default="", max_length=40),
        sort: Literal["relevance", "newest"] = "relevance",
    ):
        return runtime.store.search_history(
            q, source=source, limit=limit, offset=offset, project=project,
            since=since, before=before, sort=sort, previews=True,
        )

    @app.get("/api/sessions/{identifier}", dependencies=[Depends(require_owner)])
    def session(identifier: str):
        result = runtime.store.session(identifier)
        if not result:
            raise HTTPException(404, "Session not found")
        return result

    @app.get("/api/sessions/{identifier}/export", dependencies=[Depends(require_owner)])
    def export(identifier: str):
        result = runtime.store.session(identifier)
        if not result:
            raise HTTPException(404, "Session not found")
        return Response(
            canonical(result["payload"]),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="adr-session-{result["id"]}.json"'},
        )

    @app.get("/api/sessions/{identifier}/children", dependencies=[Depends(require_owner)])
    def session_children(
        identifier: str, limit: int = Query(default=30, ge=1, le=100),
        offset: int = Query(default=0, ge=0, le=100000),
    ):
        result = runtime.store.session_children(identifier, limit=limit, offset=offset)
        if result is None:
            raise HTTPException(404, "Session not found")
        return result

    @app.post("/api/collector/{action}", dependencies=[Depends(require_owner)])
    def collection(action: Literal["start", "pause", "scan"]):
        if action == "pause":
            runtime.collector.pause()
        else:
            runtime.collector.resume()
        runtime.store.audit("collection_changed", f"Collection: {action}")
        return {"recording": runtime.store.settings()["recording"]}

    @app.patch("/api/settings", dependencies=[Depends(require_owner)])
    def settings(body: Preferences):
        for key, value in body.model_dump(exclude_none=True).items():
            runtime.store.setting(key, value)
        runtime.collector.wake.set()
        return {"ok": True}

    @app.post("/api/history/delete", dependencies=[Depends(require_owner)])
    def delete_history():
        runtime.collector.pause()
        if runtime.collector.capture_lock.locked():
            raise HTTPException(409, "Collection is stopping; retry deletion in a moment")
        with runtime.reviews.lock:
            runtime.reviews.forget_evidence()
            runtime.store.purge_history()
        return {"ok": True}

    @app.get("/api/inventory", dependencies=[Depends(require_owner)])
    def inventory():
        from .access_status import inventory_access_status

        data = runtime.store.settings()
        phase = runtime.collector.status()["inventory_phase"]
        return {
            "snapshot": data.get("inventory_snapshot"),
            "updated_at": data.get("inventory_updated_at"),
            "phase": phase,
            "access": inventory_access_status(
                data.get("inventory_snapshot"), phase=phase, platform_name=sys.platform,
                native_available=runtime.native.connected,
            ),
        }

    @app.get("/api/access", dependencies=[Depends(require_owner)])
    def access_status():
        from .access_status import inventory_access_status

        data = runtime.store.settings()
        result = inventory_access_status(
            data.get("inventory_snapshot"), phase=runtime.collector.status()["inventory_phase"],
            platform_name=sys.platform, native_available=runtime.native.connected,
        )
        if runtime.native.connected:
            try:
                result["identity"] = runtime.native.call("file_access_identity", timeout=3)
            except (NativeUnavailable, ValueError):
                result["identity"] = None
        return result

    @app.get("/api/inventory/coverage", dependencies=[Depends(require_owner)])
    def inventory_coverage(
        section: Literal["access", "skipped"] = "access",
        root: str | None = Query(default=None, max_length=8192),
        offset: int = Query(default=0, ge=0, le=100000),
        limit: int = Query(default=20, ge=1, le=100),
        revision: str = Query(default="", max_length=80),
    ):
        from adr_discovery.coverage.report import coverage_page
        from adr_discovery.reporter.snapshot import from_dict

        settings = runtime.store.settings()
        if revision and revision != settings.get("inventory_updated_at"):
            raise HTTPException(409, "The scan changed. Refresh inventory before loading more details.")
        snapshot = settings.get("inventory_snapshot") or {}
        if not isinstance(snapshot.get("coverage"), dict):
            raise HTTPException(409, "Run an inventory scan to see its coverage details")
        parsed = from_dict({"coverage": snapshot["coverage"]}).coverage
        return coverage_page(parsed, section=section, root=root, offset=offset, limit=limit)

    @app.post("/api/access/settings", dependencies=[Depends(require_owner)])
    def access_settings(body: AccessSettings):
        if sys.platform != "darwin" or not runtime.native.connected:
            raise NativeUnavailable("Open macOS Privacy & Security settings to review ADR access")
        result = runtime.native.call("open_access_settings", {"target": body.target}, timeout=5)
        runtime.store.audit("access_settings_opened", "Requested macOS privacy settings")
        return result

    @app.post("/api/inventory/scan", dependencies=[Depends(require_owner)])
    def scan_inventory():
        threading.Thread(target=runtime.collector.scan_inventory, daemon=True).start()
        return {"started": True}

    @app.get("/api/protection", dependencies=[Depends(require_owner)])
    def protection():
        return runtime.policy

    @app.get("/api/protection/starter", dependencies=[Depends(require_owner)])
    def starter_protection():
        return runtime.starter_protection()

    @app.post("/api/protection/starter", dependencies=[Depends(require_owner)])
    def add_starter_protection(_body: Input):
        return runtime.add_starter_protection()

    @app.post("/api/protection/rules", dependencies=[Depends(require_owner)])
    def add_rule(body: Rule):
        return runtime.change_policy(add=body.model_dump())

    @app.delete("/api/protection/rules/{identifier}", dependencies=[Depends(require_owner)])
    def delete_rule(identifier: str):
        return runtime.change_policy(delete=identifier)

    @app.patch("/api/protection", dependencies=[Depends(require_owner)])
    def protection_settings(body: PolicySettings):
        return runtime.change_policy(**body.model_dump(exclude_none=True))

    @app.post("/api/hooks/{harness}/{action}", dependencies=[Depends(require_owner)])
    def configure_hook(
        harness: Literal["claude", "codex", "opencode", "copilot"],
        action: Literal["install", "remove"],
    ):
        handler = hooks.install if action == "install" else hooks.uninstall
        result = handler(harness, runtime.state_dir)
        runtime.store.audit("hook_changed", f"{harness} hook: {action}")
        return result

    @app.post("/api/integrations/{harness}/connect", dependencies=[Depends(require_owner)])
    async def connect_integration(
        harness: Literal["claude", "codex", "opencode", "copilot"],
        body: IntegrationConsent,
    ):
        return await run_in_threadpool(
            agent_plugins.connect,
            runtime,
            harness,
            allow_context=body.allow_context,
            allow_credentials=body.allow_credentials,
            driver=getattr(runtime, "integration_driver", None),
        )

    @app.post("/api/integrations/connect-all", dependencies=[Depends(require_owner)])
    async def connect_all_integrations(body: AllIntegrationsConsent):
        return await run_in_threadpool(
            agent_plugins.connect_all, runtime, allow_agents=body.allow_agents,
            driver=getattr(runtime, "integration_driver", None),
        )

    @app.post("/api/integrations/{harness}/disconnect", dependencies=[Depends(require_owner)])
    async def disconnect_integration(harness: Literal["claude", "codex", "opencode", "copilot"]):
        return await run_in_threadpool(
            agent_plugins.disconnect,
            runtime,
            harness,
            driver=getattr(runtime, "integration_driver", None),
        )

    @app.post("/api/integrations/enroll")
    async def enroll_integration(body: IntegrationEnrollment, request: Request):
        # CLI enrollment requests can only ask the native owner. They cannot
        # authorize themselves, return a bearer token, or choose arbitrary paths.
        if request.headers.get("origin") or request.headers.get("sec-fetch-site"):
            raise HTTPException(403, "Use the authenticated app for browser setup")
        if not body.allow_context and not (body.harness == "all" and body.allow_agents):
            raise HTTPException(400, "Explicit device-context consent is required")
        if not runtime.native.connected:
            raise HTTPException(409, "Headless setup requires the private owner capability")
        if not runtime.enrollment_lock.acquire(blocking=False):
            raise HTTPException(409, "Another integration setup is already waiting")
        try:
            now = time.monotonic()
            if now - runtime.last_enrollment < 10:
                raise HTTPException(429, "Wait a moment before requesting setup again")
            runtime.last_enrollment = now
            driver = getattr(runtime, "integration_driver", None) or agent_plugins.NativePluginDriver()
            if body.harness != "all":
                await run_in_threadpool(driver.executable, body.harness)
            decision = await run_in_threadpool(
                runtime.native.call,
                "approve_integration",
                {
                    "harness": (
                        "installed agents" if body.harness == "all" else hooks.HARNESS_LABELS[body.harness]
                    ),
                    "credentials": body.allow_credentials or body.allow_agents,
                },
                105,
            )
            if decision.get("allowed") is not True:
                raise HTTPException(403, "ADR integration setup was not approved")
            if body.harness == "all":
                return await run_in_threadpool(
                    agent_plugins.connect_all, runtime, allow_agents=body.allow_agents, driver=driver,
                )
            return await run_in_threadpool(
                agent_plugins.connect,
                runtime,
                body.harness,
                allow_context=True,
                allow_credentials=body.allow_credentials,
                driver=driver,
            )
        finally:
            runtime.enrollment_lock.release()

    @app.post("/api/hooks/approve", dependencies=[Depends(require_hook)])
    async def approve_hook(body: HookApproval):
        # This capability can request the owner's native decision, never approve itself.
        def outcome(allowed, code):
            return {"allowed": allowed, "reason_code": code}

        async def check_current():
            decision = await run_in_threadpool(
                evaluate_operation, body.event, body.harness, runtime.policy,
                state_dir=runtime.state_dir, allow_adr_trust=False,
                artifact_scope="direct_files",
            )
            if decision.decision == "deny" and decision.artifact:
                runtime.threats.record_block(decision, harness=body.harness, source="approval")
            return decision

        rendered = canonical(body.event)
        if len(rendered.encode()) > 16384 or detect_credentials(rendered):
            return outcome(False, "invalid_request")
        current = await check_current()
        if current.decision != "ask":
            return outcome(current.decision == "pass", current.reason_code)
        if not runtime.native.connected:
            return outcome(False, "app_unavailable")
        deadline = time.monotonic() + APPROVAL_TIMEOUT_SECONDS
        ticket, failure = await run_in_threadpool(runtime.hook_approvals.acquire, deadline)
        if ticket is None:
            return outcome(False, failure)
        try:
            # Rules may change while queued. Never show an obsolete dialog or
            # permit a previously queued request to override a newly added Block.
            current = await check_current()
            if current.decision != "ask":
                return outcome(current.decision == "pass", current.reason_code)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return outcome(False, "approval_expired")
            if not runtime.native.connected:
                return outcome(False, "app_unavailable")
            tool, arguments, cwd, _ = event_fields(body.event, body.harness)
            value = await run_in_threadpool(
                runtime.native.call,
                "approve_tool",
                {
                    "harness": body.harness,
                    "tool": tool,
                    "operation": canonical({"cwd": cwd, "arguments": arguments}),
                    "expires_at": time.time() + remaining,
                },
                remaining,
            )
            if time.monotonic() >= deadline or value.get("reason_code") == "approval_expired":
                return outcome(False, "approval_expired")
            current = await check_current()
            if current.decision == "deny":
                return outcome(False, current.reason_code)
            if time.monotonic() >= deadline:
                return outcome(False, "approval_expired")
            allowed = value.get("allowed") is True
            runtime.store.audit("file_approval", "Tool allowed once" if allowed else "Tool denied")
            return outcome(allowed, "approved" if allowed else "approval_denied")
        except NativeTimedOut:
            return outcome(False, "approval_expired")
        except NativeUnavailable:
            return outcome(False, "app_unavailable")
        finally:
            runtime.hook_approvals.release(ticket)

    @app.post("/api/hooks/events", dependencies=[Depends(require_hook)])
    def hook_event(body: HookEvent):
        if any(len(path) > 8192 for path in body.paths):
            raise HTTPException(400, "A hook path is too long")
        if not set(body.credential_kinds) <= KINDS:
            raise HTTPException(400, "Unknown credential finding type")
        runtime.store.execute(
            """INSERT INTO hook_events(
               timestamp,harness,session_id,tool,decision,reason,paths,rule_id,credential_kinds,phase,
               approval_requested) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                utcnow(),
                body.harness,
                body.session_id,
                body.tool,
                body.decision,
                body.reason,
                canonical(body.paths),
                body.rule_id,
                canonical(body.credential_kinds),
                body.phase,
                body.approval_requested or body.decision == "ask"
                or (body.decision == "pass" and body.reason == "Allowed once in ADR"),
            ),
        )
        if body.phase == "pre" and body.artifact is not None:
            runtime.threats.record_block(body.model_dump(), harness=body.harness, source="hook")
        return {"recorded": True}

    @app.post("/api/hooks/credential-use", dependencies=[Depends(require_hook)])
    def credential_use_session(body: CredentialUseSession):
        return {"recorded": record_session(runtime.store, **body.model_dump())}

    @app.get("/api/protection/events", dependencies=[Depends(require_owner)])
    def protection_events(
        interventions_only: bool = False, limit: int = Query(default=100, ge=1, le=100),
    ):
        where = "WHERE decision IN ('deny','ask') OR approval_requested=1" if interventions_only else ""
        rows = runtime.store.rows(f"SELECT * FROM hook_events {where} ORDER BY id DESC LIMIT ?", (limit,))
        for row in rows:
            row["paths"] = json.loads(row["paths"])
            row["credential_kinds"] = json.loads(row["credential_kinds"])
            row["approval_requested"] = bool(row["approval_requested"])
        return {"items": rows}

    @app.get("/api/credentials", dependencies=[Depends(require_owner)])
    def credentials():
        return {"items": runtime.broker.credentials(), "available": runtime.native.connected}

    def registered_vault_ids():
        return [
            row["id"] for row in [
                *runtime.environment_vault.entries(), *runtime.broker.credentials(),
            ] if row["state"] != "revoked"
        ]

    @app.get("/api/vault/storage", dependencies=[Depends(require_owner)])
    def vault_storage():
        if not runtime.native.connected:
            return {"backend": "local_encrypted", "available": False, "entries": []}
        ids, entries = registered_vault_ids(), []
        try:
            for offset in range(0, max(1, len(ids)), 128):
                result = runtime.native.call(
                    "vault_storage_status", {"ids": ids[offset:offset + 128]}, timeout=8,
                )
                if result.get("backend") != "local_encrypted" or not isinstance(result.get("entries"), list):
                    raise NativeUnavailable("local_vault_unavailable")
                entries.extend(result["entries"])
            return {
                "backend": "local_encrypted", "available": True, "entries": entries,
                "legacy_access": "explicit_migration_only",
            }
        except (NativeUnavailable, ValueError):
            return {
                "backend": "local_encrypted", "available": False, "entries": [],
                "reason_code": "local_vault_unavailable",
            }

    @app.post("/api/vault/migrate", dependencies=[Depends(require_owner)])
    def migrate_vault(body: VaultMigration):
        if not body.confirm:
            raise HTTPException(400, "Confirm copying the selected entries from Keychain")
        if not set(body.ids) <= set(registered_vault_ids()):
            raise HTTPException(400, "Choose entries already saved in this ADR profile")
        if not runtime.native.connected:
            raise NativeUnavailable("Open the ADR menu-bar app to move saved credentials")
        if not runtime.vault_migration_lock.acquire(blocking=False):
            raise HTTPException(409, "A credential move is already in progress")
        try:
            result = runtime.native.call(
                "vault_migrate_legacy", {"ids": body.ids, "expires_at": time.time() + 110}, timeout=120,
            )
            statuses = result.get("results", [])
            completed = sum(item.get("status") in ("migrated", "already_local") for item in statuses)
            runtime.store.audit(
                "vault_storage_migrated", "Copied saved credentials into the local vault",
                {"requested": len(body.ids), "completed": completed},
            )
            return result
        except NativeTimedOut:
            # Keychain may still finish after the IPC deadline. Do not report
            # rollback or blindly retry a potentially committed copy.
            raise NativeUnavailable(
                "The move is taking longer than expected. Refresh vault storage before trying again; "
                "Keychain originals are unchanged."
            ) from None
        finally:
            runtime.vault_migration_lock.release()

    @app.post("/api/vault/recover", dependencies=[Depends(require_owner)])
    def recover_vault(body: VaultMigration):
        if not body.confirm or not set(body.ids) <= set(registered_vault_ids()):
            raise HTTPException(400, "Confirm recovery of entries in this ADR profile")
        if not runtime.native.connected:
            raise NativeUnavailable("Open the ADR menu-bar app to verify saved credentials")
        result = runtime.native.call("vault_storage_status", {"ids": body.ids}, timeout=8)
        verified = {
            item["id"]: item.get("kind") for item in result.get("entries", [])
            if item.get("id") in body.ids and item.get("state") == "available"
        }
        outcomes = []
        for identifier in body.ids:
            environment = runtime.store.one(
                "SELECT state FROM environment_credentials WHERE id=?", (identifier,)
            )
            table, kind = (
                ("environment_credentials", "environment") if environment else ("credentials", "service")
            )
            if verified.get(identifier) != kind:
                outcomes.append({"id": identifier, "recovered": False})
                continue
            # A concurrent removal marks revoked before native deletion; never
            # reactivate that state or recreate a deleted metadata row.
            runtime.store.execute(
                f"UPDATE {table} SET state='active' WHERE id=? "
                "AND state IN ('preparing','unconfirmed','error')",
                (identifier,),
            )
            current = runtime.store.one(f"SELECT state FROM {table} WHERE id=?", (identifier,))
            outcomes.append({"id": identifier, "recovered": bool(current and current["state"] == "active")})
        runtime.environment_vault.publish_aliases()
        runtime.store.audit(
            "credential_recovered", "Verified interrupted credential saves",
            {"requested": len(body.ids), "recovered": sum(item["recovered"] for item in outcomes)},
        )
        return {"items": outcomes}

    @app.post("/api/vault/finish-save", dependencies=[Depends(require_owner)])
    def finish_vault_save(body: VaultMigration):
        if not body.confirm or len(body.ids) != 1:
            raise HTTPException(400, "Choose one interrupted save to finish")
        identifier = body.ids[0]
        environment = runtime.store.one(
            "SELECT * FROM environment_credentials WHERE id=?", (identifier,)
        )
        service = next((item for item in runtime.broker.credentials() if item["id"] == identifier), None)
        entry = environment or service
        if not entry or entry["state"] not in ("active", "preparing", "unconfirmed", "error"):
            raise HTTPException(400, "Choose an existing entry with a missing local value")
        checked = runtime.native.call("vault_storage_status", {"ids": [identifier]}, timeout=8)
        status = next((item for item in checked.get("entries", []) if item.get("id") == identifier), {})
        if status.get("state") != "missing":
            raise HTTPException(
                409, "A local copy may exist. Refresh storage and recover it without replacing it.",
            )
        table = "environment_credentials" if environment else "credentials"
        runtime.store.execute(
            f"UPDATE {table} SET state='unconfirmed' WHERE id=? AND state != 'revoked'", (identifier,),
        )
        current = runtime.store.one(f"SELECT state FROM {table} WHERE id=?", (identifier,))
        if not current or current["state"] != "unconfirmed":
            raise HTTPException(409, "This entry changed or was removed; refresh the vault")
        runtime.environment_vault.publish_aliases()
        operation = "environment_prompt_store" if environment else "vault_prompt_store"
        keys = ("id", "name", "env_name") if environment else (
            "id", "name", "origin", "auth_type", "header_name", "username", "allowed_paths",
        )
        # No value is accepted from this request. Reuse the original ID and
        # metadata in the native dialog; create-only storage prevents overwrite.
        runtime.native.call(operation, {key: entry[key] for key in keys}, timeout=120)
        return recover_vault(body)

    @app.post("/api/vault/enroll-migration")
    async def request_vault_migration(body: MigrationEnrollment, request: Request):
        # Like agent enrollment, this CLI route can request a native owner
        # decision, never approve itself or obtain an owner capability.
        if request.headers.get("origin") or request.headers.get("sec-fetch-site"):
            raise HTTPException(403, "Use the authenticated app to move credentials")
        if not body.confirm or not runtime.native.connected:
            raise HTTPException(400, "Open ADR and confirm the one-time Keychain move")
        if not runtime.enrollment_lock.acquire(blocking=False):
            raise HTTPException(409, "Another native setup request is waiting")
        try:
            now = time.monotonic()
            if now - runtime.last_enrollment < 10:
                raise HTTPException(429, "Wait a moment before requesting setup again")
            runtime.last_enrollment = now
            status = await run_in_threadpool(vault_storage)
            if not status.get("available"):
                raise NativeUnavailable("local_vault_unavailable")
            ids = [item["id"] for item in status["entries"] if item.get("state") == "missing"]
            if not ids:
                return {"results": [], "keychain_originals_retained": True}
            if len(ids) > 128:
                raise HTTPException(400, "Move smaller groups of credentials through the vault UI")
            approved = await run_in_threadpool(
                runtime.native.call, "approve_vault_migration", {"count": len(ids)}, 105,
            )
            if approved.get("allowed") is not True:
                raise HTTPException(403, "The credential move was not approved")
            ids = [identifier for identifier in ids if identifier in registered_vault_ids()]
            if not ids:
                return {"results": [], "keychain_originals_retained": True}
            return await run_in_threadpool(migrate_vault, VaultMigration(ids=ids, confirm=True))
        finally:
            runtime.enrollment_lock.release()

    @app.get("/api/environment-credentials", dependencies=[Depends(require_owner)])
    def environment_credentials():
        return {
            "items": runtime.environment_vault.entries(), "available": runtime.native.connected,
            "prompt_blocks": runtime.store.rows(
                "SELECT id,created_at,harness,kinds,aliases FROM prompt_blocks ORDER BY id DESC LIMIT 20"
            ),
            "recent_runs": recent_runs(runtime.store),
        }

    @app.post("/api/environment-credentials", dependencies=[Depends(require_owner)])
    def create_environment_credential(body: EnvironmentCredential):
        return runtime.environment_vault.create(body.name, body.env_name)

    @app.delete("/api/environment-credentials/{identifier}", dependencies=[Depends(require_owner)])
    def delete_environment_credential(identifier: str):
        runtime.environment_vault.remove(identifier)
        return {"removed": True}

    @app.post("/api/hooks/prompt-check", dependencies=[Depends(require_hook)])
    def prompt_check(body: PromptCheck):
        return runtime.environment_vault.check_prompt(body.prompt, body.harness)

    @app.post("/api/hooks/output-check", dependencies=[Depends(require_hook)])
    def output_check(body: OutputCheck):
        return runtime.environment_vault.check_prompt(body.text, body.harness, record=False)

    @app.post("/api/credentials", dependencies=[Depends(require_owner)])
    def create_credential(body: Credential):
        return runtime.broker.create(body.model_dump())

    @app.delete("/api/credentials/{identifier}", dependencies=[Depends(require_owner)])
    def delete_credential(identifier: str):
        runtime.broker.remove(identifier)
        return {"removed": True}

    @app.get("/api/approvals", dependencies=[Depends(require_owner)])
    def approvals():
        runtime.broker.expire()
        return {
            "items": runtime.store.rows(
                """SELECT r.id,r.credential_name,r.origin,r.path,r.state,r.created_at,
                   r.expires_at,g.name AS agent,g.project
                   FROM broker_requests r JOIN grants g ON g.id=r.grant_id
                   ORDER BY r.created_at DESC LIMIT 100"""
            )
        }

    @app.post("/api/approvals/{identifier}", dependencies=[Depends(require_owner)])
    def approve(identifier: str, body: Approval):
        return runtime.broker.approve(identifier, body.allow)

    @app.get("/api/agents", dependencies=[Depends(require_owner)])
    def agents():
        rows = runtime.store.rows(
            """SELECT id,name,project,credentials,created_at,revoked,kind,history_scope,approval_mode
               FROM grants ORDER BY created_at DESC"""
        )
        for row in rows:
            row["credentials"] = json.loads(row["credentials"])
        return {"items": rows}

    @app.post("/api/agents", dependencies=[Depends(require_owner)])
    def create_agent(body: Grant):
        return runtime.create_grant(**body.model_dump())

    @app.get("/api/agents/{identifier}/configuration", dependencies=[Depends(require_owner)])
    def agent_configuration(identifier: str):
        return runtime.grant_configuration(identifier)

    @app.delete("/api/agents/{identifier}", dependencies=[Depends(require_owner)])
    def revoke_agent(identifier: str):
        runtime.revoke_grant(identifier)
        return {"revoked": True}

    @app.get("/api/agent/status")
    def agent_status(grant=Depends(require_agent)):
        return {
            "id": grant["id"],
            "project": grant["project"],
            "kind": grant["kind"],
            "history_scope": grant["history_scope"],
            "approval_mode": grant["approval_mode"],
            "recording": runtime.store.settings()["recording"],
        }

    @app.get("/api/agent/sessions")
    def agent_sessions(limit: int = 20, offset: int = 0, grant=Depends(require_agent)):
        return runtime.environment_vault.model_history(
            runtime.store.sessions(project=history_project(grant), limit=limit, offset=offset)
        )

    @app.get("/api/agent/history/search")
    def agent_search_history(
        q: str = Query(min_length=1, max_length=200),
        source: str = Query(default="", max_length=80),
        limit: int = Query(default=20, ge=1, le=50),
        offset: int = Query(default=0, ge=0, le=100000),
        grant=Depends(require_agent),
    ):
        result = runtime.store.search_history(
            q,
            source=source,
            project=history_project(grant),
            limit=limit,
            offset=offset,
        )
        return runtime.environment_vault.model_history(result)

    @app.get("/api/agent/sessions/{identifier}")
    def agent_session(identifier: str, limit: int = 20, offset: int = 0, grant=Depends(require_agent)):
        result = runtime.store.session(identifier, project=history_project(grant))
        if not result:
            raise HTTPException(404, "Session is not available to this connection")
        messages = result["payload"]["chat_history"]
        result.pop("presentation", None)
        offset, limit = max(0, offset), min(max(1, limit), 50)
        result["payload"]["chat_history"] = messages[offset : offset + limit]
        result["page"] = {"offset": offset, "limit": limit, "total_messages": len(messages)}
        return runtime.environment_vault.model_history(result)

    @app.get("/api/agent/credentials")
    def agent_credentials(grant=Depends(require_agent)):
        if grant["kind"] in ("history", "context", "execution", "agent"):
            raise HTTPException(403, "History search does not grant credential access")
        permitted = json.loads(grant["credentials"])
        return {
            "items": [
                {key: item[key] for key in ("id", "name", "origin", "allowed_paths")}
                for item in runtime.broker.credentials()
                if item["id"] in permitted and item["state"] == "active"
            ]
        }

    @app.post("/api/agent/broker")
    def broker_request(body: BrokerRequest, grant=Depends(require_agent)):
        return runtime.broker.enqueue(grant, body.credential_id, body.path)

    @app.get("/api/agent/broker/{identifier}")
    def broker_result(identifier: str, grant=Depends(require_agent)):
        return runtime.broker.result(grant, identifier)

    @app.get("/api/agent/environment")
    def agent_environment(grant=Depends(require_agent)):
        return {
            "project": grant["project"],
            "variables": [
                {key: row[key] for key in ("id", "name", "env_name")}
                for row in runtime.environment_vault.permitted(grant)
            ],
            "instructions": (
                "Use $VARIABLE in adr_run_command. Its bash process and child code receive the values. "
                "In the unified ADR plugin all saved variables are available automatically. "
                "Supply your command's absolute cwd; there is no project-specific setup. "
                "Normal agent shells do not have these variables. Never ask for or print their values."
            ),
        }

    @app.post("/api/agent/environment/run")
    def environment_run(body: EnvironmentCommand, grant=Depends(require_agent)):
        return runtime.environment_vault.execute(grant, **body.model_dump())

    @app.get("/api/audit", dependencies=[Depends(require_owner)])
    def audit():
        return {"items": runtime.store.rows("SELECT * FROM audit ORDER BY id DESC LIMIT 100")}

    @app.post("/api/native/choose-path", dependencies=[Depends(require_owner)])
    async def choose_path():
        return await run_in_threadpool(runtime.native.call, "choose_path", {}, 120)

    @app.get("/api/native/login", dependencies=[Depends(require_owner)])
    async def login_status():
        if not runtime.native.connected:
            return {"available": False, "enabled": False}
        return await run_in_threadpool(runtime.native.call, "login_status")

    @app.post("/api/native/login", dependencies=[Depends(require_owner)])
    async def set_login(body: Approval):
        return await run_in_threadpool(runtime.native.call, "set_login", {"enabled": body.allow})

    for route in (
        "/",
        "/sessions",
        "/inventory",
        "/protection",
        "/threats",
        "/reviews",
        "/credentials",
        "/approvals",
        "/settings",
    ):
        app.add_api_route(route, lambda: FileResponse(web_dir / "index.html"), methods=["GET"])

    @app.get("/sessions/{identifier}")
    def session_page(identifier: str):
        return FileResponse(web_dir / "index.html")

    @app.get("/history")
    def old_history_page():
        return RedirectResponse("/sessions", status_code=307)

    @app.get("/assets/{name}")
    def asset(name: str):
        if name not in ("app.js", "styles.css", "sessions.css", "icon.svg"):
            raise HTTPException(404)
        return FileResponse(web_dir / name)

    return app
