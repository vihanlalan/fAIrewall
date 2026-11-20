"""HTTP Reverse Proxy and Inspection Gateway for autonomous AI agents."""

from __future__ import annotations

import hmac
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

try:
    from fastapi import FastAPI, HTTPException, Header, Request, Response, status
    from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
    from pydantic import BaseModel, Field
except ImportError as exc:  # pragma: no cover
    raise ImportError("fAIrewall proxy requires `pip install fairewall[proxy]`") from exc

from ..approvals import ApprovalError, ApprovalQueue, ApprovalStatus, needs_human
from ..audit import AuditLog
from ..detectors import Detector
from ..firewall import Firewall, KillSwitchError
from ..policy import Policy
from ..types import Action, Context, Principal, Trust


_CONSOLE = Path(__file__).with_name("console.html")


class InspectInputPayload(BaseModel):
    text: str
    trust: str = "user"
    source: str = "input"
    session_id: Optional[str] = None


class InspectToolPayload(BaseModel):
    tool: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    session_id: Optional[str] = None
    principal_id: str = "anonymous"
    principal_roles: List[str] = Field(default_factory=list)
    # When true, a call that needs a person is held in the approval queue and
    # returned with allowed=false and an approval id to poll.
    hold_for_approval: bool = False


class InspectOutputPayload(BaseModel):
    tool: str
    output: str
    session_id: Optional[str] = None


class ReviewPayload(BaseModel):
    reviewer: str
    note: str = ""


class FreezePayload(BaseModel):
    # "all" stops every agent; "session" one run; "principal" one agent identity.
    scope: str = "all"
    target: Optional[str] = None
    reason: str = ""
    by: str = "operator"


class LabelPayload(BaseModel):
    verdict: str          # "malicious" or "benign"
    reviewer: str
    note: str = ""


class ScopePayload(BaseModel):
    tools: Optional[List[str]] = None
    destinations: Optional[List[str]] = None
    args: Optional[Dict[str, List[Any]]] = None
    max_spend: Optional[float] = None
    on_violation: str = "hold"
    expires_at: Optional[float] = None
    by: str = ""


class CanaryPayload(BaseModel):
    kind: str = "api_key"
    label: str = ""
    session_id: Optional[str] = None
    issued_by: str = ""


class BaselineSeedPayload(BaseModel):
    tool: str
    destinations: List[str] = Field(default_factory=list)
    max_amount: float = 0.0
    reviewer: str


class RevokePayload(BaseModel):
    reviewer: str
    reason: str = ""


class CommitToolPayload(BaseModel):
    tool: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    session_id: Optional[str] = None


def create_app(
    firewall: Optional[Firewall] = None,
    policy: Optional[Policy] = None,
    audit_path: Optional[str] = None,
    shadow: bool = False,
    upstream_url: Optional[str] = None,
    api_key: Optional[str] = None,
    detectors: Optional[Sequence[Detector]] = None,
    approvals: Optional[ApprovalQueue] = None,
    reviewer_api_key: Optional[str] = None,
    kill_switch_path: Optional[str] = None,
    learning: Optional[str] = None,
    source_sampling: bool = False,
    database: Optional[str] = None,
    action_baseline: Optional[str] = None,
    canaries: Optional[bool] = None,
) -> FastAPI:
    """Create a FastAPI application with firewall enforcement.

    Args:
        api_key: When set, all management endpoints (``/v1/inspect/*``,
            ``/v1/commit/tool``, ``/v1/audit/verify``) require the caller to
            supply this key via ``Authorization: Bearer <key>`` or
            ``X-API-Key: <key>``.  Falls back to the ``FAIREWALL_API_KEY``
            environment variable.  When neither is set the endpoints are
            unauthenticated (suitable for local development only).
        approvals: Approval queue for held tool calls. One is created when
            omitted. It lives in process memory.
        reviewer_api_key: Key required to list, approve or reject held calls
            (``/v1/approvals``). Falls back to ``FAIREWALL_REVIEWER_KEY``, then
            to ``api_key``. Give reviewers a different key from the agent's,
            so an agent holding the gateway key cannot approve its own calls.
        kill_switch_path: File that keeps kill-switch freezes across restarts.
            Falls back to ``FAIREWALL_KILL_SWITCH_FILE``. Without one, a
            restart lifts every freeze.
        learning: Where the adaptive threat memory keeps its cases and labels:
            a SQLite file or a postgresql:// URL (falls back to
            ``FAIREWALL_LEARNING_DB``). Unseen threats then go to a reviewer,
            and their decisions are learned (see fairewall.learning).
        source_sampling: Track content sources with Proof of Sampling (needs
            a database): new sources get every item deep-checked, trusted
            ones a sample (see fairewall.sampling).
        database: Shared state for running several instances (Cloud Run): a
            SQLite file or postgresql:// URL (falls back to
            ``FAIREWALL_DATABASE_URL``). Sessions, freezes, held approvals,
            the audit chain and learning then live there (see fairewall.state).
    """
    if firewall is None:
        from ..state import build_gateway_firewall
        firewall = build_gateway_firewall(
            policy=policy or Policy(), database=database, audit_path=audit_path,
            learning=learning, source_sampling=source_sampling, shadow=shadow,
            detectors=detectors, kill_switch_path=kill_switch_path,
            action_baseline=action_baseline, canaries=canaries)

    effective_api_key = api_key or os.environ.get("FAIREWALL_API_KEY")
    effective_reviewer_key = (reviewer_api_key or os.environ.get("FAIREWALL_REVIEWER_KEY")
                              or effective_api_key)
    if approvals is None:
        from ..state import queue_for
        approvals = queue_for(firewall)
    queue = approvals

    app = FastAPI(
        title="fAIrewall SDK Gateway",
        description="Enterprise AI governance SDK: deterministic security firewall & reverse proxy for autonomous AI agents.",
        version="0.2.0",
    )

    upstream = upstream_url or os.environ.get("FAIREWALL_UPSTREAM_URL", "https://api.openai.com")

    # ---------------------------------------------------------------------- auth

    def _supplied_key(authorization: Optional[str], x_api_key: Optional[str]) -> Optional[str]:
        bearer = None
        if authorization:
            parts = authorization.split(" ", 1)
            if len(parts) == 2 and parts[0].lower() == "bearer":
                bearer = parts[1]
        return bearer or x_api_key

    def _key_matches(supplied: Optional[str], expected: Optional[str]) -> bool:
        return bool(supplied and expected and hmac.compare_digest(supplied, expected))

    def _require_reviewer(authorization: Optional[str], x_api_key: Optional[str]) -> None:
        """Raise HTTP 401 unless the caller holds the reviewer key."""
        if not effective_reviewer_key:
            return  # no key configured: open access (local dev)
        if not _key_matches(_supplied_key(authorization, x_api_key), effective_reviewer_key):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Reviewer key required. Supply via 'Authorization: Bearer <key>' "
                       "or 'X-API-Key: <key>'.",
            )

    def _require_any_key(authorization: Optional[str], x_api_key: Optional[str]) -> None:
        """Raise HTTP 401 unless the caller holds the agent key or the reviewer key."""
        if not (effective_api_key or effective_reviewer_key):
            return
        supplied = _supplied_key(authorization, x_api_key)
        if not (_key_matches(supplied, effective_api_key)
                or _key_matches(supplied, effective_reviewer_key)):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Invalid or missing API key.")

    def _require_auth(authorization: Optional[str], x_api_key: Optional[str]) -> None:
        """Raise HTTP 401 if the request does not carry a valid API key."""
        if not effective_api_key:
            return  # no key configured → open access (local dev)
        supplied = _supplied_key(authorization, x_api_key)
        if not _key_matches(supplied, effective_api_key):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing API key. Supply via 'Authorization: Bearer <key>' "
                       "or 'X-API-Key: <key>'.",
            )

    def _control_status() -> Optional[Dict[str, Any]]:
        status_ = getattr(firewall, "control_status", None)
        if not status_:
            return None
        return {"managed": True, "ok": status_.get("ok"), "last_sync": status_.get("last_sync"),
                "policy": status_.get("policy")}

    @app.get("/health")
    async def health() -> Dict[str, Any]:
        return {
            "status": "ok",
            "version": "0.2.0",
            "shadow": firewall.shadow,
            "policy_version": firewall.policy.version,
            "policy_fingerprint": firewall.policy.fingerprint(),
            "audit_head": firewall.audit.head,
            "detectors": [d.name for d in firewall.detectors],
            # Public on purpose: a load balancer or on-call engineer should see
            # at a glance that agents are stopped. Who and why needs a key.
            "frozen": bool(firewall.freezes()),
            # Present only on gateways managed by a control plane.
            "control_plane": _control_status(),
        }

    @app.get("/v1/sdk/health")
    async def sdk_health() -> Dict[str, Any]:
        """SDK health — lists loaded platform adapters."""
        from .. import __version__ as SDK_VERSION
        from ..presets import list_presets
        mounted = [r.prefix for r in app.routes
                   if hasattr(r, 'prefix') and r.prefix.startswith('/v1/')]
        return {
            "status": "ok",
            "sdk_version": SDK_VERSION,
            "shadow": firewall.shadow,
            "policy_version": firewall.policy.version,
            "policy_fingerprint": firewall.policy.fingerprint(),
            "adapters_mounted": [p for p in mounted if p not in ('/v1/inspect', '/v1/commit', '/v1/audit', '/v1/chat', '/v1/sdk')],
            "audit_head": firewall.audit.head,
        }

    @app.get("/v1/sdk/presets")
    async def sdk_presets() -> Dict[str, Any]:
        """List all available policy presets."""
        from ..presets import list_presets
        return {"presets": list_presets()}

    @app.post("/v1/inspect/input")
    async def inspect_input_endpoint(
        payload: InspectInputPayload,
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        _require_auth(authorization, x_api_key)
        try:
            trust = Trust(payload.trust.lower())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid trust level '{payload.trust}'. Must be user, untrusted, or trusted.",
            )

        ctx = firewall.session(session_id=payload.session_id)
        decision = firewall.inspect_input(
            text=payload.text,
            trust=trust,
            ctx=ctx,
            source=payload.source,
        )
        return {
            "allowed": decision.allowed,
            "blocked": decision.blocked,
            "decision": decision.to_dict(),
            "tainted": ctx.tainted,
        }

    @app.post("/v1/inspect/tool")
    async def inspect_tool_endpoint(
        payload: InspectToolPayload,
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        _require_auth(authorization, x_api_key)
        principal = Principal(id=payload.principal_id, roles=payload.principal_roles)
        ctx = firewall.session(session_id=payload.session_id, principal=principal)
        with firewall.session_lock(ctx.session_id):
            decision = firewall.inspect(
                tool=payload.tool,
                arguments=payload.arguments,
                ctx=ctx,
            )
            if payload.hold_for_approval and not firewall.shadow and needs_human(decision):
                try:
                    req = queue.submit(payload.tool, payload.arguments, ctx, decision)
                except ApprovalError as exc:
                    return {"allowed": False, "blocked": True, "decision": decision.to_dict(),
                            "approval_error": str(exc)}
                # Held: the caller must wait for approval, then run the tool
                # and call /v1/commit/tool.
                return {
                    "allowed": False,
                    "blocked": False,
                    "pending_approval": True,
                    "approval": req.to_dict(),
                    "decision": decision.to_dict(),
                }
        return {
            "allowed": decision.allowed,
            "blocked": decision.blocked,
            "decision": decision.to_dict(),
        }

    @app.post("/v1/inspect/output")
    async def inspect_output_endpoint(
        payload: InspectOutputPayload,
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        """Screen a tool's output before the agent reads it. Pass the returned
        ``output`` to the agent: secrets in it are already redacted."""
        _require_auth(authorization, x_api_key)
        ctx = firewall.session(session_id=payload.session_id)
        decision, output = firewall.inspect_output(payload.tool, payload.output, ctx=ctx)
        return {
            "output": output,
            "redacted": output != payload.output,
            "tainted": ctx.tainted,
            "decision": decision.to_dict(),
        }

    # -------------------------------------------------------------- approvals

    @app.get("/v1/approvals")
    async def list_approvals(
        status_filter: Optional[str] = None,
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        """List held calls for reviewers. ?status_filter=pending|approved|rejected|expired."""
        _require_reviewer(authorization, x_api_key)
        wanted = None
        if status_filter:
            try:
                wanted = ApprovalStatus(status_filter.lower())
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail="status_filter must be pending, approved, rejected or expired")
        return {"approvals": [r.to_dict() for r in queue.list(wanted)]}

    @app.get("/v1/approvals/{request_id}")
    async def get_approval(
        request_id: str,
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        """Poll one request. Agents (gateway key) and reviewers (reviewer key) may read."""
        _require_any_key(authorization, x_api_key)
        req = queue.get(request_id)
        if req is None:
            raise HTTPException(status_code=404, detail="No approval request with that id")
        return req.to_dict()

    def _decide(request_id: str, payload: ReviewPayload, approve: bool) -> Dict[str, Any]:
        try:
            decide = queue.approve if approve else queue.reject
            req = decide(request_id, reviewer=payload.reviewer, note=payload.note)
        except ApprovalError as exc:
            code = 404 if "No approval request" in str(exc) else 409
            raise HTTPException(status_code=code, detail=str(exc))
        return req.to_dict()

    @app.post("/v1/approvals/{request_id}/approve")
    async def approve_endpoint(
        request_id: str,
        payload: ReviewPayload,
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        """Approve a held call. It is re-checked first; a call the policy now
        blocks comes back with status=rejected and decided_by=fairewall."""
        _require_reviewer(authorization, x_api_key)
        return _decide(request_id, payload, approve=True)

    @app.post("/v1/approvals/{request_id}/reject")
    async def reject_endpoint(
        request_id: str,
        payload: ReviewPayload,
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        _require_reviewer(authorization, x_api_key)
        return _decide(request_id, payload, approve=False)

    # --------------------------------------------------------------- learning

    def _memory():
        memory = getattr(firewall, "memory", None)
        if memory is None:
            raise HTTPException(status_code=404, detail="Learning is off. Start the gateway "
                                "with --learning-db (or FAIREWALL_LEARNING_DB).")
        return memory

    @app.get("/v1/learning/cases")
    async def learning_cases(
        status_filter: Optional[str] = "pending",
        limit: int = 100,
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        """Threats waiting for a person (default), or ?status_filter=labeled|revoked|expired|all."""
        _require_reviewer(authorization, x_api_key)
        wanted = None if (status_filter or "").lower() == "all" else status_filter
        return {"cases": _memory().cases(wanted, limit)}

    @app.get("/v1/learning/cases/{case_id}")
    async def learning_case(
        case_id: str,
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        _require_reviewer(authorization, x_api_key)
        from ..learning import LearningError
        try:
            return _memory().get(case_id).view()
        except LearningError as exc:
            raise HTTPException(status_code=404, detail=str(exc))

    @app.post("/v1/learning/cases/{case_id}")
    async def learning_label(
        case_id: str,
        payload: LabelPayload,
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        """Teach fAIrewall: this content was malicious, or benign. Reviewer key only."""
        _require_reviewer(authorization, x_api_key)
        from ..learning import LearningError
        try:
            return _memory().label(case_id, payload.verdict, payload.reviewer, payload.note,
                                   via="gateway")
        except LearningError as exc:
            raise HTTPException(status_code=404 if "No case" in str(exc) else 409, detail=str(exc))

    @app.post("/v1/learning/cases/{case_id}/revoke")
    async def learning_revoke(
        case_id: str,
        payload: RevokePayload,
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        """Withdraw a wrong label; fAIrewall retrains without it."""
        _require_reviewer(authorization, x_api_key)
        from ..learning import LearningError
        try:
            return _memory().revoke(case_id, payload.reviewer, payload.reason)
        except LearningError as exc:
            raise HTTPException(status_code=409, detail=str(exc))

    @app.get("/v1/learning/stats")
    async def learning_stats(
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        _require_any_key(authorization, x_api_key)
        return _memory().stats()

    @app.get("/v1/sources")
    async def sources(
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        """Content sources: status, earned stake and how often each is deep-checked."""
        _require_reviewer(authorization, x_api_key)
        sampler = getattr(firewall, "sampler", None)
        if sampler is None:
            raise HTTPException(status_code=404, detail="Source sampling is off.")
        return {"sources": sampler.list()}

    # ------------------------------------------------- run scope, canaries, baseline

    def _is_reviewer(authorization: Optional[str], x_api_key: Optional[str]) -> bool:
        if not effective_reviewer_key:
            return True
        return _key_matches(_supplied_key(authorization, x_api_key), effective_reviewer_key)

    @app.post("/v1/sessions/{session_id}/scope")
    async def set_scope(
        session_id: str,
        payload: ScopePayload,
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        """Declare what a run may do. Your backend sets it before the agent starts.

        The agent key may only narrow a scope; widening one needs the reviewer key.
        """
        _require_any_key(authorization, x_api_key)
        from ..rules.scope import ScopeError
        scope = payload.model_dump(exclude={"by"}, exclude_none=True)
        try:
            return firewall.set_scope(session_id, scope, widen=_is_reviewer(authorization, x_api_key)
                                      and effective_reviewer_key != effective_api_key, by=payload.by)
        except ScopeError as exc:
            raise HTTPException(status_code=403 if "reviewer" in str(exc) else 400, detail=str(exc))

    @app.get("/v1/sessions/{session_id}/scope")
    async def get_scope(
        session_id: str,
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        _require_any_key(authorization, x_api_key)
        return {"session_id": session_id, "scope": firewall.get_scope(session_id)}

    @app.post("/v1/canaries")
    async def issue_canary(
        payload: CanaryPayload,
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        """Create a decoy value to plant (reviewer key: the agent must never learn which values are decoys)."""
        _require_reviewer(authorization, x_api_key)
        if getattr(firewall, "canaries", None) is None:
            raise HTTPException(status_code=404, detail="Canaries are off. Start with --canaries.")
        try:
            return firewall.canaries.issue(payload.kind, label=payload.label,
                                           session_id=payload.session_id, issued_by=payload.issued_by)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.get("/v1/canaries")
    async def list_canaries(
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        _require_reviewer(authorization, x_api_key)
        if getattr(firewall, "canaries", None) is None:
            raise HTTPException(status_code=404, detail="Canaries are off. Start with --canaries.")
        return {"canaries": firewall.canaries.list()}

    @app.get("/v1/baseline/{principal}")
    async def baseline_profile(
        principal: str,
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        """What this agent normally does: tools, destinations, largest amounts."""
        _require_reviewer(authorization, x_api_key)
        if getattr(firewall, "baseline", None) is None:
            raise HTTPException(status_code=404, detail="The action baseline is off. Start with --action-baseline.")
        return firewall.baseline.profile(principal)

    @app.post("/v1/baseline/{principal}")
    async def baseline_seed(
        principal: str,
        payload: BaselineSeedPayload,
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        """Onboarding: tell fAIrewall what this agent is meant to do, so it isn't held for it."""
        _require_reviewer(authorization, x_api_key)
        if getattr(firewall, "baseline", None) is None:
            raise HTTPException(status_code=404, detail="The action baseline is off. Start with --action-baseline.")
        try:
            features = firewall.baseline.allow(principal, firewall.policy.canonical_tool(payload.tool),
                                               payload.destinations, payload.max_amount,
                                               by=payload.reviewer)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"principal": principal, "tool": payload.tool, "allowed": features}

    # ------------------------------------------------------------ kill switch

    @app.get("/v1/killswitch")
    async def killswitch_status(
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        """Active freezes. Readable with the agent key or the reviewer key."""
        _require_any_key(authorization, x_api_key)
        active = firewall.freezes()
        return {"frozen": bool(active), "freezes": active,
                "persistent": bool(firewall._kill_switch_path)}

    @app.post("/v1/killswitch/freeze")
    async def killswitch_freeze(
        payload: FreezePayload,
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        """Stop agents now. Either key may freeze: stopping is always safe, so an
        agent's own supervisor holding only the gateway key can pull the switch."""
        _require_any_key(authorization, x_api_key)
        try:
            record = firewall.freeze(payload.scope, payload.target, payload.reason, payload.by)
        except KillSwitchError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"frozen": True, "freeze": record, "freezes": firewall.freezes()}

    @app.post("/v1/killswitch/unfreeze")
    async def killswitch_unfreeze(
        payload: FreezePayload,
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        """Lift a freeze. Needs the reviewer key, so an agent holding the gateway
        key cannot restart itself after an operator stopped it."""
        _require_reviewer(authorization, x_api_key)
        try:
            released = firewall.unfreeze(payload.scope, payload.target, payload.by)
        except KillSwitchError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if not released:
            raise HTTPException(status_code=404, detail="Nothing is frozen at that scope.")
        active = firewall.freezes()
        return {"released": True, "frozen": bool(active), "freezes": active}

    @app.post("/v1/commit/tool")
    async def commit_tool_endpoint(
        payload: CommitToolPayload,
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        _require_auth(authorization, x_api_key)
        ctx = firewall.session(session_id=payload.session_id)
        firewall.commit(tool=payload.tool, arguments=payload.arguments, ctx=ctx)
        return {"status": "committed", "tool": payload.tool, "session_id": ctx.session_id}

    # ---------------------------------------------------------------- console

    @app.get("/", include_in_schema=False)
    async def root() -> RedirectResponse:
        return RedirectResponse("/console")

    @app.get("/console", response_class=HTMLResponse, include_in_schema=False)
    async def console() -> HTMLResponse:
        """Operator console. The page itself holds no data; every panel calls the
        authenticated API with the key the operator types in."""
        return HTMLResponse(_CONSOLE.read_text(encoding="utf-8"))

    @app.get("/v1/console/info")
    async def console_info() -> Dict[str, Any]:
        """What the console needs before login: is auth on, and is a reviewer key set."""
        return {
            "auth_required": bool(effective_api_key),
            "separate_reviewer_key": bool(effective_reviewer_key)
            and effective_reviewer_key != effective_api_key,
            "shadow": firewall.shadow,
            "version": "0.2.0",
        }

    @app.get("/v1/policy")
    async def policy_endpoint(
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        """The active policy, as JSON, with its fingerprint."""
        _require_auth(authorization, x_api_key)
        return {"fingerprint": firewall.policy.fingerprint(), "policy": firewall.policy.to_dict()}

    @app.get("/v1/audit/recent")
    async def audit_recent(
        limit: int = 50,
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        """The newest audit records, newest first, for the live decision feed."""
        _require_auth(authorization, x_api_key)
        records = firewall.audit.records()
        tail = records[-max(1, min(limit, 500)):]
        rows = [{
            "seq": r.get("seq"), "event": r.get("event"), "tool": r.get("tool"),
            "action": r.get("action") or r.get("status"), "session_id": r.get("session_id"),
            "principal": r.get("principal"), "timestamp": r.get("timestamp"),
            "latency_ms": r.get("latency_ms"), "route": r.get("route"),
            "findings": [{"rule_id": f.get("rule_id"), "action": f.get("action"),
                          "message": f.get("message")} for f in (r.get("findings") or [])],
        } for r in reversed(tail)]
        return {"records": rows, "total": len(records), "head": firewall.audit.head}

    @app.get("/v1/audit/verify")
    async def verify_audit_endpoint(
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        _require_auth(authorization, x_api_key)
        verification = firewall.audit.verify()
        return {
            "valid": verification.valid,
            "checked": verification.checked,
            "broken_at": verification.broken_at,
            "reason": verification.reason,
            "head": firewall.audit.head,
        }

    @app.post("/v1/chat/completions")
    async def chat_completions_proxy(
        request: Request,
        x_session_id: Optional[str] = Header(None),
        x_principal_id: Optional[str] = Header("anonymous"),
        x_principal_roles: Optional[str] = Header(""),
    ) -> Response:
        """Reverse proxy for chat completions with inbound and outbound firewall checks."""
        roles = [r.strip() for r in (x_principal_roles or "").split(",") if r.strip()]
        principal = Principal(id=x_principal_id or "anonymous", roles=roles)
        ctx = firewall.session(session_id=x_session_id, principal=principal)

        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")

        # 0. Kill switch: a frozen agent gets no model reply at all.
        freeze = firewall.frozen_for(ctx)
        if freeze is not None:
            decision = firewall.inspect("<chat>", {}, ctx=ctx)  # logs the refusal
            return JSONResponse(
                status_code=423,
                content={"error": {"message": decision.reason, "type": "fairewall_kill_switch",
                                   "decision": decision.to_dict()}},
            )

        messages = body.get("messages", [])
        # Redact credentials and personal data from every tool result before it
        # is forwarded, so the model provider never receives them. Pure and
        # cheap, so it runs over the whole history, not only the newest turns.
        for msg in messages:
            if (isinstance(msg, dict) and msg.get("role") in ("tool", "function")
                    and isinstance(msg.get("content"), str) and msg["content"]):
                clean, _secrets, _pii = firewall.redact_text(msg["content"], msg.get("name"))
                msg["content"] = clean

        # 1. Inbound check on newest messages
        for msg in messages[-2:]:
            role = msg.get("role", "")
            content = msg.get("content", "")
            if isinstance(content, str) and content:
                # Tool outputs are UNTRUSTED by default
                msg_trust = Trust.UNTRUSTED if role in ("tool", "function") else Trust.USER
                inbound_decision = firewall.inspect_input(
                    text=content,
                    trust=msg_trust,
                    ctx=ctx,
                    source=f"chat_{role}",
                )
                if inbound_decision.blocked:
                    return JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content={
                            "error": {
                                "message": f"Inbound message blocked: {inbound_decision.reason}",
                                "type": "fairewall_inbound_block",
                                "decision": inbound_decision.to_dict(),
                            }
                        },
                    )

        # 2. Forward to upstream LLM API using httpx if available
        try:
            import httpx  # type: ignore
        except ImportError:
            raise HTTPException(
                status_code=500,
                detail="httpx is required to proxy requests to upstream LLM.",
            )

        # Forward headers (excluding Host)
        headers = dict(request.headers)
        headers.pop("host", None)
        target_url = f"{upstream.rstrip('/')}/v1/chat/completions"

        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                upstream_resp = await client.post(
                    target_url,
                    json=body,
                    headers={k: v for k, v in headers.items() if not k.startswith("x-")},
                )
            except Exception as exc:
                raise HTTPException(status_code=502, detail=f"Upstream request failed: {exc}")

        if upstream_resp.status_code != 200:
            return Response(
                content=upstream_resp.content,
                status_code=upstream_resp.status_code,
                headers=dict(upstream_resp.headers),
            )

        resp_data = upstream_resp.json()

        # 3. Outbound inspection of tool calls emitted by the model.
        #    Commit each allowed call so session spend and velocity windows
        #    advance correctly.  (Without commit(), budget/rate limits are
        #    silently never enforced through the proxy route.)
        choices = resp_data.get("choices", [])
        for choice in choices:
            message = choice.get("message", {})
            tool_calls = message.get("tool_calls", [])
            for tc in tool_calls:
                fn = tc.get("function", {})
                tool_name = fn.get("name", "")
                raw_args = fn.get("arguments", "{}")
                try:
                    tool_args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                except Exception:
                    tool_args = {"raw": raw_args}

                outbound_decision = firewall.inspect(
                    tool=tool_name,
                    arguments=tool_args,
                    ctx=ctx,
                )

                if outbound_decision.blocked:
                    killed = any(f.rule_id == "killswitch.frozen"
                                 for f in outbound_decision.findings)
                    if firewall.shadow and not killed:
                        # Logged already by inspect; let pass in shadow mode
                        continue
                    # Circuit breaker triggered! Replace tool call with refusal or block response
                    return JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content={
                            "error": {
                                "message": f"Tool call blocked by fAIrewall: {outbound_decision.reason}",
                                "type": "fairewall_circuit_breaker",
                                "tool": tool_name,
                                "decision": outbound_decision.to_dict(),
                            }
                        },
                    )

                # Commit the allowed tool call so budgets and rate limits advance.
                firewall.commit(tool=tool_name, arguments=tool_args, ctx=ctx)
                # Taint the session if the tool's policy marks it as producing
                # untrusted output (e.g. a web-search or external fetch tool).
                tool_policy = firewall.policy.tool(tool_name)
                if tool_policy and getattr(tool_policy, "produces_untrusted_output", False):
                    ctx.taint(tool_name)

        return JSONResponse(content=resp_data, status_code=200)

    from ..ui import mount_console
    mount_console(app, durable=False)
    return app
