"""HTTP Reverse Proxy and Inspection Gateway for autonomous AI agents."""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional, Sequence

try:
    from fastapi import FastAPI, HTTPException, Header, Request, Response, status
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field
except ImportError as exc:  # pragma: no cover
    raise ImportError("fAIrewall proxy requires `pip install fairewall[proxy]`") from exc

from ..audit import AuditLog
from ..detectors import Detector
from ..firewall import Firewall
from ..policy import Policy
from ..types import Action, Context, Principal, Trust


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
) -> FastAPI:
    """Create a FastAPI application with firewall enforcement.

    Args:
        api_key: When set, all management endpoints (``/v1/inspect/*``,
            ``/v1/commit/tool``, ``/v1/audit/verify``) require the caller to
            supply this key via ``Authorization: Bearer <key>`` or
            ``X-API-Key: <key>``.  Falls back to the ``FAIREWALL_API_KEY``
            environment variable.  When neither is set the endpoints are
            unauthenticated (suitable for local development only).
    """
    if firewall is None:
        p = policy or Policy()
        audit = AuditLog(path=audit_path) if audit_path else AuditLog()
        firewall = Firewall(policy=p, audit=audit, shadow=shadow, detectors=detectors)

    effective_api_key = api_key or os.environ.get("FAIREWALL_API_KEY")

    app = FastAPI(
        title="fAIrewall SDK Gateway",
        description="Enterprise AI governance SDK: deterministic security firewall & reverse proxy for autonomous AI agents.",
        version="0.2.0",
    )

    upstream = upstream_url or os.environ.get("FAIREWALL_UPSTREAM_URL", "https://api.openai.com")

    # ---------------------------------------------------------------------- auth

    def _require_auth(authorization: Optional[str], x_api_key: Optional[str]) -> None:
        """Raise HTTP 401 if the request does not carry a valid API key."""
        if not effective_api_key:
            return  # no key configured → open access (local dev)
        bearer = None
        if authorization:
            parts = authorization.split(" ", 1)
            if len(parts) == 2 and parts[0].lower() == "bearer":
                bearer = parts[1]
        supplied = bearer or x_api_key
        if supplied != effective_api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing API key. Supply via 'Authorization: Bearer <key>' "
                       "or 'X-API-Key: <key>'.",
            )

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
        decision = firewall.inspect(
            tool=payload.tool,
            arguments=payload.arguments,
            ctx=ctx,
        )
        return {
            "allowed": decision.allowed,
            "blocked": decision.blocked,
            "decision": decision.to_dict(),
        }

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

        messages = body.get("messages", [])
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
                    if firewall.shadow:
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

    return app
