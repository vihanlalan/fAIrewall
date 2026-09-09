"""HTTP Reverse Proxy and Inspection Gateway for autonomous AI agents."""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional

try:
    from fastapi import FastAPI, HTTPException, Header, Request, Response, status
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field
except ImportError as exc:  # pragma: no cover
    raise ImportError("fAIrewall proxy requires `pip install fairewall[proxy]`") from exc

from ..audit import AuditLog
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
) -> FastAPI:
    """Create a FastAPI application with firewall enforcement."""
    if firewall is None:
        p = policy or Policy()
        audit = AuditLog(path=audit_path) if audit_path else AuditLog()
        firewall = Firewall(policy=p, audit=audit, shadow=shadow)

    app = FastAPI(
        title="fAIrewall Gateway",
        description="Deterministic security firewall & reverse proxy for autonomous AI agents.",
        version="0.1.0",
    )

    upstream = upstream_url or os.environ.get("FAIREWALL_UPSTREAM_URL", "https://api.openai.com")

    @app.get("/health")
    async def health() -> Dict[str, Any]:
        return {
            "status": "ok",
            "version": "0.1.0",
            "shadow": firewall.shadow,
            "policy_version": firewall.policy.version,
            "policy_fingerprint": firewall.policy.fingerprint(),
            "audit_head": firewall.audit.head,
        }

    @app.post("/v1/inspect/input")
    async def inspect_input_endpoint(payload: InspectInputPayload) -> Dict[str, Any]:
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
    async def inspect_tool_endpoint(payload: InspectToolPayload) -> Dict[str, Any]:
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
    async def commit_tool_endpoint(payload: CommitToolPayload) -> Dict[str, Any]:
        ctx = firewall.session(session_id=payload.session_id)
        firewall.commit(tool=payload.tool, arguments=payload.arguments, ctx=ctx)
        return {"status": "committed", "tool": payload.tool, "session_id": ctx.session_id}

    @app.get("/v1/audit/verify")
    async def verify_audit_endpoint() -> Dict[str, Any]:
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

        # 3. Outbound inspection of tool calls emitted by the model
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

        return JSONResponse(content=resp_data, status_code=200)

    return app
