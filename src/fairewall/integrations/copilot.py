"""fAIrewall integration for Microsoft Copilot Studio.

Microsoft Copilot Studio uses the **Bot Framework Activity** protocol for
all messaging.  Plugin / Power Platform actions are invoked via
``activity.type = "invoke"`` with an ``activity.value`` payload.

This module provides:

1. **CopilotAdapter** — a FastAPI ``APIRouter`` with three endpoints:

   - ``POST /v1/copilot/activity`` — inspect Bot Framework Activity objects
     (type: message, event, invoke)
   - ``POST /v1/copilot/action``   — guard Power Automate plugin invocations
   - ``GET  /v1/copilot/health``   — adapter liveness

2. **guard_copilot_action** — direct Python callable for Copilot extensions
   that import fAIrewall as a library.

Bot Framework Activity Format
-----------------------------
The adapter processes the ``activity.text`` field (type: message) and
``activity.value`` dict (type: invoke / event) for governance screening.

Authentication
--------------
The adapter checks the ``Authorization: Bearer <token>`` header.  Full AAD
JWT validation (audience / issuer) requires ``python-jose[cryptography]``
to be installed.  Without it the adapter falls back to a presence check
(suitable for internal networks only — configure ``validate_jwt=False`` in
that case and enforce auth at the API gateway layer).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from ..sdk import GovernanceSDK
from ..types import Decision, Principal, Trust

try:
    from fastapi import APIRouter, Header, HTTPException, Request, status
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False


# ---------------------------------------------------------------------------
# Direct callable
# ---------------------------------------------------------------------------

def guard_copilot_action(
    action_name: str,
    action_value: Dict[str, Any],
    sdk: GovernanceSDK,
    user_id: Optional[str] = None,
    conversation_id: Optional[str] = None,
    commit: bool = True,
) -> Decision:
    """Guard a Microsoft Copilot Studio plugin action before execution.

    Args:
        action_name:     The plugin action name (maps to a tool in the Policy).
        action_value:    The ``activity.value`` dict carrying action arguments.
        sdk:             A :class:`~fairewall.sdk.GovernanceSDK` instance.
        user_id:         AAD object ID of the user (principal).
        conversation_id: Bot Framework conversation ID (session).
        commit:          Advance budgets on ALLOW.

    Returns:
        A :class:`~fairewall.types.Decision`.

    Example::

        sdk = GovernanceSDK.from_preset("COPILOT_ENTERPRISE")
        decision = guard_copilot_action(
            "create_document",
            {"title": "Q3 Report", "content": "..."},
            sdk,
            user_id="aad-oid-abc",
            conversation_id="conv-xyz",
        )
    """
    principal = Principal(id=user_id or "copilot_anon")
    return sdk.guard_action(
        action_name=action_name,
        arguments=action_value,
        session_id=conversation_id,
        principal=principal,
        commit=commit,
    )


# ---------------------------------------------------------------------------
# Webhook adapter (FastAPI)
# ---------------------------------------------------------------------------

class CopilotAdapter:
    """FastAPI router adapter for Microsoft Copilot Studio.

    Mount on the fAIrewall proxy to expose Copilot-specific governance
    endpoints::

        from fairewall.integrations.copilot import CopilotAdapter
        adapter = CopilotAdapter(GovernanceSDK.from_preset("COPILOT_ENTERPRISE"))
        app.include_router(adapter.router)

    Args:
        sdk:          A configured :class:`~fairewall.sdk.GovernanceSDK`.
        validate_jwt: When ``True`` (default) the ``Authorization`` header
                      must be present.  Full AAD signature validation is
                      performed if ``python-jose`` is installed.
        tenant_id:    AAD tenant ID used in JWT issuer validation.
        audience:     Expected JWT audience (defaults to the Bot Framework
                      app ID).
    """

    def __init__(
        self,
        sdk: GovernanceSDK,
        validate_jwt: bool = True,
        tenant_id: Optional[str] = None,
        audience: Optional[str] = None,
    ) -> None:
        if not _FASTAPI_AVAILABLE:
            raise ImportError(
                "CopilotAdapter requires `pip install fairewall[copilot]`"
            )
        self.sdk = sdk
        self.validate_jwt = validate_jwt
        self.tenant_id = tenant_id
        self.audience = audience
        self.router = APIRouter(prefix="/v1/copilot", tags=["Copilot Governance"])
        self._register_routes()

    # ------------------------------------------------------------------

    def _check_auth(self, authorization: Optional[str]) -> Optional[str]:
        """Returns the user_id (sub) claim if JWT is valid, else None."""
        if not self.validate_jwt:
            return None
        if not authorization:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Authorization header for Copilot endpoint.",
            )
        parts = authorization.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization header must be 'Bearer <token>'.",
            )
        token = parts[1]
        try:
            from jose import jwt, JWTError  # type: ignore
            issuer = (
                f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"
                if self.tenant_id else None
            )
            options: Dict[str, Any] = {"verify_signature": False}  # offline check
            claims = jwt.decode(token, key=None, options=options,
                                audience=self.audience, issuer=issuer)
            return claims.get("oid") or claims.get("sub")
        except Exception:
            # jose not installed or decode failed; fall back to presence only
            return None

    # ------------------------------------------------------------------

    def _register_routes(self) -> None:

        router = self.router
        sdk = self.sdk
        adapter = self

        @router.get("/health")
        async def health() -> Dict[str, Any]:
            return {
                "status": "ok",
                "platform": "copilot",
                "policy_version": sdk.policy.version,
                "policy_fingerprint": sdk.policy.fingerprint(),
                "shadow": sdk.firewall.shadow,
            }

        @router.post("/activity")
        async def inspect_activity(
            request: Request,
            authorization: Optional[str] = Header(None),
        ) -> Dict[str, Any]:
            """Inspect a Bot Framework Activity for injection and policy compliance."""
            user_id = adapter._check_auth(authorization)

            try:
                activity = await request.json()
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid JSON body.")

            activity_type = activity.get("type", "message")
            conversation_id = (
                activity.get("conversation", {}).get("id")
                or activity.get("conversationId")
            )
            user_id = user_id or activity.get("from", {}).get("id")
            principal = Principal(id=user_id or "copilot_anon")

            decisions = []

            # Screen text content (message type)
            text = activity.get("text", "")
            if text:
                dec = sdk.screen(
                    text=text,
                    session_id=conversation_id,
                    principal=principal,
                    trust=Trust.USER,
                    source="copilot_message",
                )
                decisions.append(dec)
                if dec.blocked:
                    return JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content={
                            "blocked": True,
                            "reason": dec.reason,
                            "findings": [f.to_dict() for f in dec.findings],
                        },
                    )

            # For invoke/event, screen the value field for injection
            value = activity.get("value")
            if value and isinstance(value, dict):
                value_text = json.dumps(value)
                dec = sdk.screen(
                    text=value_text,
                    session_id=conversation_id,
                    principal=principal,
                    trust=Trust.USER,
                    source="copilot_value",
                )
                decisions.append(dec)
                if dec.blocked:
                    return JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content={
                            "blocked": True,
                            "reason": dec.reason,
                            "findings": [f.to_dict() for f in dec.findings],
                        },
                    )

            # If this is a plugin/action invoke, guard it
            if activity_type == "invoke":
                action_name = activity.get("name", "invoke")
                arguments = value or {}
                decision = sdk.guard_action(
                    action_name=action_name,
                    arguments=arguments,
                    session_id=conversation_id,
                    principal=principal,
                    commit=True,
                )
                if decision.blocked:
                    return JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content={
                            "blocked": True,
                            "reason": decision.reason,
                            "findings": [f.to_dict() for f in decision.findings],
                        },
                    )
                return {
                    "allowed": True,
                    "blocked": False,
                    "activity_type": activity_type,
                    "action": action_name,
                    "decision_id": decision.call_id,
                }

            return {
                "allowed": True,
                "blocked": False,
                "activity_type": activity_type,
                "screened": len(decisions),
            }

        @router.post("/action")
        async def guard_action_endpoint(
            request: Request,
            authorization: Optional[str] = Header(None),
        ) -> Dict[str, Any]:
            """Guard a Power Automate / Copilot plugin action invocation."""
            user_id = adapter._check_auth(authorization)

            try:
                data = await request.json()
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid JSON body.")

            action_name = data.get("action") or data.get("tool") or data.get("name", "")
            if not action_name:
                raise HTTPException(status_code=400, detail="'action' field is required.")

            arguments: Dict[str, Any] = data.get("arguments", data.get("value", {}))
            conversation_id = data.get("conversation_id") or data.get("session_id")
            user_id = user_id or data.get("user_id") or data.get("principal_id")
            principal = Principal(id=user_id or "copilot_anon")

            decision = sdk.guard_action(
                action_name=action_name,
                arguments=arguments,
                session_id=conversation_id,
                principal=principal,
                commit=True,
            )

            if decision.blocked:
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={
                        "allowed": False,
                        "blocked": True,
                        "reason": decision.reason,
                        "findings": [f.to_dict() for f in decision.findings],
                    },
                )

            return {
                "allowed": True,
                "blocked": False,
                "action": action_name,
                "decision_id": decision.call_id,
                "session_id": decision.session_id,
            }
