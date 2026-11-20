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
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

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
        jwks_provider: Optional[Callable[[], Dict[str, Any]]] = None,
    ) -> None:
        if not _FASTAPI_AVAILABLE:
            raise ImportError(
                "CopilotAdapter requires `pip install fairewall[copilot]`"
            )
        if validate_jwt and not (tenant_id and audience):
            raise ValueError(
                "CopilotAdapter(validate_jwt=True) needs both tenant_id and audience; "
                "pass validate_jwt=False only for local development."
            )
        self.sdk = sdk
        self.validate_jwt = validate_jwt
        self.tenant_id = tenant_id
        self.audience = audience
        # Injectable so tests (and air-gapped deployments) can supply keys.
        self._jwks_provider = jwks_provider or self._fetch_azure_jwks
        self._jwks_cache: Optional[Tuple[float, Dict[str, Any]]] = None
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
            from jose import jwt  # type: ignore
            issuer = f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"
            claims = jwt.decode(
                token,
                self._jwks(),
                algorithms=["RS256"],
                audience=self.audience,
                issuer=issuer,
            )
        except Exception as exc:
            # Fail closed: a token we cannot verify is a token we do not trust.
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid bearer token (%s)." % type(exc).__name__,
            ) from exc
        return claims.get("oid") or claims.get("sub")

    def _jwks(self) -> Dict[str, Any]:
        """Signing keys, cached for an hour."""
        now = time.time()
        if self._jwks_cache and now - self._jwks_cache[0] < 3600:
            return self._jwks_cache[1]
        keys = self._jwks_provider()
        self._jwks_cache = (now, keys)
        return keys

    def _fetch_azure_jwks(self) -> Dict[str, Any]:
        import json as _json
        import urllib.request

        url = "https://login.microsoftonline.com/%s/discovery/v2.0/keys" % self.tenant_id
        with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310 - fixed https host
            return _json.loads(resp.read().decode("utf-8"))

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
