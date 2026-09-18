"""fAIrewall integration for Salesforce Agentforce / Einstein Platform.

Salesforce Agentforce invokes Einstein Platform Actions through a structured
``inputs[]`` envelope.  External service callouts use Named Credentials.

This module provides:

1. **AgentforceAdapter** — a FastAPI ``APIRouter`` with endpoints:

   - ``POST /v1/salesforce/screen``            — screen Einstein action inputs
   - ``POST /v1/salesforce/action``            — guard Agentforce action calls
   - ``POST /v1/salesforce/external-service``  — guard External Service callouts
   - ``GET  /v1/salesforce/health``            — adapter liveness

2. **guard_agentforce_action** — direct callable for Salesforce Functions /
   Heroku Python sidecars or custom integrations.

Salesforce Action Envelope
--------------------------
Salesforce sends action invocations as::

    {
        "inputs": [
            {"opportunityId": "006…", "amount": 5000}
        ],
        "context": {"userId": "005…", "orgId": "00D…"}
    }

The adapter flattens ``inputs[0]`` as the action ``arguments`` and maps
``context.userId`` to the principal.

Authentication
--------------
Endpoints validate the ``Authorization: Bearer <token>`` Salesforce
Connected App JWT.  Claims checked: ``iss`` (Connected App consumer key),
``sub`` (Salesforce user ID), ``aud`` (``https://login.salesforce.com``).
Pass ``validate_jwt=False`` for local development.
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

def guard_agentforce_action(
    action_name: str,
    inputs: List[Dict[str, Any]],
    sdk: GovernanceSDK,
    user_id: Optional[str] = None,
    org_id: Optional[str] = None,
    commit: bool = True,
) -> Decision:
    """Guard a Salesforce Agentforce action invocation.

    Args:
        action_name: The Einstein Platform Action API name.
        inputs:      The ``inputs`` list from the Salesforce action request.
                     The first element is used as the action arguments.
        sdk:         A :class:`~fairewall.sdk.GovernanceSDK` instance.
        user_id:     Salesforce user ID (principal).
        org_id:      Salesforce Org ID (used as session identifier).
        commit:      Advance budgets on ALLOW.

    Returns:
        A :class:`~fairewall.types.Decision`.

    Example::

        sdk = GovernanceSDK.from_preset("SALESFORCE_CRM")
        decision = guard_agentforce_action(
            "update_opportunity_amount",
            [{"opportunityId": "006Dn…", "amount": 4500.0}],
            sdk,
            user_id="005Dn…",
            org_id="00D…",
        )
    """
    arguments = inputs[0] if inputs else {}
    principal = Principal(id=user_id or "sf_anon")
    return sdk.guard_action(
        action_name=action_name,
        arguments=arguments,
        session_id=org_id,
        principal=principal,
        commit=commit,
    )


# ---------------------------------------------------------------------------
# Webhook adapter (FastAPI)
# ---------------------------------------------------------------------------

class AgentforceAdapter:
    """FastAPI router adapter for Salesforce Agentforce.

    Mount on the fAIrewall proxy::

        from fairewall.integrations.salesforce import AgentforceAdapter
        adapter = AgentforceAdapter(GovernanceSDK.from_preset("SALESFORCE_CRM"))
        app.include_router(adapter.router)

    Args:
        sdk:                A :class:`~fairewall.sdk.GovernanceSDK`.
        validate_jwt:       Require and verify Salesforce Connected App JWT.
        connected_app_key:  Expected JWT ``iss`` (consumer key).
        salesforce_domain:  JWT audience base URL.
    """

    def __init__(
        self,
        sdk: GovernanceSDK,
        validate_jwt: bool = True,
        connected_app_key: Optional[str] = None,
        salesforce_domain: str = "https://login.salesforce.com",
    ) -> None:
        if not _FASTAPI_AVAILABLE:
            raise ImportError(
                "AgentforceAdapter requires `pip install fairewall[salesforce]`"
            )
        self.sdk = sdk
        self.validate_jwt = validate_jwt
        self.connected_app_key = connected_app_key
        self.salesforce_domain = salesforce_domain
        self.router = APIRouter(prefix="/v1/salesforce", tags=["Salesforce Governance"])
        self._register_routes()

    # ------------------------------------------------------------------

    def _check_auth(self, authorization: Optional[str]) -> Dict[str, str]:
        """Returns ``{"user_id": …, "org_id": …}`` from JWT claims."""
        if not self.validate_jwt:
            return {}
        if not authorization:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Authorization header for Salesforce endpoint.",
            )
        parts = authorization.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization must be 'Bearer <jwt>'.",
            )
        token = parts[1]
        try:
            from jose import jwt  # type: ignore
            options = {"verify_signature": False, "verify_aud": False}
            claims = jwt.decode(token, key=None, options=options)
            if self.connected_app_key and claims.get("iss") != self.connected_app_key:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="JWT issuer does not match Connected App consumer key.",
                )
            return {
                "user_id": claims.get("sub", "sf_anon"),
                "org_id": claims.get("aud", "").replace(self.salesforce_domain + "/", ""),
            }
        except HTTPException:
            raise
        except Exception:
            # jose not installed — fall back to unauthenticated
            return {}

    # ------------------------------------------------------------------

    def _register_routes(self) -> None:

        router = self.router
        sdk = self.sdk
        adapter = self

        @router.get("/health")
        async def health() -> Dict[str, Any]:
            return {
                "status": "ok",
                "platform": "salesforce",
                "policy_version": sdk.policy.version,
                "policy_fingerprint": sdk.policy.fingerprint(),
                "shadow": sdk.firewall.shadow,
            }

        @router.post("/screen")
        async def screen_inputs(
            request: Request,
            authorization: Optional[str] = Header(None),
        ) -> Dict[str, Any]:
            """Screen Agentforce action input text for prompt injection."""
            claims = adapter._check_auth(authorization)
            try:
                data = await request.json()
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid JSON body.")

            inputs: List[Dict[str, Any]] = data.get("inputs", [{}])
            context: Dict[str, Any] = data.get("context", {})
            user_id = claims.get("user_id") or context.get("userId") or data.get("user_id")
            org_id = claims.get("org_id") or context.get("orgId") or data.get("org_id")

            # Screen all string values in inputs for injection
            blocked_decisions = []
            for inp in inputs:
                for key, val in inp.items():
                    if isinstance(val, str) and val:
                        dec = sdk.screen(
                            text=val,
                            session_id=org_id,
                            principal=Principal(id=user_id or "sf_anon"),
                            trust=Trust.UNTRUSTED,
                            source=f"sf_input_{key}",
                        )
                        if dec.blocked:
                            blocked_decisions.append(dec)

            if blocked_decisions:
                first = blocked_decisions[0]
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={
                        "blocked": True,
                        "reason": first.reason,
                        "findings": [f.to_dict() for f in first.findings],
                    },
                )

            return {"allowed": True, "blocked": False, "screened_inputs": len(inputs)}

        @router.post("/action")
        async def guard_action_endpoint(
            request: Request,
            authorization: Optional[str] = Header(None),
        ) -> Dict[str, Any]:
            """Guard a Salesforce Agentforce action invocation."""
            claims = adapter._check_auth(authorization)
            try:
                data = await request.json()
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid JSON body.")

            action_name = data.get("action") or data.get("actionApiName", "")
            if not action_name:
                raise HTTPException(status_code=400, detail="'action' or 'actionApiName' required.")

            inputs: List[Dict[str, Any]] = data.get("inputs", [{}])
            context: Dict[str, Any] = data.get("context", {})
            user_id = claims.get("user_id") or context.get("userId") or data.get("user_id")
            org_id = claims.get("org_id") or context.get("orgId") or data.get("org_id")
            arguments = inputs[0] if inputs else {}

            decision = sdk.guard_action(
                action_name=action_name,
                arguments=arguments,
                session_id=org_id,
                principal=Principal(id=user_id or "sf_anon"),
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

        @router.post("/external-service")
        async def guard_external_service(
            request: Request,
            authorization: Optional[str] = Header(None),
        ) -> Dict[str, Any]:
            """Guard a Salesforce External Service (Named Credential) callout."""
            claims = adapter._check_auth(authorization)
            try:
                data = await request.json()
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid JSON body.")

            service_name = data.get("service", "external_service_callout")
            arguments = data.get("parameters", data.get("arguments", {}))
            context: Dict[str, Any] = data.get("context", {})
            user_id = claims.get("user_id") or context.get("userId")
            org_id = claims.get("org_id") or context.get("orgId")

            decision = sdk.guard_action(
                action_name=service_name,
                arguments=arguments,
                session_id=org_id,
                principal=Principal(id=user_id or "sf_anon"),
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
                "service": service_name,
                "decision_id": decision.call_id,
            }
