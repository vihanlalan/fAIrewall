"""fAIrewall integration for Zapier Agents.

Zapier Agents invoke actions via HTTP webhooks using a simple JSON envelope
format.  This module provides two integration points:

1. **ZapierWebhookAdapter** — a FastAPI ``APIRouter`` with four endpoints
   that you mount on the shared fAIrewall proxy:

   - ``POST /v1/zapier/screen``   — screen inbound trigger payloads
   - ``POST /v1/zapier/action``   — guard Zap action invocations
   - ``GET  /v1/zapier/audit``    — last N audit records
   - ``GET  /v1/zapier/health``   — adapter liveness

2. **guard_zapier_action** — a direct Python callable for embedding in
   custom Zapier Code steps or Python scripts.

Signature Verification
----------------------
All webhook endpoints verify the ``X-Zapier-Secret`` header against the
secret supplied at adapter construction time (HMAC-SHA256 over the raw
request body).  Set ``verify_signature=False`` only in local development.

Envelope Format
---------------
Zapier sends action payloads as::

    {
        "inputData": {"amount": 150, "order_id": "X"},
        "meta":      {"zap_id": "...", "user_id": "...", "step": "..."}
    }

The adapter extracts ``inputData`` as the action's ``arguments`` and
``meta.zap_id`` + ``meta.user_id`` as the session and principal identifiers.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Dict, List, Optional

from ..firewall import Firewall
from ..policy import Policy
from ..presets import load_preset
from ..sdk import GovernanceSDK
from ..types import Context, Decision, Principal, Trust

try:
    from fastapi import APIRouter, Header, HTTPException, Request, status
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

if _FASTAPI_AVAILABLE:
    class ZapierScreenPayload(BaseModel):
        text: str
        zap_id: Optional[str] = None
        user_id: Optional[str] = None
        source: str = "zapier_trigger"

    class ZapierActionPayload(BaseModel):
        action: str
        inputData: Dict[str, Any] = Field(default_factory=dict)
        meta: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Direct callable integration
# ---------------------------------------------------------------------------

def guard_zapier_action(
    action: str,
    input_data: Dict[str, Any],
    sdk: GovernanceSDK,
    zap_id: Optional[str] = None,
    user_id: Optional[str] = None,
    commit: bool = True,
) -> Decision:
    """Guard a Zapier Agent action call.

    Use this in Zapier Code steps or custom Python scripts that import
    fAIrewall directly.  For webhook-based integrations use
    :class:`ZapierWebhookAdapter` instead.

    Args:
        action:     The Zapier action name (e.g. ``"send_email"``,
                    ``"create_record"``).
        input_data: The ``inputData`` dict from the Zap payload.
        sdk:        A configured :class:`~fairewall.sdk.GovernanceSDK` instance.
        zap_id:     Zapier Zap ID, used as session identifier.
        user_id:    Zapier user ID, used as principal identifier.
        commit:     Advance spend/velocity budgets if the call is allowed.

    Returns:
        A :class:`~fairewall.types.Decision`.

    Example::

        sdk = GovernanceSDK.from_preset("ZAPIER_SME")
        decision = guard_zapier_action(
            "create_record",
            {"amount": 150.0, "record_type": "invoice"},
            sdk,
            zap_id="zap_abc123",
            user_id="usr_xyz",
        )
        if decision.blocked:
            raise RuntimeError(f"Blocked: {decision.reason}")
    """
    principal = Principal(id=user_id or "zapier_anon") if user_id else None
    return sdk.guard_action(
        action_name=action,
        arguments=input_data,
        session_id=zap_id,
        principal=principal,
        commit=commit,
    )


# ---------------------------------------------------------------------------
# Webhook adapter (FastAPI)
# ---------------------------------------------------------------------------

class ZapierWebhookAdapter:
    """FastAPI router adapter for Zapier Agent webhook payloads.

    Mount this on the fAIrewall proxy to expose Zapier-specific governance
    endpoints:

    .. code-block:: python

        from fairewall.proxy import create_app
        from fairewall.integrations.zapier import ZapierWebhookAdapter

        sdk = GovernanceSDK.from_preset("ZAPIER_SME")
        adapter = ZapierWebhookAdapter(sdk, webhook_secret="my-secret")
        app = create_app()
        app.include_router(adapter.router)

    Args:
        sdk:              A configured :class:`~fairewall.sdk.GovernanceSDK`.
        webhook_secret:   Shared HMAC secret for ``X-Zapier-Secret``
                          verification.  ``None`` disables verification
                          (dev only).
        verify_signature: Master switch for signature verification.
    """

    def __init__(
        self,
        sdk: GovernanceSDK,
        webhook_secret: Optional[str] = None,
        verify_signature: bool = True,
    ) -> None:
        if not _FASTAPI_AVAILABLE:
            raise ImportError(
                "ZapierWebhookAdapter requires `pip install fairewall[zapier]`"
            )
        self.sdk = sdk
        self.webhook_secret = webhook_secret
        self.verify_signature = verify_signature
        self.router = APIRouter(prefix="/v1/zapier", tags=["Zapier Governance"])
        self._register_routes()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _verify_hmac(self, body: bytes, signature: Optional[str]) -> None:
        if not self.verify_signature or not self.webhook_secret:
            return
        if not signature:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing X-Zapier-Secret header.",
            )
        expected = hmac.new(
            self.webhook_secret.encode(),
            body,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, signature.lower()):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid X-Zapier-Secret signature.",
            )

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------

    def _register_routes(self) -> None:

        router = self.router
        sdk = self.sdk

        @router.get("/health")
        async def health() -> Dict[str, Any]:
            """Zapier adapter liveness check."""
            return {
                "status": "ok",
                "platform": "zapier",
                "sdk_platform": sdk.platform,
                "policy_version": sdk.policy.version,
                "policy_fingerprint": sdk.policy.fingerprint(),
                "shadow": sdk.firewall.shadow,
            }

        @router.post("/screen")
        async def screen_trigger(
            request: Request,
            x_zapier_secret: Optional[str] = Header(None),
        ) -> Dict[str, Any]:
            """Screen an inbound Zapier trigger payload for prompt injection."""
            body = await request.body()
            self._verify_hmac(body, x_zapier_secret)
            try:
                data = json.loads(body)
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid JSON body.")

            text = str(data.get("text", data.get("inputData", "")))
            zap_id = data.get("zap_id") or data.get("meta", {}).get("zap_id")
            user_id = data.get("user_id") or data.get("meta", {}).get("user_id")
            source = data.get("source", "zapier_trigger")

            principal = Principal(id=user_id) if user_id else None
            decision = sdk.screen(
                text=text,
                session_id=zap_id,
                principal=principal,
                trust=Trust.UNTRUSTED,
                source=source,
            )
            return {
                "allowed": decision.allowed,
                "blocked": decision.blocked,
                "reason": decision.reason,
                "findings": [f.to_dict() for f in decision.findings],
                "session_id": decision.session_id,
            }

        @router.post("/action")
        async def guard_action(
            request: Request,
            x_zapier_secret: Optional[str] = Header(None),
        ) -> Dict[str, Any]:
            """Guard a Zapier Agent action invocation."""
            body = await request.body()
            self._verify_hmac(body, x_zapier_secret)
            try:
                data = json.loads(body)
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid JSON body.")

            action = data.get("action", data.get("tool", ""))
            if not action:
                raise HTTPException(status_code=400, detail="'action' field is required.")

            input_data: Dict[str, Any] = data.get("inputData", data.get("arguments", {}))
            meta: Dict[str, Any] = data.get("meta", {})
            zap_id = meta.get("zap_id") or data.get("session_id")
            user_id = meta.get("user_id") or data.get("principal_id")

            principal = Principal(id=user_id) if user_id else None
            decision = sdk.guard_action(
                action_name=action,
                arguments=input_data,
                session_id=zap_id,
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
                "reason": decision.reason,
                "decision_id": decision.call_id,
                "session_id": decision.session_id,
            }

        @router.get("/audit")
        async def get_audit(last: int = 50) -> Dict[str, Any]:
            """Return the last N audit records and chain verification status."""
            verification = sdk.verify_audit()
            records = sdk.audit.records()[-last:]
            return {
                "valid": verification.valid,
                "checked": verification.checked,
                "broken_at": verification.broken_at,
                "reason": verification.reason,
                "records": records,
            }
