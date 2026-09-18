"""fAIrewall integration for Haptik Smart Agent and WhatsApp Bots.

Supports two inbound webhook formats:

1. **Meta WhatsApp Cloud API** — the standard Meta webhook payload delivered
   by `graph.facebook.com` to your registered callback URL.
2. **Haptik Smart Agent** — Haptik's proprietary webhook format used by its
   enterprise NLU platform.

This module provides:

- **HaptikAdapter** — FastAPI ``APIRouter`` with six endpoints:

  - ``POST /v1/haptik/message``     — screen Haptik inbound user messages
  - ``POST /v1/haptik/action``      — guard Haptik Smart Agent action dispatches
  - ``POST /v1/whatsapp/message``   — screen Meta WhatsApp Cloud API messages
  - ``POST /v1/whatsapp/action``    — guard WhatsApp flow / action calls
  - ``GET  /v1/haptik/health``      — adapter liveness
  - ``GET  /v1/whatsapp/verify``    — Meta webhook challenge verification

- **guard_whatsapp_message** / **guard_haptik_message** — direct callables.

Signature Verification
----------------------
- **Meta**: ``X-Hub-Signature-256: sha256=<hmac>`` header (HMAC-SHA256 over
  the raw request body using the app secret).
- **Haptik**: ``client_id`` + ``api_token`` in the JSON body or headers.

Both verifications are enabled by default.  Pass ``verify_signature=False``
in local development only.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Dict, List, Optional

from ..sdk import GovernanceSDK
from ..types import Decision, Principal, Trust

try:
    from fastapi import APIRouter, Header, HTTPException, Query, Request, status
    from fastapi.responses import JSONResponse, PlainTextResponse
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False


# ---------------------------------------------------------------------------
# Direct callables
# ---------------------------------------------------------------------------

def guard_whatsapp_message(
    text: str,
    sdk: GovernanceSDK,
    phone_number: Optional[str] = None,
    wa_id: Optional[str] = None,
) -> Decision:
    """Screen an inbound WhatsApp user message.

    Args:
        text:         The message body text.
        sdk:          A :class:`~fairewall.sdk.GovernanceSDK` instance.
        phone_number: User's phone number (session identifier).
        wa_id:        WhatsApp user ID (principal).

    Returns:
        A :class:`~fairewall.types.Decision`.
    """
    principal = Principal(id=wa_id or phone_number or "wa_anon")
    return sdk.screen(
        text=text,
        session_id=phone_number,
        principal=principal,
        trust=Trust.USER,
        source="whatsapp_message",
    )


def guard_haptik_message(
    text: str,
    sdk: GovernanceSDK,
    conversation_id: Optional[str] = None,
    user_id: Optional[str] = None,
) -> Decision:
    """Screen an inbound Haptik Smart Agent user message.

    Args:
        text:            The message text.
        sdk:             A :class:`~fairewall.sdk.GovernanceSDK` instance.
        conversation_id: Haptik conversation ID (session).
        user_id:         Haptik user ID (principal).

    Returns:
        A :class:`~fairewall.types.Decision`.
    """
    principal = Principal(id=user_id or "haptik_anon")
    return sdk.screen(
        text=text,
        session_id=conversation_id,
        principal=principal,
        trust=Trust.USER,
        source="haptik_message",
    )


# ---------------------------------------------------------------------------
# Webhook adapter (FastAPI)
# ---------------------------------------------------------------------------

class HaptikAdapter:
    """FastAPI router adapter for Haptik + WhatsApp governance.

    Mount on the fAIrewall proxy::

        from fairewall.integrations.haptik import HaptikAdapter
        adapter = HaptikAdapter(
            GovernanceSDK.from_preset("WHATSAPP_BOT"),
            meta_app_secret="your-meta-app-secret",
            haptik_client_id="your-client-id",
            haptik_api_token="your-api-token",
        )
        app.include_router(adapter.router)

    Args:
        sdk:              :class:`~fairewall.sdk.GovernanceSDK` instance.
        meta_app_secret:  Meta WhatsApp app secret for HMAC verification.
        haptik_client_id: Haptik client ID for request validation.
        haptik_api_token: Haptik API token for request validation.
        verify_signature: Master switch for all signature checks.
        meta_verify_token: Token for the Meta webhook challenge handshake.
    """

    def __init__(
        self,
        sdk: GovernanceSDK,
        meta_app_secret: Optional[str] = None,
        haptik_client_id: Optional[str] = None,
        haptik_api_token: Optional[str] = None,
        verify_signature: bool = True,
        meta_verify_token: Optional[str] = None,
    ) -> None:
        if not _FASTAPI_AVAILABLE:
            raise ImportError(
                "HaptikAdapter requires `pip install fairewall[haptik]`"
            )
        self.sdk = sdk
        self.meta_app_secret = meta_app_secret
        self.haptik_client_id = haptik_client_id
        self.haptik_api_token = haptik_api_token
        self.verify_signature = verify_signature
        self.meta_verify_token = meta_verify_token
        self.router = APIRouter(tags=["Haptik / WhatsApp Governance"])
        self._register_routes()

    # ------------------------------------------------------------------

    def _verify_meta_hmac(self, body: bytes, signature: Optional[str]) -> None:
        if not self.verify_signature or not self.meta_app_secret:
            return
        if not signature:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing X-Hub-Signature-256 header.",
            )
        sig_value = signature.removeprefix("sha256=")
        expected = hmac.new(
            self.meta_app_secret.encode(),
            body,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, sig_value):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Meta HMAC signature.",
            )

    def _verify_haptik_auth(self, client_id: Optional[str], api_token: Optional[str]) -> None:
        if not self.verify_signature:
            return
        if self.haptik_client_id and client_id != self.haptik_client_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Haptik client_id.",
            )
        if self.haptik_api_token and api_token != self.haptik_api_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Haptik api_token.",
            )

    @staticmethod
    def _extract_whatsapp_messages(data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract messages from Meta WhatsApp Cloud API webhook payload."""
        messages = []
        for entry in data.get("entry", []):
            for change in entry.get("changes", []):
                value = change.get("value", {})
                for msg in value.get("messages", []):
                    msg["_contacts"] = value.get("contacts", [])
                    msg["_phone_number_id"] = value.get("metadata", {}).get("phone_number_id")
                    messages.append(msg)
        return messages

    # ------------------------------------------------------------------

    def _register_routes(self) -> None:

        router = self.router
        sdk = self.sdk
        adapter = self

        @router.get("/v1/haptik/health")
        async def health() -> Dict[str, Any]:
            return {
                "status": "ok",
                "platform": "haptik_whatsapp",
                "policy_version": sdk.policy.version,
                "policy_fingerprint": sdk.policy.fingerprint(),
                "shadow": sdk.firewall.shadow,
            }

        # ------ Meta WhatsApp webhook verification challenge ------
        @router.get("/v1/whatsapp/verify")
        async def whatsapp_verify(
            hub_mode: Optional[str] = Query(None, alias="hub.mode"),
            hub_verify_token: Optional[str] = Query(None, alias="hub.verify_token"),
            hub_challenge: Optional[str] = Query(None, alias="hub.challenge"),
        ) -> Any:
            """Respond to Meta's webhook verification challenge."""
            if hub_mode == "subscribe" and hub_challenge:
                if adapter.meta_verify_token:
                    if hub_verify_token != adapter.meta_verify_token:
                        raise HTTPException(status_code=403, detail="Verification token mismatch.")
                return PlainTextResponse(hub_challenge)
            raise HTTPException(status_code=400, detail="Invalid verification request.")

        # ------ WhatsApp inbound message screening ------
        @router.post("/v1/whatsapp/message")
        async def whatsapp_message(
            request: Request,
            x_hub_signature_256: Optional[str] = Header(None),
        ) -> Dict[str, Any]:
            """Screen inbound WhatsApp messages for injection."""
            body = await request.body()
            adapter._verify_meta_hmac(body, x_hub_signature_256)
            try:
                data = json.loads(body)
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid JSON body.")

            messages = adapter._extract_whatsapp_messages(data)
            blocked = []
            for msg in messages:
                msg_type = msg.get("type", "text")
                if msg_type != "text":
                    continue
                text = msg.get("text", {}).get("body", "")
                if not text:
                    continue
                phone_number = msg.get("from", "")
                contacts = msg.get("_contacts", [])
                wa_id = contacts[0].get("wa_id", phone_number) if contacts else phone_number

                dec = sdk.screen(
                    text=text,
                    session_id=phone_number,
                    principal=Principal(id=wa_id or "wa_anon"),
                    trust=Trust.USER,
                    source="whatsapp_message",
                )
                if dec.blocked:
                    blocked.append({"from": phone_number, "reason": dec.reason})

            if blocked:
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"blocked": True, "blocked_messages": blocked},
                )

            return {"allowed": True, "blocked": False, "processed": len(messages)}

        # ------ WhatsApp action guard ------
        @router.post("/v1/whatsapp/action")
        async def whatsapp_action(
            request: Request,
            x_hub_signature_256: Optional[str] = Header(None),
        ) -> Dict[str, Any]:
            """Guard a WhatsApp flow action invocation."""
            body = await request.body()
            adapter._verify_meta_hmac(body, x_hub_signature_256)
            try:
                data = json.loads(body)
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid JSON body.")

            action = data.get("action", data.get("tool", ""))
            if not action:
                raise HTTPException(status_code=400, detail="'action' is required.")
            arguments = data.get("parameters", data.get("arguments", {}))
            phone_number = data.get("from", data.get("session_id", ""))

            decision = sdk.guard_action(
                action_name=action,
                arguments=arguments,
                session_id=phone_number,
                principal=Principal(id=phone_number or "wa_anon"),
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
            return {"allowed": True, "blocked": False, "action": action,
                    "decision_id": decision.call_id}

        # ------ Haptik inbound message screening ------
        @router.post("/v1/haptik/message")
        async def haptik_message(
            request: Request,
            x_haptik_client_id: Optional[str] = Header(None),
            x_haptik_api_token: Optional[str] = Header(None),
        ) -> Dict[str, Any]:
            """Screen inbound Haptik Smart Agent user messages."""
            try:
                data = await request.json()
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid JSON body.")

            client_id = x_haptik_client_id or data.get("client_id")
            api_token = x_haptik_api_token or data.get("api_token")
            adapter._verify_haptik_auth(client_id, api_token)

            conversation_id = str(data.get("conversation_id", data.get("session_id", "")))
            user_id = str(data.get("user_id", data.get("user_name", "haptik_anon")))
            text = data.get("message", {}).get("body", data.get("text", ""))

            if not text:
                return {"allowed": True, "blocked": False, "note": "no text to screen"}

            decision = sdk.screen(
                text=text,
                session_id=conversation_id,
                principal=Principal(id=user_id),
                trust=Trust.USER,
                source="haptik_message",
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

            return {"allowed": True, "blocked": False,
                    "session_id": decision.session_id}

        # ------ Haptik action guard ------
        @router.post("/v1/haptik/action")
        async def haptik_action(
            request: Request,
            x_haptik_client_id: Optional[str] = Header(None),
            x_haptik_api_token: Optional[str] = Header(None),
        ) -> Dict[str, Any]:
            """Guard a Haptik Smart Agent action dispatch."""
            try:
                data = await request.json()
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid JSON body.")

            client_id = x_haptik_client_id or data.get("client_id")
            api_token = x_haptik_api_token or data.get("api_token")
            adapter._verify_haptik_auth(client_id, api_token)

            action = data.get("action", data.get("tool", ""))
            if not action:
                raise HTTPException(status_code=400, detail="'action' is required.")
            arguments = data.get("parameters", data.get("arguments", {}))
            conversation_id = str(data.get("conversation_id", ""))
            user_id = str(data.get("user_id", "haptik_anon"))

            decision = sdk.guard_action(
                action_name=action,
                arguments=arguments,
                session_id=conversation_id,
                principal=Principal(id=user_id),
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
            return {"allowed": True, "blocked": False, "action": action,
                    "decision_id": decision.call_id}
