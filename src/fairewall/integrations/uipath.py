"""fAIrewall integration for UiPath Automation Platform.

UiPath processes can be governed in two ways:

1. **UiPath Automation Cloud Webhooks** — the Automation Cloud posts job
   lifecycle events (``job.started``, ``job.completed``, ``job.faulted``)
   and Action Center task events to a registered HTTP endpoint.

2. **Direct Python callable** — for UiPath processes that execute Python
   Activities or Invoke Python scripts, use ``guard_uipath_action()``
   to inline governance without HTTP overhead.

This module provides:

- **UiPathAdapter** — FastAPI ``APIRouter`` with endpoints:

  - ``POST /v1/uipath/job-started``      — screen UiPath Job inputs
  - ``POST /v1/uipath/action-request``   — guard Action Center tasks
  - ``POST /v1/uipath/webhook``          — generic Automation Cloud event
  - ``GET  /v1/uipath/health``           — adapter liveness

- **guard_uipath_action** — direct callable for Python Activities and
  Invoke Python scripts.

Automation Cloud Webhook Authentication
----------------------------------------
UiPath Automation Cloud signs webhooks with a ``X-UiPath-Signature`` header
(HMAC-SHA256 over the raw body using the webhook secret).  Set
``verify_signature=False`` for local development.

UiPath Envelope Format
-----------------------
Job-started events are posted as::

    {
        "Type":    "job.started",
        "EventId": "uuid",
        "Timestamp": "...",
        "Body": {
            "Id": 42,
            "ProcessName": "InvoiceProcessing",
            "InputArguments": "{\"InvoiceAmount\": 1200}"
        }
    }

The adapter extracts ``Body.InputArguments`` (JSON string) as action
arguments and ``Body.ProcessName`` as the action name.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Dict, Optional

from ..sdk import GovernanceSDK
from ..types import Decision, Principal, Trust

try:
    from fastapi import APIRouter, Header, HTTPException, Request, status
    from fastapi.responses import JSONResponse
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False


# ---------------------------------------------------------------------------
# Direct callable
# ---------------------------------------------------------------------------

def guard_uipath_action(
    action_name: str,
    arguments: Dict[str, Any],
    sdk: GovernanceSDK,
    job_id: Optional[str] = None,
    robot_name: Optional[str] = None,
    commit: bool = True,
) -> Decision:
    """Guard a UiPath RPA action or process step.

    Use this from UiPath Python Activities or Invoke Python scripts to
    inline governance without HTTP overhead.

    Args:
        action_name: The UiPath process or activity name (e.g.
                     ``"approve_invoice"``, ``"process_payment"``).
        arguments:   The activity's input arguments dict.
        sdk:         A :class:`~fairewall.sdk.GovernanceSDK` instance.
        job_id:      UiPath Job ID (used as session identifier so that
                     per-job spend and velocity limits accumulate correctly).
        robot_name:  UiPath robot/machine name (principal identifier).
        commit:      Advance budgets on ALLOW.

    Returns:
        A :class:`~fairewall.types.Decision`.

    Example::

        sdk = GovernanceSDK.from_preset("UIPATH_RPA")

        # In a UiPath Python Activity:
        decision = guard_uipath_action(
            "approve_invoice",
            {"invoice_id": "INV-001", "amount": 1200.0},
            sdk,
            job_id="job_123",
            robot_name="Robot01",
        )
        if decision.blocked:
            raise Exception(f"fAIrewall blocked: {decision.reason}")
    """
    principal = Principal(id=robot_name or "uipath_robot")
    return sdk.guard_action(
        action_name=action_name,
        arguments=arguments,
        session_id=job_id,
        principal=principal,
        commit=commit,
    )


def screen_uipath_document(
    text: str,
    sdk: GovernanceSDK,
    job_id: Optional[str] = None,
    source: str = "uipath_document",
) -> Decision:
    """Screen a document or file read by a UiPath bot for injection.

    Call this after reading an invoice, email, or external file.  The
    session will be marked tainted, which blocks high-risk financial
    actions (``approve_invoice``, ``process_payment``) until the job ends.

    Args:
        text:    The document text content.
        sdk:     A :class:`~fairewall.sdk.GovernanceSDK` instance.
        job_id:  UiPath Job ID (session).
        source:  Label for the audit log.

    Returns:
        A :class:`~fairewall.types.Decision`.
    """
    return sdk.screen(
        text=text,
        session_id=job_id,
        trust=Trust.UNTRUSTED,
        source=source,
    )


# ---------------------------------------------------------------------------
# Webhook adapter (FastAPI)
# ---------------------------------------------------------------------------

class UiPathAdapter:
    """FastAPI router adapter for UiPath Automation Cloud webhooks.

    Mount on the fAIrewall proxy::

        from fairewall.integrations.uipath import UiPathAdapter
        adapter = UiPathAdapter(
            GovernanceSDK.from_preset("UIPATH_RPA"),
            webhook_secret="your-automation-cloud-secret",
        )
        app.include_router(adapter.router)

    Args:
        sdk:              A :class:`~fairewall.sdk.GovernanceSDK`.
        webhook_secret:   Automation Cloud webhook HMAC secret.
        verify_signature: Master switch for HMAC verification.
    """

    def __init__(
        self,
        sdk: GovernanceSDK,
        webhook_secret: Optional[str] = None,
        verify_signature: bool = True,
    ) -> None:
        if not _FASTAPI_AVAILABLE:
            raise ImportError(
                "UiPathAdapter requires `pip install fairewall[uipath]`"
            )
        self.sdk = sdk
        self.webhook_secret = webhook_secret
        self.verify_signature = verify_signature
        self.router = APIRouter(prefix="/v1/uipath", tags=["UiPath Governance"])
        self._register_routes()

    # ------------------------------------------------------------------

    def _verify_hmac(self, body: bytes, signature: Optional[str]) -> None:
        if not self.verify_signature or not self.webhook_secret:
            return
        if not signature:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing X-UiPath-Signature header.",
            )
        expected = hmac.new(
            self.webhook_secret.encode(),
            body,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, signature.lower()):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid UiPath webhook signature.",
            )

    @staticmethod
    def _parse_input_arguments(raw: Any) -> Dict[str, Any]:
        """Parse UiPath InputArguments (JSON string or dict)."""
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, str) and raw:
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass
        return {"raw": str(raw)} if raw else {}

    # ------------------------------------------------------------------

    def _register_routes(self) -> None:

        router = self.router
        sdk = self.sdk
        adapter = self

        @router.get("/health")
        async def health() -> Dict[str, Any]:
            return {
                "status": "ok",
                "platform": "uipath",
                "policy_version": sdk.policy.version,
                "policy_fingerprint": sdk.policy.fingerprint(),
                "shadow": sdk.firewall.shadow,
            }

        @router.post("/job-started")
        async def job_started(
            request: Request,
            x_uipath_signature: Optional[str] = Header(None),
        ) -> Dict[str, Any]:
            """Screen UiPath Job inputs before the process begins execution."""
            body = await request.body()
            adapter._verify_hmac(body, x_uipath_signature)
            try:
                event = json.loads(body)
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid JSON body.")

            event_body: Dict[str, Any] = event.get("Body", event)
            process_name = event_body.get("ProcessName", "uipath_process")
            job_id = str(event_body.get("Id", event.get("EventId", "")))
            robot_name = event_body.get("HostMachineName", event_body.get("Robot", {}).get("Name"))
            raw_inputs = event_body.get("InputArguments", {})
            arguments = adapter._parse_input_arguments(raw_inputs)

            principal = Principal(id=robot_name or "uipath_robot")

            # Screen any string argument values for injection
            for key, val in arguments.items():
                if isinstance(val, str) and val:
                    dec = sdk.screen(
                        text=val,
                        session_id=job_id,
                        principal=principal,
                        trust=Trust.UNTRUSTED,
                        source=f"uipath_input_{key}",
                    )
                    if dec.blocked:
                        return JSONResponse(
                            status_code=status.HTTP_403_FORBIDDEN,
                            content={
                                "blocked": True,
                                "reason": dec.reason,
                                "job_id": job_id,
                                "process": process_name,
                                "findings": [f.to_dict() for f in dec.findings],
                            },
                        )

            # Guard the process-start action itself
            decision = sdk.guard_action(
                action_name=process_name,
                arguments=arguments,
                session_id=job_id,
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
                        "job_id": job_id,
                        "process": process_name,
                        "findings": [f.to_dict() for f in decision.findings],
                    },
                )

            return {
                "allowed": True,
                "blocked": False,
                "job_id": job_id,
                "process": process_name,
                "decision_id": decision.call_id,
            }

        @router.post("/action-request")
        async def action_request(
            request: Request,
            x_uipath_signature: Optional[str] = Header(None),
        ) -> Dict[str, Any]:
            """Guard a UiPath Action Center task before it is assigned."""
            body = await request.body()
            adapter._verify_hmac(body, x_uipath_signature)
            try:
                data = json.loads(body)
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid JSON body.")

            action_name = (
                data.get("action")
                or data.get("ActionTitle")
                or data.get("Type", "action_center_task")
            )
            action_body = data.get("Body", data)
            raw_data = action_body.get("Data", action_body.get("arguments", {}))
            arguments = adapter._parse_input_arguments(raw_data)
            job_id = str(action_body.get("JobId", data.get("session_id", "")))
            assignee = action_body.get("Assignee", action_body.get("robot", "uipath_robot"))

            decision = sdk.guard_action(
                action_name=action_name,
                arguments=arguments,
                session_id=job_id,
                principal=Principal(id=str(assignee)),
                commit=True,
            )

            if decision.blocked:
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={
                        "allowed": False,
                        "blocked": True,
                        "reason": decision.reason,
                        "action": action_name,
                        "findings": [f.to_dict() for f in decision.findings],
                    },
                )

            return {
                "allowed": True,
                "blocked": False,
                "action": action_name,
                "job_id": job_id,
                "decision_id": decision.call_id,
            }

        @router.post("/webhook")
        async def generic_webhook(
            request: Request,
            x_uipath_signature: Optional[str] = Header(None),
        ) -> Dict[str, Any]:
            """Generic UiPath Automation Cloud webhook — routes by event Type."""
            body = await request.body()
            adapter._verify_hmac(body, x_uipath_signature)
            try:
                event = json.loads(body)
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid JSON body.")

            event_type = event.get("Type", "unknown")
            event_id = event.get("EventId", "")
            event_body = event.get("Body", {})

            # Log and screen any string fields in the event body
            for key, val in event_body.items():
                if isinstance(val, str) and len(val) > 10:
                    dec = sdk.screen(
                        text=val,
                        session_id=event_id,
                        trust=Trust.UNTRUSTED,
                        source=f"uipath_event_{event_type}_{key}",
                    )
                    if dec.blocked:
                        return JSONResponse(
                            status_code=status.HTTP_403_FORBIDDEN,
                            content={
                                "blocked": True,
                                "event_type": event_type,
                                "reason": dec.reason,
                                "findings": [f.to_dict() for f in dec.findings],
                            },
                        )

            return {
                "allowed": True,
                "blocked": False,
                "event_type": event_type,
                "event_id": event_id,
            }
