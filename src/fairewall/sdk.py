"""fAIrewall GovernanceSDK — high-level facade for enterprise AI governance.

This module provides ``GovernanceSDK``, a convenience wrapper that wires
together the Firewall, AuditLog, and optional platform adapters into a
single object that MSME and enterprise customers can drop into any AI agent
stack without touching lower-level internals.

Quick start::

    from fairewall.sdk import GovernanceSDK
    from fairewall.presets import load_preset

    sdk = GovernanceSDK.from_preset("ZAPIER_SME")

    # Screen inbound user input
    result = sdk.screen("Ignore all previous instructions…")
    if result.blocked:
        raise ValueError(result.reason)

    # Guard an action before execution
    decision = sdk.guard_action("process_refund", {"amount": 150.0, "order_id": "X"})
    if decision.allowed:
        # run the action
        ...

    # Verify audit trail integrity
    report = sdk.verify_audit()
    assert report.valid
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

from .audit import AuditLog, ChainVerification
from .detectors import Detector
from .firewall import Firewall
from .policy import Policy
from .types import Action, Context, Decision, Finding, Principal, Trust


# ---------------------------------------------------------------------------
# Session report
# ---------------------------------------------------------------------------

@dataclass
class SessionReport:
    """Snapshot of a session's governance state."""

    session_id: str
    tainted: bool
    taint_sources: List[str]
    total_spend: float
    call_count: int
    blocked_count: int
    allowed_count: int
    flagged_count: int
    principal_id: str
    principal_roles: List[str]
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "tainted": self.tainted,
            "taint_sources": self.taint_sources,
            "total_spend": self.total_spend,
            "call_count": self.call_count,
            "blocked_count": self.blocked_count,
            "allowed_count": self.allowed_count,
            "flagged_count": self.flagged_count,
            "principal_id": self.principal_id,
            "principal_roles": self.principal_roles,
            "created_at": self.created_at,
        }


# ---------------------------------------------------------------------------
# GovernanceSDK
# ---------------------------------------------------------------------------

class GovernanceSDK:
    """High-level AI governance facade for enterprise and MSME deployments.

    This class acts as the single integration point.  Customers instantiate
    one SDK object per deployment (or per platform adapter) and then call
    :meth:`screen` for inbound text and :meth:`guard_action` for outbound
    tool calls.  Both methods return a :class:`~fairewall.types.Decision`
    that carries a human-readable ``reason`` and a machine-readable list of
    ``findings``.

    The SDK is thread-safe and maintains per-session state (spend budgets,
    velocity windows, taint flags) internally.

    Args:
        policy: Governance policy.  Use :func:`~fairewall.presets.load_preset`
                to get a platform-specific starting point.
        audit_path: File path for the tamper-evident JSONL audit log.  Pass
                    ``None`` to log in-memory only (not recommended for
                    production).
        shadow: When ``True`` the SDK evaluates and logs every call but never
                blocks.  Use to observe behaviour before enforcing.
        detectors: Optional list of Tier-1 ML detectors.  See
                   :class:`~fairewall.detectors.HeuristicDetector` and
                   :class:`~fairewall.detectors.OnnxDetector`.
        platform: Informational label attached to audit log entries (e.g.
                  ``"zapier"``, ``"copilot"``).
    """

    def __init__(
        self,
        policy: Optional[Policy] = None,
        audit_path: Optional[str] = None,
        shadow: bool = False,
        detectors: Optional[Sequence[Detector]] = None,
        platform: str = "generic",
    ) -> None:
        self.platform = platform
        audit = AuditLog(path=audit_path) if audit_path else AuditLog()
        self._fw = Firewall(
            policy=policy or Policy(),
            audit=audit,
            shadow=shadow,
            detectors=list(detectors or []),
        )
        # Per-session counters (call_count, blocked, allowed, flagged)
        self._session_stats: Dict[str, Dict[str, int]] = {}

    # ------------------------------------------------------------------
    # Factory helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_preset(
        cls,
        preset_name: str,
        audit_path: Optional[str] = None,
        shadow: bool = False,
        detectors: Optional[Sequence[Detector]] = None,
    ) -> "GovernanceSDK":
        """Create a GovernanceSDK using a named policy preset.

        Args:
            preset_name: One of ``ZAPIER_SME``, ``COPILOT_ENTERPRISE``,
                         ``SALESFORCE_CRM``, ``WHATSAPP_BOT``, ``UIPATH_RPA``.

        Example::

            sdk = GovernanceSDK.from_preset("SALESFORCE_CRM", audit_path="audit.jsonl")
        """
        from .presets import load_preset  # local import avoids circular at module level
        policy = load_preset(preset_name)
        platform = preset_name.lower().split("_")[0]
        return cls(
            policy=policy,
            audit_path=audit_path,
            shadow=shadow,
            detectors=detectors,
            platform=platform,
        )

    @classmethod
    def from_policy_file(
        cls,
        path: str,
        audit_path: Optional[str] = None,
        shadow: bool = False,
        detectors: Optional[Sequence[Detector]] = None,
        platform: str = "custom",
    ) -> "GovernanceSDK":
        """Create a GovernanceSDK from a JSON or YAML policy file.

        Requires ``pip install fairewall[yaml]`` for YAML files.

        Example::

            sdk = GovernanceSDK.from_policy_file("policy.yaml")
        """
        policy = Policy.from_file(path)
        return cls(
            policy=policy,
            audit_path=audit_path,
            shadow=shadow,
            detectors=detectors,
            platform=platform,
        )

    # ------------------------------------------------------------------
    # Core SDK methods
    # ------------------------------------------------------------------

    def screen(
        self,
        text: str,
        session_id: Optional[str] = None,
        principal: Optional[Principal] = None,
        trust: Trust = Trust.USER,
        source: str = "input",
    ) -> Decision:
        """Screen inbound text for prompt injection and hostile content.

        Call this before passing user input or external tool outputs to your
        AI agent.  The ``trust`` parameter controls taint propagation:

        - ``Trust.USER`` — text comes directly from a trusted human operator.
        - ``Trust.UNTRUSTED`` — text was fetched from the web, a PDF, an
          email, or another agent.  Marks the session tainted, which blocks
          high-privilege tools until :meth:`reset_session` is called.

        Args:
            text: The text to screen.
            session_id: Identifies the agent session for budget/taint tracking.
            principal: The human or service identity behind the request.
            trust: Trust level of the text source.
            source: Descriptive label for the audit log (e.g. ``"user_input"``,
                    ``"web_fetch"``, ``"email_body"``).

        Returns:
            A :class:`~fairewall.types.Decision` with ``allowed``, ``blocked``,
            ``reason``, and ``findings``.
        """
        ctx = self._fw.session(session_id, principal)
        decision = self._fw.inspect_input(text, trust=trust, ctx=ctx, source=source)
        self._record_stat(ctx.session_id, decision)
        return decision

    def guard_action(
        self,
        action_name: str,
        arguments: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        principal: Optional[Principal] = None,
        commit: bool = True,
    ) -> Decision:
        """Adjudicate an AI agent action call before execution.

        The firewall evaluates all six rule engines (injection, schema, taint,
        financial, velocity, egress) and optional ML detectors.  If the call
        is allowed *and* ``commit=True``, session spend and rate-limit
        windows are advanced.

        Args:
            action_name: The tool or action name (e.g. ``"process_refund"``).
            arguments: Keyword arguments the agent wants to pass.
            session_id: Session identifier.
            principal: Caller identity.
            commit: Advance spend and velocity budgets on ALLOW.  Set
                    ``False`` for dry-run / shadow inspection.

        Returns:
            A :class:`~fairewall.types.Decision`.
        """
        ctx = self._fw.session(session_id, principal)
        decision = self._fw.inspect(action_name, arguments, ctx=ctx)
        if commit and decision.allowed:
            self._fw.commit(action_name, arguments or {}, ctx)
        self._record_stat(ctx.session_id, decision)
        return decision

    def execute_action(
        self,
        action_name: str,
        fn: Callable[..., Any],
        arguments: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        principal: Optional[Principal] = None,
        raise_on_block: bool = False,
    ) -> Any:
        """Inspect, then run ``fn(**arguments)`` only if the call is permitted.

        This is the most ergonomic integration point: pass any callable
        (your tool function, a lambda, an SDK client method) and the
        GovernanceSDK handles the inspect → execute → commit lifecycle.

        Args:
            action_name: The tool name registered in the policy.
            fn: Callable that implements the action.
            arguments: Keyword arguments forwarded to ``fn``.
            session_id: Session identifier.
            principal: Caller identity.
            raise_on_block: If ``True``, raises
                :class:`~fairewall.types.FirewallBlock` instead of returning
                the refusal string.

        Returns:
            The return value of ``fn`` on success, or a ``"SECURITY BLOCK: …"``
            string on a blocked call (unless ``raise_on_block=True``).
        """
        ctx = self._fw.session(session_id, principal)
        # inspect first so we can record the stat before execution
        decision = self._fw.inspect(action_name, arguments, ctx=ctx)
        self._record_stat(ctx.session_id, decision)
        return self._fw.execute(
            tool=action_name,
            fn=fn,
            arguments=arguments,
            ctx=ctx,
            raise_on_block=raise_on_block,
        )

    def guard(
        self,
        action_name: Optional[str] = None,
        raise_on_block: bool = False,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator that places a function under governance.

        Equivalent to ``Firewall.guard()`` but surfaced on the SDK::

            sdk = GovernanceSDK.from_preset("UIPATH_RPA")

            @sdk.guard()
            def approve_invoice(invoice_id: str, amount: float) -> str:
                ...

            approve_invoice(invoice_id="INV-001", amount=1200.0, _session_id="s1")
        """
        return self._fw.guard(tool=action_name, raise_on_block=raise_on_block)

    def sanitize(
        self,
        text: str,
        session_id: Optional[str] = None,
        source: str = "tool_output",
    ) -> str:
        """Wrap untrusted external content in safety boundary tags.

        Neutralizes injection signatures in-band so the AI agent can still
        read the content without being fooled by hostile instructions embedded
        inside it.

        Args:
            text: External content (web page, PDF text, email body, etc.)
            session_id: Session identifier.
            source: Label for the audit log.

        Returns:
            The content wrapped in ``<untrusted_data …>`` tags with any
            detected injection patterns flagged.
        """
        ctx = self._fw.session(session_id)
        return self._fw.sanitize(text, ctx=ctx, source=source)

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def get_session(
        self,
        session_id: Optional[str] = None,
        principal: Optional[Principal] = None,
    ) -> Context:
        """Get or create a session context.

        Args:
            session_id: Reuse an existing session or create a new one.
            principal: Identity to associate with the session.

        Returns:
            The :class:`~fairewall.types.Context` for this session.
        """
        return self._fw.session(session_id, principal)

    def get_session_report(self, session_id: str) -> Optional[SessionReport]:
        """Return a governance snapshot for the given session.

        Returns ``None`` if the session does not exist.
        """
        ctx = self._fw._contexts.get(session_id)
        if ctx is None:
            return None
        stats = self._session_stats.get(session_id, {})
        return SessionReport(
            session_id=session_id,
            tainted=ctx.tainted,
            taint_sources=list(getattr(ctx, "_taint_sources", [])),
            total_spend=float(getattr(ctx, "total_spend", 0.0)),
            call_count=stats.get("calls", 0),
            blocked_count=stats.get("blocked", 0),
            allowed_count=stats.get("allowed", 0),
            flagged_count=stats.get("flagged", 0),
            principal_id=ctx.principal.id,
            principal_roles=list(ctx.principal.roles),
        )

    def reset_session(self, session_id: Optional[str] = None) -> None:
        """Reset session state (taint, budgets, velocity windows).

        Pass ``session_id=None`` to reset all sessions.
        """
        self._fw.reset(session_id)
        if session_id is None:
            self._session_stats.clear()
        else:
            self._session_stats.pop(session_id, None)

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    def verify_audit(self) -> ChainVerification:
        """Verify the cryptographic integrity of the audit chain.

        Returns:
            A :class:`~fairewall.audit.ChainVerification` with ``valid``,
            ``checked``, ``broken_at``, and ``reason``.
        """
        return self._fw.audit.verify()

    @property
    def audit(self) -> AuditLog:
        """Direct access to the underlying :class:`~fairewall.audit.AuditLog`."""
        return self._fw.audit

    @property
    def firewall(self) -> Firewall:
        """Direct access to the underlying :class:`~fairewall.firewall.Firewall`."""
        return self._fw

    @property
    def policy(self) -> Policy:
        """The active governance policy."""
        return self._fw.policy

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _record_stat(self, session_id: str, decision: Decision) -> None:
        s = self._session_stats.setdefault(session_id, {
            "calls": 0, "blocked": 0, "allowed": 0, "flagged": 0,
        })
        s["calls"] += 1
        if decision.action is Action.BLOCK:
            s["blocked"] += 1
        elif decision.action is Action.FLAG:
            s["flagged"] += 1
        else:
            s["allowed"] += 1

    def __repr__(self) -> str:
        return (
            f"GovernanceSDK(platform={self.platform!r}, "
            f"policy_v={self.policy.version!r}, "
            f"shadow={self._fw.shadow})"
        )
