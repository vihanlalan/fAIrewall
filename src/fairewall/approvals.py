"""Human approval queue: hold a tool call until a person approves or rejects it.

Without this, a FLAG decision only labels a call ("a person should look") and
the call still runs. With a queue, the call waits instead:

    queue = ApprovalQueue(firewall)
    outcome = queue.run("send_contract", send_contract, {"customer": "Priya"},
                        session_id="run-42")
    if isinstance(outcome, ApprovalRequest):      # held for a person
        ...                                       # tell the user it is pending
    queue.approve(outcome.id, reviewer="finance-lead")   # runs the call now

What gets held: any call the policy marks FLAG, and any call blocked *only*
because its tool is configured with ``require_human_approval``. Everything
else is untouched: clean calls run straight away, and calls the policy hard
blocks (injection, over-limit spend, unapproved destination, ...) stay
blocked. A reviewer cannot approve what the policy forbids.

On approval the call is inspected again before it runs, because session state
may have moved on while it waited (another call may have used up the budget,
or the session may have read untrusted content). If the policy now hard blocks
it, the request is rejected by fAIrewall, not run.

Every request, approval, rejection and expiry is written to the firewall's
hash-chained audit log, with the reviewer's name.

Limits: the queue lives in process memory, so pending requests are lost on
restart (the audit log keeps the record). Shadow-mode firewalls never hold a
call, since shadow mode must not change behaviour.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from .firewall import Firewall, redact
from .types import Action, Context, Decision, FirewallBlock, Principal

APPROVAL_ONLY_RULE = "schema.human_approval_required"


def needs_human(decision: Decision) -> bool:
    """True when a person should decide this call, rather than the policy.

    A FLAG, or a BLOCK whose only blocking findings are "this tool needs a
    person's approval". Any other blocking finding is a hard block.
    """
    if decision.action is Action.FLAG:
        return True
    if decision.action is Action.BLOCK:
        blockers = [f.rule_id for f in decision.findings if f.action is Action.BLOCK]
        return bool(blockers) and all(r == APPROVAL_ONLY_RULE for r in blockers)
    return False


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ApprovalError(Exception):
    """The request cannot be decided: unknown id, already decided, expired, or bad reviewer."""


@dataclass
class ApprovalRequest:
    """One held tool call, waiting for a person."""

    id: str
    tool: str
    arguments: Dict[str, Any]
    session_id: str
    principal_id: str
    reason: str
    rule_ids: List[str]
    created_at: float
    expires_at: Optional[float]
    status: ApprovalStatus = ApprovalStatus.PENDING
    decided_by: Optional[str] = None
    decided_at: Optional[float] = None
    note: str = ""
    # Set when an approved call was run by the queue itself (Python API).
    executed: bool = False
    # The learning case for this call (fairewall.learning), when one was opened.
    # The reviewer's decision here becomes its label.
    case_id: Optional[str] = None
    _fn: Optional[Callable[..., Any]] = field(default=None, repr=False, compare=False)

    @property
    def pending(self) -> bool:
        return self.status is ApprovalStatus.PENDING

    def to_dict(self) -> Dict[str, Any]:
        """JSON-safe view. Arguments are included in full: a reviewer needs them to decide."""
        return {
            "id": self.id,
            "tool": self.tool,
            "arguments": self.arguments,
            "session_id": self.session_id,
            "principal_id": self.principal_id,
            "reason": self.reason,
            "rule_ids": list(self.rule_ids),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "status": self.status.value,
            "decided_by": self.decided_by,
            "decided_at": self.decided_at,
            "note": self.note,
            "executed": self.executed,
            "case_id": self.case_id,
        }

    def __str__(self) -> str:
        # What an agent sees when its tool call is held, so it can tell the user.
        return ("PENDING HUMAN APPROVAL (request %s): %s. The action has not run; "
                "a person must approve it first." % (self.id, self.reason))


class ApprovalQueue:
    """Holds calls that need a person, and runs them once approved.

    Args:
        firewall: The firewall whose policy decides what gets held.
        ttl_seconds: How long a request may wait before it expires. ``None``
            means never. Default one hour.
        max_requests: Hard cap on stored requests. When full, the oldest
            decided requests are dropped; if every stored request is still
            pending, new calls are refused (fail closed) rather than run.
        clock: Injectable time source for tests.
    """

    def __init__(
        self,
        firewall: Firewall,
        ttl_seconds: Optional[float] = 3600.0,
        max_requests: int = 10_000,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if ttl_seconds is not None and ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be greater than zero, or None")
        if max_requests < 1:
            raise ValueError("max_requests must be at least 1")
        self.firewall = firewall
        self.ttl_seconds = ttl_seconds
        self.max_requests = max_requests
        self._clock = clock
        self._requests: Dict[str, ApprovalRequest] = {}
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- holding

    def submit(
        self,
        tool: str,
        arguments: Dict[str, Any],
        ctx: Context,
        decision: Decision,
        fn: Optional[Callable[..., Any]] = None,
    ) -> ApprovalRequest:
        """Hold one call. ``fn`` is kept so ``approve`` can run it; omit it when
        the caller executes the tool itself (the HTTP flow)."""
        if not needs_human(decision):
            raise ValueError("Only calls that need a person can be queued; this one is %s"
                             % decision.action.value)
        now = self._clock()
        req = ApprovalRequest(
            id=uuid.uuid4().hex[:16],
            tool=tool,
            arguments=dict(arguments),
            session_id=ctx.session_id,
            principal_id=ctx.principal.id,
            reason=decision.reason,
            rule_ids=sorted({f.rule_id for f in decision.findings}),
            created_at=now,
            expires_at=(now + self.ttl_seconds) if self.ttl_seconds is not None else None,
            _fn=fn,
            case_id=decision.case_id,
        )
        with self._lock:
            self._expire_locked(now)
            if len(self._requests) >= self.max_requests:
                self._evict_decided_locked()
            if len(self._requests) >= self.max_requests:
                raise ApprovalError("Approval queue is full of pending requests; refusing to hold more.")
            self._requests[req.id] = req
        self._audit("approval_requested", req, {"arguments": redact(req.arguments)})
        return req

    def run(
        self,
        tool: str,
        fn: Callable[..., Any],
        arguments: Optional[Dict[str, Any]] = None,
        ctx: Optional[Context] = None,
        session_id: Optional[str] = None,
        principal: Optional[Principal] = None,
        raise_on_block: bool = False,
    ) -> Any:
        """Like ``Firewall.execute``, but calls that need a person are held.

        Returns the tool's result when it ran, an ``ApprovalRequest`` when it
        was held, or a ``"SECURITY BLOCK: ..."`` string when the policy refused
        it (or raises ``FirewallBlock`` with ``raise_on_block``).
        """
        fw = self.firewall
        if fw.shadow:
            # Shadow mode observes; it must never change what happens.
            return fw.execute(tool, fn, arguments, ctx=ctx, session_id=session_id,
                              principal=principal, raise_on_block=raise_on_block)
        ctx = ctx or fw.session(session_id, principal)
        arguments = dict(arguments or {})
        with fw.session_lock(ctx.session_id):
            decision = fw.inspect(tool, arguments, ctx=ctx)
            if needs_human(decision):
                try:
                    return self.submit(tool, arguments, ctx, decision, fn=fn)
                except ApprovalError as exc:
                    fw._log("tool_call_blocked", decision, ctx,
                            {"arguments": redact(arguments), "approval_error": str(exc)})
                    if raise_on_block:
                        raise FirewallBlock(decision) from exc
                    return "SECURITY BLOCK: " + str(exc)
            if decision.blocked:
                fw._log("tool_call_blocked", decision, ctx, {"arguments": redact(arguments)})
                if raise_on_block:
                    raise FirewallBlock(decision)
                return "SECURITY BLOCK: " + decision.reason
            return fw._perform(tool, fn, arguments, ctx, decision)

    # --------------------------------------------------------------- deciding

    def approve(self, request_id: str, reviewer: str, note: str = "") -> ApprovalRequest:
        """Approve a pending request.

        The call is re-inspected first. If the policy now hard blocks it, the
        request is rejected by fAIrewall instead and nothing runs; check the
        returned request's ``status``. If the request holds a function (Python
        API), the call runs now. Use ``approve_and_run`` to get its result.
        """
        req, _ = self._approve(request_id, reviewer, note)
        return req

    def approve_and_run(self, request_id: str, reviewer: str, note: str = "") -> Any:
        """Approve, run the held function, and return its result.

        Returns ``None`` when there was nothing to run (HTTP flow) or when the
        re-check rejected the request; check ``get(request_id).status``.
        """
        _, result = self._approve(request_id, reviewer, note)
        return result

    def reject(self, request_id: str, reviewer: str, note: str = "") -> ApprovalRequest:
        """Reject a pending request. Nothing runs."""
        reviewer = self._check_reviewer(reviewer)
        with self._lock:
            req = self._pending_locked(request_id)
            self._decide_locked(req, ApprovalStatus.REJECTED, reviewer, note)
        self._audit("approval_rejected", req, {})
        self._teach(req, "malicious", reviewer, note)
        return req

    # ---------------------------------------------------------------- reading

    def get(self, request_id: str) -> Optional[ApprovalRequest]:
        with self._lock:
            self._expire_locked(self._clock())
            return self._requests.get(request_id)

    def pending(self) -> List[ApprovalRequest]:
        """Pending requests, oldest first."""
        return self.list(ApprovalStatus.PENDING)

    def list(self, status: Optional[ApprovalStatus] = None) -> List[ApprovalRequest]:
        with self._lock:
            self._expire_locked(self._clock())
            items = [r for r in self._requests.values() if status is None or r.status is status]
        return sorted(items, key=lambda r: r.created_at)

    # -------------------------------------------------------------- internals

    def _teach(self, req: ApprovalRequest, verdict: str, reviewer: str, note: str) -> None:
        """Turn the reviewer's decision into a label, so fAIrewall learns from it.

        Only calls held for a content threat have a case; business approvals
        (a refund over the limit, a tool that always needs a person) teach nothing.
        """
        baseline = getattr(self.firewall, "baseline", None)
        if baseline is not None and "baseline.novel_action" in req.rule_ids:
            # The reviewer vouched for (or refused) this new action: the baseline learns it.
            baseline.observe(req.principal_id, self.firewall.policy.canonical_tool(req.tool),
                             req.arguments, self.firewall.spend_of(req.tool, req.arguments),
                             "approved" if verdict == "benign" else "rejected", reviewer=reviewer)
        memory = getattr(self.firewall, "memory", None)
        if memory is None or not req.case_id:
            return
        from .learning import LearningError
        try:
            memory.label(req.case_id, verdict, reviewer, note=note, via="approval:" + req.id)
        except LearningError as exc:  # e.g. already labelled from the review page
            self.firewall.audit.append("learning_label_skipped", {
                "approval_id": req.id, "case_id": req.case_id, "reason": str(exc)})

    def _approve(self, request_id: str, reviewer: str, note: str):
        reviewer = self._check_reviewer(reviewer)
        fw = self.firewall
        with self._lock:
            req = self._pending_locked(request_id)
            if reviewer == req.principal_id:
                raise ApprovalError("A principal cannot approve its own request.")
            # Claim it so a second reviewer cannot approve it concurrently.
            self._decide_locked(req, ApprovalStatus.APPROVED, reviewer, note)

        ctx = fw.session(req.session_id)
        with fw.session_lock(ctx.session_id):
            recheck = fw.inspect(req.tool, req.arguments, ctx=ctx)
            if recheck.blocked and not needs_human(recheck):
                # Name only what now blocks it; "needs approval" is already satisfied.
                hard = [f for f in recheck.findings
                        if f.action is Action.BLOCK and f.rule_id != APPROVAL_ONLY_RULE]
                why = "; ".join("[%s] %s" % (f.rule_id, f.message) for f in hard)
                with self._lock:
                    req.status = ApprovalStatus.REJECTED
                    req.decided_by = "fairewall"
                    req.note = "Approved by %s, but the policy now blocks it: %s" % (reviewer, why)
                self._audit("approval_rejected", req, {"recheck_reason": why,
                                                       "approved_by": reviewer})
                self._teach(req, "benign", reviewer, note)
                return req, None

            self._audit("approval_granted", req, {})
            self._teach(req, "benign", reviewer, note)
            if req._fn is None:
                return req, None
            fn, req._fn = req._fn, None
            result = fw._perform(req.tool, fn, req.arguments, ctx, recheck,
                                 extra={"approval_id": req.id, "approved_by": reviewer})
            req.executed = True
            return req, result

    @staticmethod
    def _check_reviewer(reviewer: str) -> str:
        reviewer = (reviewer or "").strip()
        if not reviewer:
            raise ApprovalError("A reviewer name is required, so the audit log shows who decided.")
        return reviewer

    def _pending_locked(self, request_id: str) -> ApprovalRequest:
        self._expire_locked(self._clock())
        req = self._requests.get(request_id)
        if req is None:
            raise ApprovalError("No approval request with id %r." % request_id)
        if not req.pending:
            raise ApprovalError("Request %s is already %s." % (request_id, req.status.value))
        return req

    def _decide_locked(self, req: ApprovalRequest, status: ApprovalStatus,
                       reviewer: str, note: str) -> None:
        req.status = status
        req.decided_by = reviewer
        req.decided_at = self._clock()
        req.note = note

    def _expire_locked(self, now: float) -> None:
        for req in self._requests.values():
            if req.pending and req.expires_at is not None and now >= req.expires_at:
                req.status = ApprovalStatus.EXPIRED
                req.decided_at = now
                req._fn = None
                self._audit("approval_expired", req, {})

    def _evict_decided_locked(self) -> None:
        decided = sorted((r for r in self._requests.values() if not r.pending),
                         key=lambda r: r.decided_at or r.created_at)
        for req in decided[: max(1, len(self._requests) - self.max_requests + 1)]:
            del self._requests[req.id]

    def _audit(self, event: str, req: ApprovalRequest, extra: Dict[str, Any]) -> None:
        self.firewall.audit.append(event, {
            "approval_id": req.id,
            "tool": req.tool,
            "session_id": req.session_id,
            "principal": req.principal_id,
            "status": req.status.value,
            "reason": req.reason,
            "rule_ids": list(req.rule_ids),
            "decided_by": req.decided_by,
            "note": req.note,
            "policy_fingerprint": self.firewall.policy.fingerprint(),
            **extra,
        })
