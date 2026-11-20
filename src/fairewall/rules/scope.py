"""Run scope: the trusted side says what this run is for; anything outside it waits for a person.

An agent run starts from a request the operator or the user made ("refund up to
$40 on ORD-1001"). The application backend -- never the model -- declares that
as the run's scope before the agent starts:

    fw.set_scope("run-42", {"tools": ["lookup_order", "refund"],
                            "args": {"order_id": ["ORD-1001"]},
                            "destinations": [],
                            "max_spend": 40.0})

Then a call that steps outside it is held for a person (``scope.*``), however
convincing the instruction that led there: a different tool, an order the user
never mentioned, an email to a domain not in scope. Spending more than the
run's cap is blocked outright. Scope can only be *narrowed* by the caller that
set it; widening it needs the reviewer (``widen=True``), so an agent that
gains control of its own backend calls still cannot grant itself more.

Fields (all optional; a missing field does not restrict):
  tools         tool names this run may call
  destinations  where it may send things: domains ("acme.in" also covers
                "mail.acme.in"), or exact feature strings ("to:payee=p123")
  args          {argument: [allowed values]} for top-level arguments
  max_spend     money this run may move in total (same units as the policy)
  on_violation  "hold" (default: a person decides) or "block"
  expires_at    Unix time after which every call is held
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional

from ..policy import Policy, Rule
from ..types import Action, Context, Finding, Severity, ToolCall

FIELDS = ("tools", "destinations", "args", "max_spend", "on_violation", "expires_at")


class ScopeError(ValueError):
    """A scope that is malformed, or a widening attempted without the reviewer."""


def normalize(scope: Dict[str, Any]) -> Dict[str, Any]:
    unknown = set(scope) - set(FIELDS) - {"spent", "set_by"}
    if unknown:
        raise ScopeError("Unknown scope field(s): %s" % ", ".join(sorted(unknown)))
    out: Dict[str, Any] = {}
    if scope.get("tools") is not None:
        out["tools"] = sorted({str(t) for t in scope["tools"]})
    if scope.get("destinations") is not None:
        from ..baseline import ActionBaseline
        out["destinations"] = sorted({ActionBaseline.feature_for(str(d)) for d in scope["destinations"]})
    if scope.get("args") is not None:
        if not isinstance(scope["args"], dict):
            raise ScopeError("args must map argument names to lists of allowed values")
        out["args"] = {str(k): sorted({str(v) for v in vals}) for k, vals in scope["args"].items()}
    if scope.get("max_spend") is not None:
        out["max_spend"] = float(scope["max_spend"])
        if out["max_spend"] < 0:
            raise ScopeError("max_spend cannot be negative")
    on = scope.get("on_violation", "hold")
    if on not in ("hold", "block"):
        raise ScopeError("on_violation must be hold or block")
    out["on_violation"] = on
    if scope.get("expires_at") is not None:
        out["expires_at"] = float(scope["expires_at"])
    return out


def narrows(old: Optional[Dict[str, Any]], new: Dict[str, Any]) -> bool:
    """True when *new* allows nothing *old* did not. No scope at all allows everything."""
    if old is None:
        return True
    for key in ("tools", "destinations"):
        if key in old and (key not in new or not set(new[key]) <= set(old[key])):
            return False
    if "args" in old:
        new_args = new.get("args", {})
        for arg, allowed in old["args"].items():
            if arg not in new_args or not set(new_args[arg]) <= set(allowed):
                return False
    if "max_spend" in old and ("max_spend" not in new or new["max_spend"] > old["max_spend"]):
        return False
    if "expires_at" in old and ("expires_at" not in new or new["expires_at"] > old["expires_at"]):
        return False
    if old.get("on_violation") == "block" and new.get("on_violation") != "block":
        return False
    return True


def _dest_allowed(feature: str, allowed: List[str]) -> bool:
    for a in allowed:
        if feature == a:
            return True
        if feature.startswith("domain:") and a.startswith("domain:"):
            host, base = feature[7:], a[7:]
            if host == base or host.endswith("." + base):
                return True
    return False


class ScopeRule(Rule):
    """Enforces each session's declared scope. Stateless without one."""

    id = "scope"

    def __init__(self, clock=time.time) -> None:
        self._scopes: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._clock = clock
        from .financial import FinancialRule
        self._money = FinancialRule()

    # -- state (persisted with the session, like budgets) --------------------
    def snapshot_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            s = self._scopes.get(session_id)
            return dict(s) if s is not None else None

    def restore_session(self, session_id: str, state: Optional[Dict[str, Any]]) -> None:
        if state is not None:
            with self._lock:
                self._scopes[session_id] = dict(state)

    def reset(self, session_id: Optional[str] = None) -> None:
        with self._lock:
            if session_id is None:
                self._scopes.clear()
            else:
                self._scopes.pop(session_id, None)

    def get(self, session_id: str) -> Optional[Dict[str, Any]]:
        return self.snapshot_session(session_id)

    def set(self, session_id: str, scope: Dict[str, Any], *, widen: bool = False,
            by: str = "") -> Dict[str, Any]:
        new = normalize(scope)
        with self._lock:
            old = self._scopes.get(session_id)
            if not widen and not narrows(old, new):
                raise ScopeError("This would widen the run's scope; only a reviewer can do that.")
            new["spent"] = (old or {}).get("spent", 0.0)
            new["set_by"] = by[:100]
            self._scopes[session_id] = new
            return dict(new)

    # -- the rule -------------------------------------------------------------
    def evaluate(self, call: ToolCall, ctx: Context, policy: Policy) -> List[Finding]:
        scope = self.snapshot_session(ctx.session_id)
        if not scope:
            return []
        from ..baseline import destinations
        hold = Action.BLOCK if scope.get("on_violation") == "block" else Action.FLAG
        found: List[Finding] = []

        def out(rule: str, msg: str, **ev: Any) -> None:
            found.append(Finding("scope." + rule, hold, Severity.HIGH,
                                 msg + " This run was not set up for that.", ev))

        if scope.get("expires_at") is not None and self._clock() > scope["expires_at"]:
            out("expired", "The run's scope expired.", expires_at=scope["expires_at"])
        if "tools" in scope and call.tool not in scope["tools"]:
            out("tool_out_of_scope", "Tool %s is outside this run's scope." % call.tool,
                allowed=scope["tools"])
        if "destinations" in scope:
            for d in destinations(call.arguments):
                if not _dest_allowed(d, scope["destinations"]):
                    out("destination_out_of_scope", "Destination %s is outside this run's scope." % d,
                        destination=d, allowed=scope["destinations"])
        for arg, allowed in scope.get("args", {}).items():
            if arg in call.arguments and str(call.arguments[arg]) not in allowed:
                out("argument_out_of_scope", "%s=%s is outside this run's scope."
                    % (arg, call.arguments[arg]), argument=arg, allowed=allowed)
        if "max_spend" in scope:
            amount = self._money._spend_total(call, policy)
            if amount and scope.get("spent", 0.0) + amount > scope["max_spend"]:
                found.append(Finding(
                    "scope.budget", Action.BLOCK, Severity.HIGH,
                    "This call would bring the run's spending to %.2f, over its cap of %.2f."
                    % (scope.get("spent", 0.0) + amount, scope["max_spend"]),
                    {"spent": scope.get("spent", 0.0), "amount": amount, "cap": scope["max_spend"]}))
        return found

    def commit(self, call: ToolCall, ctx: Context, policy: Policy) -> None:
        with self._lock:
            scope = self._scopes.get(ctx.session_id)
            if scope is not None and "max_spend" in scope:
                scope["spent"] = scope.get("spent", 0.0) + self._money._spend_total(call, policy)
