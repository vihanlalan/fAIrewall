"""Financial boundary guard: per-transaction ceilings and per-session budget.

The per-session budget is the part that matters. A per-transaction cap alone is
trivially defeated by an agent that has been talked into issuing fifty refunds
of 499 each -- every one of them individually within policy.
"""

from __future__ import annotations

import math
import re
import threading
from collections import defaultdict
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional, Tuple

from ..policy import Policy, Rule
from ..types import Action, Context, Finding, Severity, ToolCall

# How deep to look for spend fields inside nested arguments.
_MAX_DEPTH = 6


def coerce_amount(value: Any) -> Optional[float]:
    """Parse a monetary argument that may arrive as a float, int, or string.

    Models emit "$1,200.00" and "1200 USD" as readily as 1200.0, and a ceiling
    that silently skips values it cannot parse is not a ceiling.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            return None
        return float(value)
    if isinstance(value, Decimal):
        return float(value)
    if not isinstance(value, str):
        return None

    s = value.strip()
    if not s:
        return None

    # Handle optional currency prefix '$'
    if s.startswith("$"):
        s = s[1:].strip()

    # Handle optional currency suffix 'USD' (case-insensitive)
    if s.upper().endswith("USD"):
        s = s[:-3].strip()

    # Strict numeric check: no scientific notation ('e' or 'E'), no letters,
    # valid comma thousands separators if commas are used, or plain digits,
    # and optional single decimal point.
    pattern = r"^-?(\d{1,3}(,\d{3})+|\d+)(\.\d+)?$"
    if not re.match(pattern, s):
        return None

    clean_num = s.replace(",", "")
    try:
        d = Decimal(clean_num)
        return float(d)
    except (InvalidOperation, ValueError):
        return None


class FinancialRule(Rule):
    id = "financial"

    def __init__(self) -> None:
        self._session_spend: Dict[str, float] = defaultdict(float)
        self._lock = threading.Lock()

    def session_spend(self, session_id: str) -> float:
        with self._lock:
            return self._session_spend[session_id]

    def snapshot_session(self, session_id):
        return self.session_spend(session_id)

    def restore_session(self, session_id, state):
        if state is not None:
            with self._lock:
                self._session_spend[session_id] = state

    def _amounts(self, call: ToolCall, policy: Policy) -> Dict[str, Tuple[str, Optional[float], Any]]:
        """Every spend field in the call, at any depth: path -> (field name, amount, raw).

        Amounts are in major units: a field listed in ``spend_arg_scales`` (for
        example ``amount_cents``) is multiplied by its scale. Looking only at the
        top level let ``{"payment": {"amount": 900}}`` and ``{"amount_cents":
        90000}`` through uncapped.

        A *nested* field named ``value`` that does not parse as money is skipped:
        the name is too generic (CRM fields, form values) to fail closed on. Every
        other spend field that does not parse is reported as unparseable, which
        blocks, exactly as at the top level.
        """
        names = set(policy.spend_arg_names)
        scales = policy.spend_arg_scales or {}
        found: Dict[str, Tuple[str, Optional[float], Any]] = {}

        def visit(value: Any, path: str, depth: int) -> None:
            if depth > _MAX_DEPTH:
                return
            if isinstance(value, dict):
                for raw_key, sub in value.items():
                    key = str(raw_key)
                    sub_path = key if not path else path + "." + key
                    if key in names or key in scales:
                        if isinstance(sub, (dict, list)):
                            before = len(found)
                            visit(sub, sub_path, depth + 1)
                            if len(found) == before:
                                # A spend field holding an object with no readable
                                # amount inside, e.g. {"amount": {"cents": 5e6}}:
                                # fail closed rather than let it through uncapped.
                                found[sub_path] = (key, None, sub)
                            continue
                        amount = coerce_amount(sub)
                        if amount is not None and key in scales:
                            amount = amount * scales[key]
                        if amount is None and path and key == "value":
                            continue
                        found[sub_path] = (key, amount, sub)
                    else:
                        visit(sub, sub_path, depth + 1)
            elif isinstance(value, list):
                for i, sub in enumerate(value):
                    visit(sub, "%s[%d]" % (path, i), depth + 1)

        visit(call.arguments, "", 0)
        return found

    def _spend_total(self, call: ToolCall, policy: Policy) -> float:
        """Money this call moves: the largest single amount, or the sum of line items.

        ``amount`` and ``total`` on one call usually describe the same payment, so
        they are not added together. Amounts inside a list are separate line
        items, so they are summed; otherwise ten $90 items would count as $90.
        """
        amounts = self._amounts(call, policy)
        valid = [a for _, a, _ in amounts.values() if a is not None and a > 0]
        if not valid:
            return 0.0
        listed = [a for path, (_, a, _) in amounts.items()
                  if "[" in path and a is not None and a > 0]
        return max(max(valid), sum(listed))

    def _limit_for(self, arg_name, call, ctx, policy, path=None):
        """Most specific ceiling wins: tool override, then principal, then policy."""
        tool_policy = policy.tool(call.tool)
        if tool_policy:
            for key in (path, arg_name):
                if key and key in tool_policy.max_values:
                    return tool_policy.max_values[key], "tools." + call.tool + ".max_values." + key
        if ctx.principal.max_spend is not None:
            if ctx.principal.max_spend < policy.max_spend_per_transaction:
                return ctx.principal.max_spend, "principal.max_spend"
        return policy.max_spend_per_transaction, "policy.max_spend_per_transaction"

    def evaluate(self, call: ToolCall, ctx: Context, policy: Policy) -> List[Finding]:
        findings: List[Finding] = []
        amounts = self._amounts(call, policy)
        if not amounts:
            return findings

        for path, (field_name, amount, raw) in amounts.items():
            arg_name = path
            if amount is None:
                findings.append(
                    Finding(
                        rule_id="financial.unparseable_amount",
                        action=Action.BLOCK,
                        severity=Severity.HIGH,
                        message=(
                            "Unparseable spend amount in argument '%s': %r; failing closed."
                            % (arg_name, raw)
                        ),
                        evidence={
                            "argument": arg_name,
                            "raw_value": str(raw)[:100],
                        },
                    )
                )
                continue

            if amount < 0:
                findings.append(
                    Finding(
                        rule_id="financial.negative_amount",
                        action=Action.BLOCK,
                        severity=Severity.HIGH,
                        message=(
                            "Negative amount %.2f in argument %s; sign inversion turns "
                            "a refund into a charge and slips under every ceiling."
                            % (amount, arg_name)
                        ),
                        evidence={"argument": arg_name, "amount": amount},
                    )
                )
                continue

            limit, source = self._limit_for(field_name, call, ctx, policy, path=path)
            if amount > limit:
                findings.append(
                    Finding(
                        rule_id="financial.transaction_limit",
                        action=Action.BLOCK,
                        severity=Severity.CRITICAL,
                        message=(
                            "Agent attempted %s of %.2f, exceeding the %.2f ceiling."
                            % (call.tool, amount, limit)
                        ),
                        evidence={
                            "argument": arg_name,
                            "amount": amount,
                            "limit": limit,
                            "limit_source": source,
                        },
                    )
                )

        total = self._spend_total(call, policy)
        with self._lock:
            current_spend = self._session_spend[ctx.session_id]
        projected = current_spend + total
        if total and projected > policy.max_spend_per_session:
            findings.append(
                Finding(
                    rule_id="financial.session_budget",
                    action=Action.BLOCK,
                    severity=Severity.CRITICAL,
                    message=(
                        "Call would bring session spend to %.2f, over the %.2f session "
                        "budget." % (projected, policy.max_spend_per_session)
                    ),
                    evidence={
                        "already_spent": round(current_spend, 2),
                        "this_call": total,
                        "budget": policy.max_spend_per_session,
                    },
                )
            )
        return findings

    def commit(self, call: ToolCall, ctx: Context, policy: Policy) -> None:
        with self._lock:
            self._session_spend[ctx.session_id] += self._spend_total(call, policy)

    def reset(self, session_id: Optional[str] = None) -> None:
        with self._lock:
            if session_id is None:
                self._session_spend.clear()
            else:
                self._session_spend.pop(session_id, None)

