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
from typing import Any, Dict, List, Optional

from ..policy import Policy, Rule
from ..types import Action, Context, Finding, Severity, ToolCall


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

    def _amounts(self, call: ToolCall, policy: Policy) -> Dict[str, Optional[float]]:
        found: Dict[str, Optional[float]] = {}
        for name in policy.spend_arg_names:
            if name in call.arguments:
                found[name] = coerce_amount(call.arguments[name])
        return found

    def _spend_total(self, call: ToolCall, policy: Policy) -> float:
        amounts = self._amounts(call, policy)
        valid = [a for a in amounts.values() if a is not None]
        return max(valid) if valid else 0.0

    def _limit_for(self, arg_name, call, ctx, policy):
        """Most specific ceiling wins: tool override, then principal, then policy."""
        tool_policy = policy.tool(call.tool)
        if tool_policy and arg_name in tool_policy.max_values:
            return tool_policy.max_values[arg_name], "tools." + call.tool + ".max_values." + arg_name
        if ctx.principal.max_spend is not None:
            if ctx.principal.max_spend < policy.max_spend_per_transaction:
                return ctx.principal.max_spend, "principal.max_spend"
        return policy.max_spend_per_transaction, "policy.max_spend_per_transaction"

    def evaluate(self, call: ToolCall, ctx: Context, policy: Policy) -> List[Finding]:
        findings: List[Finding] = []
        amounts = self._amounts(call, policy)
        if not amounts:
            return findings

        for arg_name, amount in amounts.items():
            if amount is None:
                findings.append(
                    Finding(
                        rule_id="financial.unparseable_amount",
                        action=Action.BLOCK,
                        severity=Severity.HIGH,
                        message=(
                            "Unparseable spend amount in argument '%s': %r; failing closed."
                            % (arg_name, call.arguments.get(arg_name))
                        ),
                        evidence={
                            "argument": arg_name,
                            "raw_value": str(call.arguments.get(arg_name)),
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

            limit, source = self._limit_for(arg_name, call, ctx, policy)
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

