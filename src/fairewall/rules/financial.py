"""Financial boundary guard: per-transaction ceilings and per-session budget.

The per-session budget is the part that matters. A per-transaction cap alone is
trivially defeated by an agent that has been talked into issuing fifty refunds
of 499 each -- every one of them individually within policy.
"""

from __future__ import annotations

from collections import defaultdict
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
        return float(value)
    if isinstance(value, str):
        cleaned = "".join(ch for ch in value if ch.isdigit() or ch in ".-")
        try:
            return float(cleaned)
        except ValueError:
            return None
    return None


class FinancialRule(Rule):
    id = "financial"

    def __init__(self) -> None:
        self._session_spend: Dict[str, float] = defaultdict(float)

    def session_spend(self, session_id: str) -> float:
        return self._session_spend[session_id]

    def _amounts(self, call: ToolCall, policy: Policy) -> Dict[str, float]:
        found: Dict[str, float] = {}
        for name in policy.spend_arg_names:
            if name in call.arguments:
                amount = coerce_amount(call.arguments[name])
                if amount is not None:
                    found[name] = amount
        return found

    def _spend_total(self, call: ToolCall, policy: Policy) -> float:
        amounts = self._amounts(call, policy)
        return max(amounts.values()) if amounts else 0.0

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
        projected = self._session_spend[ctx.session_id] + total
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
                        "already_spent": round(self._session_spend[ctx.session_id], 2),
                        "this_call": total,
                        "budget": policy.max_spend_per_session,
                    },
                )
            )
        return findings

    def commit(self, call: ToolCall, ctx: Context, policy: Policy) -> None:
        self._session_spend[ctx.session_id] += self._spend_total(call, policy)

    def reset(self, session_id: Optional[str] = None) -> None:
        if session_id is None:
            self._session_spend.clear()
        else:
            self._session_spend.pop(session_id, None)
