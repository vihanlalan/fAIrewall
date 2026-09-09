import pytest
from fairewall.policy import Policy, ToolPolicy
from fairewall.rules.financial import FinancialRule, coerce_amount
from fairewall.types import Action, Context, Principal, ToolCall


def test_coerce_amount():
    assert coerce_amount(100) == 100.0
    assert coerce_amount(125.50) == 125.50
    assert coerce_amount("500") == 500.0
    assert coerce_amount("$1,250.00") == 1250.00
    assert coerce_amount("250.00 USD") == 250.00
    assert coerce_amount("-50") == -50.0
    assert coerce_amount(True) is None
    assert coerce_amount(False) is None
    assert coerce_amount("invalid_text") is None
    assert coerce_amount(None) is None


def test_financial_per_transaction_limit():
    rule = FinancialRule()
    policy = Policy(max_spend_per_transaction=500.0)
    ctx = Context(session_id="s1")

    # Allowed transaction
    call_ok = ToolCall(tool="pay", arguments={"amount": 450.0})
    findings = rule.evaluate(call_ok, ctx, policy)
    assert len(findings) == 0

    # Exceeding transaction
    call_over = ToolCall(tool="pay", arguments={"amount": 550.0})
    findings = rule.evaluate(call_over, ctx, policy)
    assert len(findings) == 1
    assert findings[0].rule_id == "financial.transaction_limit"
    assert findings[0].action == Action.BLOCK


def test_financial_session_cumulative_limit():
    rule = FinancialRule()
    policy = Policy(
        max_spend_per_transaction=500.0,
        max_spend_per_session=1000.0,
    )
    ctx = Context(session_id="sess_cum")

    # Transaction 1: $400 (allowed)
    call1 = ToolCall(tool="pay", arguments={"amount": 400.0})
    assert len(rule.evaluate(call1, ctx, policy)) == 0
    rule.commit(call1, ctx, policy)
    assert rule.session_spend("sess_cum") == 400.0

    # Transaction 2: $400 (allowed)
    call2 = ToolCall(tool="pay", arguments={"amount": 400.0})
    assert len(rule.evaluate(call2, ctx, policy)) == 0
    rule.commit(call2, ctx, policy)
    assert rule.session_spend("sess_cum") == 800.0

    # Transaction 3: $300 (exceeds $1000 total session limit!)
    call3 = ToolCall(tool="pay", arguments={"amount": 300.0})
    findings = rule.evaluate(call3, ctx, policy)
    assert len(findings) == 1
    assert findings[0].rule_id == "financial.session_budget"
    assert findings[0].action == Action.BLOCK

    # Blocked calls do NOT advance session spend if not committed
    assert rule.session_spend("sess_cum") == 800.0


def test_financial_principal_override():
    rule = FinancialRule()
    policy = Policy(max_spend_per_transaction=1000.0)

    # Principal has restricted spend limit of $200
    ctx_restricted = Context(
        session_id="s_p",
        principal=Principal(id="limited_agent", max_spend=200.0),
    )
    call = ToolCall(tool="pay", arguments={"amount": 350.0})
    findings = rule.evaluate(call, ctx_restricted, policy)
    assert len(findings) == 1
    assert findings[0].rule_id == "financial.transaction_limit"
    assert findings[0].action == Action.BLOCK
