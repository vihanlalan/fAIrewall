"""Spend fields hidden in nested arguments or minor units must still be capped."""

from fairewall.policy import Policy, ToolPolicy
from fairewall.rules.financial import FinancialRule
from fairewall.types import Action, Context, ToolCall


def _rules(args, policy=None, session="s"):
    rule = FinancialRule()
    policy = policy or Policy(max_spend_per_transaction=500.0, max_spend_per_session=1000.0)
    findings = rule.evaluate(ToolCall(tool="pay", arguments=args), Context(session_id=session), policy)
    return {f.rule_id for f in findings if f.action is Action.BLOCK}, rule, policy


def test_nested_amount_is_capped():
    blocked, _, _ = _rules({"payment": {"amount": 900, "currency": "INR"}})
    assert "financial.transaction_limit" in blocked


def test_deeply_nested_amount_is_capped():
    blocked, _, _ = _rules({"order": {"lines": [{"meta": {"amount": "1,200.00"}}]}})
    assert "financial.transaction_limit" in blocked


def test_minor_units_are_converted():
    over, _, _ = _rules({"amount_cents": 90000})   # $900
    assert "financial.transaction_limit" in over
    under, _, _ = _rules({"amount_paise": 40000})  # ₹400
    assert not under


def test_line_items_are_summed_against_the_session_budget():
    # Four $300 items: each under the $500 cap, $1,200 together over the $1,000 budget.
    blocked, _, _ = _rules({"items": [{"amount": 300}] * 4})
    assert "financial.transaction_limit" not in blocked
    assert "financial.session_budget" in blocked


def test_amount_and_total_for_one_payment_are_not_double_counted():
    rule = FinancialRule()
    policy = Policy(max_spend_per_transaction=500.0, max_spend_per_session=1000.0)
    call = ToolCall(tool="pay", arguments={"amount": 400, "total": 400})
    ctx = Context(session_id="s")
    rule.commit(call, ctx, policy)
    assert rule.session_spend("s") == 400


def test_generic_nested_value_text_is_not_blocked():
    blocked, _, _ = _rules({"fields": [{"name": "tier", "value": "Gold"}]})
    assert not blocked


def test_nested_value_number_is_still_capped():
    blocked, _, _ = _rules({"fields": {"value": 900}})
    assert "financial.transaction_limit" in blocked


def test_nested_unparseable_amount_fails_closed():
    blocked, _, _ = _rules({"payment": {"amount": "9e2"}})
    assert "financial.unparseable_amount" in blocked


def test_tool_cap_can_target_a_nested_path():
    policy = Policy(max_spend_per_transaction=500.0, tools={
        "pay": ToolPolicy("pay", max_values={"payment.amount": 100.0})})
    blocked, _, _ = _rules({"payment": {"amount": 150}}, policy=policy)
    assert "financial.transaction_limit" in blocked


def test_scales_round_trip_and_validate():
    p = Policy(spend_arg_scales={"amount_milli": 0.001})
    assert Policy.from_dict(p.to_dict()).spend_arg_scales == {"amount_milli": 0.001}
    try:
        Policy(spend_arg_scales={"bad": 0})
    except ValueError:
        pass
    else:
        raise AssertionError("a zero scale must be rejected")
