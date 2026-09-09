import pytest
from fairewall.firewall import Firewall
from fairewall.policy import Policy
from fairewall.rules.financial import FinancialRule, coerce_amount
from fairewall.types import Action, Context, ToolCall


def test_scientific_notation_rejected_or_correctly_parsed():
    """SEC-01: '1e6' must NOT silently become 16.0 or pass under a $500 ceiling.

    It must either parse to exactly 1,000,000 (and exceed a $500 ceiling) or
    be rejected as unparseable and blocked.
    """
    rule = FinancialRule()
    policy = Policy(max_spend_per_transaction=500.0)
    ctx = Context(session_id="s_sec01_1")

    val = coerce_amount("1e6")
    # Must NOT silently strip 'e' to become 16.0
    assert val != 16.0
    # Must either be None (rejected) or exactly 1,000,000.0
    assert val is None or val == 1_000_000.0

    call = ToolCall(tool="transfer", arguments={"amount": "1e6"})
    findings = rule.evaluate(call, ctx, policy)
    # Under a $500 ceiling, '1e6' MUST be blocked (either transaction_limit or unparseable_amount)
    assert len(findings) > 0
    assert any(f.action == Action.BLOCK for f in findings)
    assert any(
        f.rule_id in ("financial.unparseable_amount", "financial.transaction_limit")
        for f in findings
    )


def test_unparseable_dict_amount_fails_closed():
    """SEC-01: An unparseable complex object like {'cents': 5000000} passed as a spend

    argument must fail closed with Action.BLOCK, not be silently omitted resulting in ALLOW.
    """
    rule = FinancialRule()
    policy = Policy(max_spend_per_transaction=500.0)
    ctx = Context(session_id="s_sec01_2")

    call = ToolCall(tool="transfer", arguments={"amount": {"cents": 5000000}})
    findings = rule.evaluate(call, ctx, policy)

    assert len(findings) > 0
    assert any(f.action == Action.BLOCK for f in findings)
    assert any(f.rule_id == "financial.unparseable_amount" for f in findings)


def test_unparseable_string_fails_closed():
    """SEC-01: Malformed strings such as '1000 USD via wire' or ambiguous separators

    like '1,000.50.00' must result in Action.BLOCK.
    """
    rule = FinancialRule()
    policy = Policy(max_spend_per_transaction=500.0)
    ctx = Context(session_id="s_sec01_3")

    for malformed in ["1000 USD via wire", "1,000.50.00"]:
        call = ToolCall(tool="transfer", arguments={"amount": malformed})
        findings = rule.evaluate(call, ctx, policy)
        assert len(findings) > 0, f"Expected BLOCK for {malformed}"
        assert any(f.action == Action.BLOCK for f in findings), f"Expected BLOCK for {malformed}"
        assert any(f.rule_id == "financial.unparseable_amount" for f in findings)


def test_currency_suffix_does_not_bypass_ceiling():
    """SEC-01: Unsupported or ambiguous currencies like '500 BTC' and '500 JPY' must

    NOT be silently stripped and treated as 500 USD. They must fail closed with Action.BLOCK.
    """
    rule = FinancialRule()
    policy = Policy(max_spend_per_transaction=500.0)
    ctx = Context(session_id="s_sec01_4")

    for ambiguous_curr in ["500 BTC", "500 JPY"]:
        val = coerce_amount(ambiguous_curr)
        # Must not silently strip the currency letters to return 500.0
        assert val is None

        call = ToolCall(tool="transfer", arguments={"amount": ambiguous_curr})
        findings = rule.evaluate(call, ctx, policy)
        assert len(findings) > 0
        assert any(f.action == Action.BLOCK for f in findings)
        assert any(f.rule_id == "financial.unparseable_amount" for f in findings)


def test_clean_valid_amounts_still_pass():
    """SEC-01: Clean, valid numbers and standard USD formats must continue to work

    as expected without false-positive blocks.
    """
    rule = FinancialRule()
    policy = Policy(max_spend_per_transaction=500.0)
    ctx = Context(session_id="s_sec01_5")

    for valid_val, expected in [
        (500, 500.0),
        ("$499.99", 499.99),
        (250.5, 250.5),
        ("500", 500.0),
        ("500.00", 500.0),
    ]:
        parsed = coerce_amount(valid_val)
        assert parsed == expected, f"Failed to coerce {valid_val}"

        call = ToolCall(tool="transfer", arguments={"amount": valid_val})
        findings = rule.evaluate(call, ctx, policy)
        assert not any(f.action == Action.BLOCK for f in findings), f"Unexpected block for {valid_val}"
