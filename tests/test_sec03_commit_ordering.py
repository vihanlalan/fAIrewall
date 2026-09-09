import time
import pytest
from fairewall.firewall import Firewall
from fairewall.policy import Policy
from fairewall.rules.financial import FinancialRule
from fairewall.rules.velocity import VelocityRule
from fairewall.types import Context


def test_failed_tool_call_does_not_consume_budget():
    """SEC-03: If a guarded tool raises an unhandled exception during execution,

    its spend and velocity counters must NOT be committed.
    """
    policy = Policy(
        max_spend_per_transaction=500.0,
        max_spend_per_session=1000.0,
        max_calls_per_minute=10,
    )
    fw = Firewall(policy=policy)
    ctx = fw.session("s_sec03_fail")

    fin_rule = next(r for r in fw.rules if isinstance(r, FinancialRule))
    vel_rule = next(r for r in fw.rules if isinstance(r, VelocityRule))

    assert fin_rule.session_spend("s_sec03_fail") == 0.0
    initial_call_count = len(vel_rule._window((ctx.session_id, None), time.time()))

    def broken_payment(amount: float):
        raise RuntimeError("Payment gateway network error")

    # The tool call fails during execution
    with pytest.raises(RuntimeError, match="Payment gateway network error"):
        fw.execute("pay", broken_payment, {"amount": 250.0}, ctx=ctx)

    # SEC-03: Spend and velocity counters must remain UNCHANGED after failure!
    assert fin_rule.session_spend("s_sec03_fail") == 0.0
    assert len(vel_rule._window((ctx.session_id, None), time.time())) == initial_call_count


def test_successful_tool_call_still_consumes_budget():
    """SEC-03: Successful tool calls must advance spend and velocity counters normally."""
    policy = Policy(
        max_spend_per_transaction=500.0,
        max_spend_per_session=1000.0,
        max_calls_per_minute=10,
    )
    fw = Firewall(policy=policy)
    ctx = fw.session("s_sec03_success")

    fin_rule = next(r for r in fw.rules if isinstance(r, FinancialRule))
    vel_rule = next(r for r in fw.rules if isinstance(r, VelocityRule))

    def working_payment(amount: float):
        return f"paid {amount}"

    res = fw.execute("pay", working_payment, {"amount": 250.0}, ctx=ctx)
    assert res == "paid 250.0"

    assert fin_rule.session_spend("s_sec03_success") == 250.0
    assert len(vel_rule._window((ctx.session_id, None), time.time())) == 1


def test_blocked_call_never_reaches_commit_or_fn():
    """SEC-03: A call that fails inspect() must neither execute fn() nor advance counters."""
    policy = Policy(
        max_spend_per_transaction=500.0,
        max_spend_per_session=1000.0,
    )
    fw = Firewall(policy=policy)
    ctx = fw.session("s_sec03_block")

    fin_rule = next(r for r in fw.rules if isinstance(r, FinancialRule))

    executed = False

    def monitored_tool(amount: float):
        nonlocal executed
        executed = True
        return "paid"

    # Attempt $600 with $500 ceiling
    res = fw.execute("pay", monitored_tool, {"amount": 600.0}, ctx=ctx)
    assert "SECURITY BLOCK" in str(res)
    assert executed is False
    assert fin_rule.session_spend("s_sec03_block") == 0.0
