import pytest
from fairewall.policy import Policy, ToolPolicy
from fairewall.rules.velocity import VelocityRule
from fairewall.types import Action, Context, ToolCall


def test_velocity_sliding_window():
    current_time = 1000.0

    def mock_clock():
        return current_time

    rule = VelocityRule(clock=mock_clock)
    policy = Policy(max_calls_per_minute=3)
    ctx = Context(session_id="vel_session")
    call = ToolCall(tool="search", arguments={})

    # Call 1: OK
    assert len(rule.evaluate(call, ctx, policy)) == 0
    rule.commit(call, ctx, policy)

    # Call 2: OK
    current_time += 10.0
    assert len(rule.evaluate(call, ctx, policy)) == 0
    rule.commit(call, ctx, policy)

    # Call 3: OK
    current_time += 10.0
    assert len(rule.evaluate(call, ctx, policy)) == 0
    rule.commit(call, ctx, policy)

    # Call 4 within the 60s window: BLOCKED!
    current_time += 5.0
    findings = rule.evaluate(call, ctx, policy)
    assert len(findings) == 1
    assert findings[0].rule_id == "velocity.session_rate"
    assert findings[0].action == Action.BLOCK

    # Blocked call does not commit; advance time past window
    current_time += 45.0  # now 70s since Call 1
    # Call 1 has rolled out of window, so now OK again!
    assert len(rule.evaluate(call, ctx, policy)) == 0


def test_velocity_per_tool_limit():
    current_time = 5000.0
    rule = VelocityRule(clock=lambda: current_time)
    policy = Policy(
        max_calls_per_minute=100,
        tools={
            "expensive_query": ToolPolicy(
                name="expensive_query",
                rate_limit_per_minute=2,
            )
        },
    )
    ctx = Context(session_id="s_tool")
    call = ToolCall(tool="expensive_query", arguments={})

    rule.commit(call, ctx, policy)
    rule.commit(call, ctx, policy)

    # 3rd call in minute: BLOCKED on tool limit
    findings = rule.evaluate(call, ctx, policy)
    assert len(findings) == 1
    assert findings[0].rule_id == "velocity.tool_rate"
    assert findings[0].action == Action.BLOCK
