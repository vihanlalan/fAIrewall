import pytest
from fairewall.types import (
    Action,
    Context,
    Decision,
    Finding,
    FirewallBlock,
    Principal,
    Severity,
    ToolCall,
    Trust,
)


def test_action_and_severity_rankings():
    f_info = Finding("r1", Action.ALLOW, Severity.INFO, "ok")
    f_flag = Finding("r2", Action.FLAG, Severity.MEDIUM, "flagged")
    f_block = Finding("r3", Action.BLOCK, Severity.CRITICAL, "blocked")

    decision = Decision.from_findings([f_info, f_flag])
    assert decision.action == Action.FLAG
    assert decision.severity == Severity.MEDIUM
    assert decision.allowed is True
    assert decision.blocked is False

    decision2 = Decision.from_findings([f_info, f_flag, f_block])
    assert decision2.action == Action.BLOCK
    assert decision2.severity == Severity.CRITICAL
    assert decision2.allowed is False
    assert decision2.blocked is True
    assert "[r3] blocked" in decision2.reason


def test_principal_and_context():
    p = Principal(id="agent_007", roles=["analyst", "operator"], max_spend=250.0)
    assert p.has_role("analyst") is True
    assert p.has_role("admin") is False
    assert p.max_spend == 250.0

    ctx = Context(session_id="sess_1", principal=p)
    assert ctx.tainted is False
    assert ctx.taint_sources == []

    ctx.taint("web_scraper")
    assert ctx.tainted is True
    assert "web_scraper" in ctx.taint_sources

    # Tainting with the same source does not duplicate
    ctx.taint("web_scraper")
    assert ctx.taint_sources == ["web_scraper"]


def test_tool_call_and_decision_serialization():
    tc = ToolCall(tool="refund", arguments={"amount": 100})
    assert tc.tool == "refund"
    assert tc.arguments == {"amount": 100}
    assert isinstance(tc.id, str) and len(tc.id) > 0

    finding = Finding(
        rule_id="test.rule",
        action=Action.BLOCK,
        severity=Severity.HIGH,
        message="Test rejection",
        evidence={"detail": "foo"},
    )
    decision = Decision.from_findings(
        [finding],
        call_id="call_123",
        session_id="sess_abc",
        tool="refund",
        latency_ms=1.234,
    )
    d = decision.to_dict()
    assert d["call_id"] == "call_123"
    assert d["action"] == "block"
    assert d["severity"] == "high"
    assert len(d["findings"]) == 1
    assert d["findings"][0]["rule_id"] == "test.rule"


def test_firewall_block_exception():
    f = Finding("rule_x", Action.BLOCK, Severity.HIGH, "Stop right there")
    decision = Decision.from_findings([f])
    exc = FirewallBlock(decision)
    assert "Stop right there" in str(exc)
    assert exc.decision == decision
