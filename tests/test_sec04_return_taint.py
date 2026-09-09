import pytest
from fairewall.firewall import Firewall
from fairewall.policy import Policy, ToolPolicy
from fairewall.types import Action, Context, Trust


def test_guarded_tool_with_produces_untrusted_output_taints_session():
    """SEC-04: A guarded tool configured with produces_untrusted_output=True must

    taint the session upon successful execution, causing subsequent calls to
    tools marked forbid_when_tainted=True to be blocked.
    """
    try:
        fetch_policy = ToolPolicy(name="fetch_url", produces_untrusted_output=True)
    except TypeError:
        fetch_policy = ToolPolicy(name="fetch_url")
        setattr(fetch_policy, "produces_untrusted_output", True)

    policy = Policy(
        tools={
            "fetch_url": fetch_policy,
            "wire_transfer": ToolPolicy(
                name="wire_transfer",
                forbid_when_tainted=True,
            ),
        }
    )
    fw = Firewall(policy=policy)
    ctx = fw.session("sec04_sess_1")

    # Before calling fetch_url, session is clean
    assert not ctx.tainted
    assert fw.inspect("wire_transfer", {"amount": 100}, ctx=ctx).allowed

    def fake_fetch(url: str):
        return f"content from {url}"

    # Execute fetch_url
    res = fw.execute("fetch_url", fake_fetch, {"url": "https://example.com"}, ctx=ctx)
    assert res == "content from https://example.com"

    # Session MUST now be tainted
    assert ctx.tainted is True
    assert "fetch_url" in ctx.taint_sources

    # Subsequent call to forbid_when_tainted tool in the same session must be BLOCKED
    decision = fw.inspect("wire_transfer", {"amount": 100}, ctx=ctx)
    assert decision.blocked is True
    assert any(f.rule_id == "taint.untrusted_context" for f in decision.findings)


def test_guarded_tool_without_flag_does_not_taint():
    """SEC-04: A guarded tool with produces_untrusted_output=False (default)

    must NOT taint the session, confirming opt-in and non-breaking behavior.
    """
    try:
        fetch_policy = ToolPolicy(name="fetch_url", produces_untrusted_output=False)
    except TypeError:
        fetch_policy = ToolPolicy(name="fetch_url")

    policy = Policy(
        tools={
            "fetch_url": fetch_policy,
            "wire_transfer": ToolPolicy(
                name="wire_transfer",
                forbid_when_tainted=True,
            ),
        }
    )
    fw = Firewall(policy=policy)
    ctx = fw.session("sec04_sess_2")

    def fake_fetch(url: str):
        return f"content from {url}"

    res = fw.execute("fetch_url", fake_fetch, {"url": "https://example.com"}, ctx=ctx)
    assert res == "content from https://example.com"

    # Session must NOT be tainted
    assert ctx.tainted is False
    assert len(ctx.taint_sources) == 0

    # Subsequent call remains allowed
    assert fw.inspect("wire_transfer", {"amount": 100}, ctx=ctx).allowed is True


def test_taint_persists_across_subsequent_calls_same_session():
    """SEC-04: Taint acquired in a session must not be reset by subsequent

    clean tool calls in the same session.
    """
    try:
        p_fetch = ToolPolicy(name="fetch_url", produces_untrusted_output=True)
        p_calc = ToolPolicy(name="calc", produces_untrusted_output=False)
    except TypeError:
        p_fetch = ToolPolicy(name="fetch_url")
        setattr(p_fetch, "produces_untrusted_output", True)
        p_calc = ToolPolicy(name="calc")

    policy = Policy(
        tools={
            "fetch_url": p_fetch,
            "calc": p_calc,
            "wire_transfer": ToolPolicy(name="wire_transfer", forbid_when_tainted=True),
        }
    )
    fw = Firewall(policy=policy)
    ctx = fw.session("sec04_sess_3")

    # Taint session via untrusted tool
    fw.execute("fetch_url", lambda url: "untrusted data", {"url": "https://evil.com"}, ctx=ctx)
    assert ctx.tainted is True

    # Call a benign tool without flag
    fw.execute("calc", lambda x: x * 2, {"x": 21}, ctx=ctx)

    # Taint must still persist
    assert ctx.tainted is True
    decision = fw.inspect("wire_transfer", {"amount": 50}, ctx=ctx)
    assert decision.blocked is True


def test_manual_inspect_input_escape_hatch_still_works():
    """SEC-04: Manual inspect_input(result, trust=Trust.UNTRUSTED) escape hatch

    must continue to work standalone.
    """
    fw = Firewall(policy=Policy(
        tools={"wire_transfer": ToolPolicy(name="wire_transfer", forbid_when_tainted=True)}
    ))
    ctx = fw.session("sec04_manual")
    fw.inspect_input("scraped payload", trust=Trust.UNTRUSTED, ctx=ctx, source="manual_crawler")
    assert ctx.tainted is True
    assert "manual_crawler" in ctx.taint_sources
    assert fw.inspect("wire_transfer", {"amount": 100}, ctx=ctx).blocked is True
