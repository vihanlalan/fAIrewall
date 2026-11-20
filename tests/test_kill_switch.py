"""Kill switch: stop agents now, at every scope, through every path."""

import json

import pytest
from fastapi.testclient import TestClient

from fairewall import Firewall, Policy, ToolPolicy
from fairewall.approvals import ApprovalQueue, ApprovalStatus
from fairewall.firewall import KILL_SWITCH_RULE, KillSwitchError
from fairewall.proxy import create_app
from fairewall.types import Principal


def _blocked_by_switch(d):
    return d.blocked and [f.rule_id for f in d.findings] == [KILL_SWITCH_RULE]


def test_freeze_all_blocks_every_call_and_unfreeze_restores():
    fw = Firewall()
    assert fw.inspect("lookup", {}, session_id="a").allowed
    record = fw.freeze(reason="duplicate refunds", by="ops")
    assert record["scope"] == "all" and record["by"] == "ops"
    d = fw.inspect("lookup", {}, session_id="a")
    assert _blocked_by_switch(d) and d.route == "kill_switch"
    assert "duplicate refunds" in d.reason
    assert fw.unfreeze(by="ops") is True
    assert fw.inspect("lookup", {}, session_id="a").allowed
    assert fw.unfreeze() is False  # nothing left to release


def test_session_and_principal_scopes_are_narrow():
    fw = Firewall()
    fw.freeze("session", "run-1")
    assert _blocked_by_switch(fw.inspect("lookup", {}, session_id="run-1"))
    assert fw.inspect("lookup", {}, session_id="run-2").allowed

    fw.freeze("principal", "billing-bot")
    bot = fw.session("run-3", Principal(id="billing-bot"))
    assert _blocked_by_switch(fw.inspect("lookup", {}, ctx=bot))
    other = fw.session("run-4", Principal(id="support-bot"))
    assert fw.inspect("lookup", {}, ctx=other).allowed
    assert {(f["scope"], f["target"]) for f in fw.freezes()} == {
        ("session", "run-1"), ("principal", "billing-bot")}


def test_shadow_mode_and_flag_only_rules_cannot_soften_a_freeze():
    fw = Firewall(policy=Policy(flag_only_rules=["killswitch"]), shadow=True)
    fw.freeze()
    assert _blocked_by_switch(fw.inspect("lookup", {}, session_id="s"))


def test_execute_never_runs_the_tool_while_frozen():
    fw = Firewall()
    ran = []
    fw.freeze()
    out = fw.execute("lookup", lambda: ran.append(1) or "done", {}, session_id="s")
    assert ran == [] and out.startswith("SECURITY BLOCK")


def test_approval_granted_during_a_freeze_does_not_run():
    policy = Policy(tools={"wire": ToolPolicy("wire", require_human_approval=True)})
    fw = Firewall(policy=policy)
    queue = ApprovalQueue(fw)
    ran = []
    ctx = fw.session("s")
    decision = fw.inspect("wire", {"amount": 10}, ctx=ctx)
    req = queue.submit("wire", {"amount": 10}, ctx, decision, fn=lambda amount: ran.append(amount))
    fw.freeze(reason="incident")
    result = queue.approve(req.id, reviewer="alice")
    assert result.status is ApprovalStatus.REJECTED and result.decided_by == "fairewall"
    assert ran == []


def test_frozen_state_survives_session_reset_and_prune():
    fw = Firewall()
    fw.freeze("session", "s")
    fw.reset("s")
    fw.reset()
    fw.prune_stale_sessions(ttl=0)
    assert _blocked_by_switch(fw.inspect("lookup", {}, session_id="s"))


def test_bad_requests_are_refused():
    fw = Firewall()
    with pytest.raises(KillSwitchError):
        fw.freeze("galaxy")
    with pytest.raises(KillSwitchError):
        fw.freeze("session")  # no target
    with pytest.raises(KillSwitchError):
        fw.unfreeze("principal", "  ")


def test_freezes_are_audited_and_the_chain_still_verifies():
    fw = Firewall()
    fw.freeze(reason="r", by="ops")
    fw.inspect("lookup", {}, session_id="s")
    fw.unfreeze(by="lead")
    events = [r["event"] for r in fw.audit.records()]
    assert events[0] == "kill_switch_engaged" and events[-1] == "kill_switch_released"
    assert fw.audit.verify().valid


def test_freezes_persist_across_restart(tmp_path):
    path = str(tmp_path / "ks.json")
    fw = Firewall(kill_switch_path=path)
    fw.freeze("principal", "billing-bot", reason="incident 42", by="ops")
    restarted = Firewall(kill_switch_path=path)
    assert [(f["scope"], f["target"], f["reason"]) for f in restarted.freezes()] == [
        ("principal", "billing-bot", "incident 42")]
    restarted.unfreeze("principal", "billing-bot")
    assert Firewall(kill_switch_path=path).freezes() == []


def test_unreadable_state_file_fails_closed(tmp_path):
    path = tmp_path / "ks.json"
    path.write_text("{not json", encoding="utf-8")
    fw = Firewall(kill_switch_path=str(path))
    assert _blocked_by_switch(fw.inspect("lookup", {}, session_id="s"))
    assert fw.freezes()[0]["by"] == "fairewall"


def test_no_freeze_costs_nothing_measurable():
    import time
    fw = Firewall()
    ctx = fw.session("s")
    started = time.perf_counter()
    for _ in range(10000):
        fw.frozen_for(ctx)
    assert (time.perf_counter() - started) * 1000 < 50  # < 5 microseconds a call


# ------------------------------------------------------------------ gateway

def _client(**kw):
    return TestClient(create_app(api_key="agent", reviewer_api_key="boss", **kw))


AGENT = {"X-API-Key": "agent"}
BOSS = {"X-API-Key": "boss"}


def test_gateway_freeze_needs_a_key_and_either_key_works():
    c = _client()
    assert c.post("/v1/killswitch/freeze", json={}).status_code == 401
    assert c.post("/v1/killswitch/freeze", json={"reason": "x"}, headers=AGENT).status_code == 200
    assert c.post("/v1/killswitch/freeze", json={"scope": "session", "target": "s"}, headers=BOSS).status_code == 200
    status = c.get("/v1/killswitch", headers=AGENT).json()
    assert status["frozen"] is True and len(status["freezes"]) == 2


def test_only_the_reviewer_key_can_release():
    c = _client()
    c.post("/v1/killswitch/freeze", json={}, headers=AGENT)
    assert c.post("/v1/killswitch/unfreeze", json={}, headers=AGENT).status_code == 401
    r = c.post("/v1/killswitch/unfreeze", json={"by": "lead"}, headers=BOSS)
    assert r.status_code == 200 and r.json()["frozen"] is False
    assert c.post("/v1/killswitch/unfreeze", json={}, headers=BOSS).status_code == 404


def test_gateway_rejects_bad_scope():
    c = _client()
    assert c.post("/v1/killswitch/freeze", json={"scope": "galaxy"}, headers=AGENT).status_code == 400
    assert c.post("/v1/killswitch/freeze", json={"scope": "session"}, headers=AGENT).status_code == 400


def test_health_shows_frozen_and_tool_calls_are_blocked():
    c = _client()
    assert c.get("/health").json()["frozen"] is False
    c.post("/v1/killswitch/freeze", json={"reason": "incident"}, headers=AGENT)
    assert c.get("/health").json()["frozen"] is True
    r = c.post("/v1/inspect/tool", json={"tool": "lookup", "session_id": "s"}, headers=AGENT).json()
    assert r["blocked"] is True
    assert r["decision"]["findings"][0]["rule_id"] == KILL_SWITCH_RULE


def test_held_call_is_not_queued_while_frozen():
    policy = Policy(tools={"wire": ToolPolicy("wire", require_human_approval=True)})
    c = TestClient(create_app(policy=policy, api_key="agent", reviewer_api_key="boss"))
    c.post("/v1/killswitch/freeze", json={}, headers=AGENT)
    r = c.post("/v1/inspect/tool", json={"tool": "wire", "hold_for_approval": True}, headers=AGENT).json()
    assert r["blocked"] is True and not r.get("pending_approval")


def test_chat_proxy_refuses_without_calling_the_model(monkeypatch):
    import httpx

    called = []

    class FailIfUsed:
        def __init__(self, *a, **kw):
            called.append(1)

    monkeypatch.setattr(httpx, "AsyncClient", FailIfUsed)
    c = _client(upstream_url="http://upstream.invalid")
    c.post("/v1/killswitch/freeze", json={"scope": "session", "target": "run-9"}, headers=AGENT)
    r = c.post("/v1/chat/completions", headers={"X-Session-Id": "run-9"},
               json={"model": "m", "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 423 and r.json()["error"]["type"] == "fairewall_kill_switch"
    assert called == []


def test_console_has_the_kill_switch():
    page = _client().get("/console").text
    for marker in ('id="k-freeze"', 'id="kill-banner"', "/v1/killswitch/freeze", "/v1/killswitch/unfreeze"):
        assert marker in page


def test_freeze_file_written_by_gateway(tmp_path):
    path = tmp_path / "ks.json"
    c = _client(kill_switch_path=str(path))
    c.post("/v1/killswitch/freeze", json={"reason": "r"}, headers=AGENT)
    assert json.loads(path.read_text(encoding="utf-8"))["freezes"][0]["scope"] == "all"
    assert c.get("/v1/killswitch", headers=AGENT).json()["persistent"] is True
