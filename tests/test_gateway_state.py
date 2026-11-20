"""Several gateway instances, one database: the state Cloud Run needs to be shared, is."""
import threading

import pytest
from fastapi.testclient import TestClient

from fairewall.anchor import Anchorer
from fairewall.approvals import ApprovalError, ApprovalStatus
from fairewall.policy import Policy, ToolPolicy
from fairewall.proxy import create_app
from fairewall.state import DurableApprovalQueue, GatewayState, build_gateway_firewall
from fairewall.types import Principal, Trust

AGENT = {"Authorization": "Bearer agent-key"}
REVIEWER = {"Authorization": "Bearer boss-key"}


def policy():
    return Policy(
        max_spend_per_session=100.0,
        tools={
            "pay": ToolPolicy("pay", required_args=["amount"]),
            "send_email": ToolPolicy("send_email", forbid_when_tainted=True),
            "contract": ToolPolicy("contract", require_human_approval=True),
            "lookup": ToolPolicy("lookup", rate_limit_per_minute=3),
        })


def instance(db, **kw):
    """One gateway process. Two of these on one database = two Cloud Run instances."""
    fw = build_gateway_firewall(policy=policy(), database=db, **kw)
    fw.state.freeze_cache_s = 0  # tests want every read fresh
    return fw


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "gateway.sqlite")


def test_taint_seen_on_one_instance_holds_on_the_other(db):
    a, b = instance(db), instance(db)
    a.inspect_input("Quarterly report", trust=Trust.UNTRUSTED, ctx=a.session("run-1"), source="web")
    d = b.inspect("send_email", {"to": "x@y.z"}, ctx=b.session("run-1"))
    assert d.blocked and any(f.rule_id == "taint.untrusted_context" for f in d.findings)


def test_a_budget_is_shared_and_no_spend_is_lost(db):
    a, b = instance(db), instance(db)
    a.commit("pay", {"amount": 60.0}, a.session("run-1"))
    b.commit("pay", {"amount": 30.0}, b.session("run-1"))
    # 90 spent across two instances: 20 more breaks the 100 session budget on either.
    for fw in (a, b):
        d = fw.inspect("pay", {"amount": 20.0}, ctx=fw.session("run-1"))
        assert d.blocked and any(f.rule_id == "financial.session_budget" for f in d.findings)
    assert a.inspect("pay", {"amount": 20.0}, ctx=a.session("run-2")).allowed  # other sessions untouched


def test_concurrent_commits_from_many_instances_lose_nothing(db):
    fleet = [instance(db) for _ in range(4)]

    def spend(fw):
        for _ in range(5):
            fw.commit("pay", {"amount": 1.0}, fw.session("run-9"))

    threads = [threading.Thread(target=spend, args=(fw,)) for fw in fleet]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    fresh = instance(db)
    fresh.session("run-9")
    assert fresh.rules[2].session_spend("run-9") == pytest.approx(20.0)


def test_rate_limits_count_calls_on_every_instance(db):
    a, b = instance(db), instance(db)
    a.commit("lookup", {}, a.session("r"))
    b.commit("lookup", {}, b.session("r"))
    a.commit("lookup", {}, a.session("r"))
    d = b.inspect("lookup", {}, ctx=b.session("r"))
    assert d.blocked and any(f.rule_id == "velocity.tool_rate" for f in d.findings)


def test_a_freeze_on_one_instance_stops_agents_on_all(db):
    a, b = instance(db), instance(db)
    a.freeze("principal", "agent-7", reason="incident", by="sec-lead")
    d = b.inspect("lookup", {}, ctx=b.session("r", Principal("agent-7")))
    assert d.blocked and d.route == "kill_switch"
    assert b.unfreeze("principal", "agent-7", by="sec-lead")
    assert a.inspect("lookup", {}, ctx=a.session("r", Principal("agent-7"))).allowed


def test_unreadable_shared_state_fails_closed(db):
    a = instance(db)

    def broken():
        raise RuntimeError("database down")

    a.state.freezes = lambda fresh=False: broken()
    d = a.inspect("lookup", {}, ctx=a.session("r"))
    assert d.blocked and "could not be read" in d.findings[0].message


def test_evicting_a_cached_session_keeps_the_shared_one(db):
    a, b = instance(db), instance(db)
    a.inspect_input("page", trust=Trust.UNTRUSTED, ctx=a.session("r"), source="web")
    a.reset("r", shared=False)                      # cache eviction on instance a
    assert b.session("r").tainted
    a.reset("r")                                    # an operator clears it after review
    assert not b.session("r").tainted


# ------------------------------------------------------------------ approvals

def held(fw, queue, sid="run-1", principal="agent-7"):
    ctx = fw.session(sid, Principal(principal))
    decision = fw.inspect("contract", {"customer": "Priya"}, ctx=ctx)
    return queue.submit("contract", {"customer": "Priya"}, ctx, decision)


def test_pending_approvals_survive_a_restart(db):
    a = instance(db)
    req = held(a, DurableApprovalQueue(a, a.state))
    restarted = instance(db)
    queue = DurableApprovalQueue(restarted, restarted.state)
    assert [r.id for r in queue.pending()] == [req.id]
    done = queue.approve(req.id, reviewer="legal")
    assert done.status is ApprovalStatus.APPROVED and done.decided_by == "legal"


def test_two_reviewers_on_two_instances_get_one_decision(db):
    a, b = instance(db), instance(db)
    req = held(a, DurableApprovalQueue(a, a.state))
    queues = [DurableApprovalQueue(fw, fw.state) for fw in (a, b, a, b)]
    results = []

    def decide(q, i):
        try:
            results.append(("ok", q.approve(req.id, reviewer="reviewer-%d" % i).decided_by))
        except ApprovalError as exc:
            results.append(("refused", str(exc)))

    threads = [threading.Thread(target=decide, args=(q, i)) for i, q in enumerate(queues)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert [r[0] for r in results].count("ok") == 1
    assert all("already approved" in r[1] for r in results if r[0] == "refused")


def test_self_approval_and_expiry_still_hold(db):
    now = [1000.0]
    a = instance(db)
    queue = DurableApprovalQueue(a, a.state, ttl_seconds=60, clock=lambda: now[0])
    req = held(a, queue)
    with pytest.raises(ApprovalError, match="own request"):
        queue.approve(req.id, reviewer="agent-7")
    now[0] += 61
    with pytest.raises(ApprovalError, match="expired"):
        queue.approve(req.id, reviewer="legal")
    assert queue.get(req.id).status is ApprovalStatus.EXPIRED


def test_approval_rechecks_with_the_stored_principal(db):
    a = instance(db)
    queue = DurableApprovalQueue(a, a.state)
    req = held(a, queue, sid="run-5")
    a.freeze("principal", "agent-7", reason="incident")
    b = instance(db)  # another instance, which never saw this session's principal
    done = DurableApprovalQueue(b, b.state).approve(req.id, reviewer="legal")
    assert done.status is ApprovalStatus.REJECTED and done.decided_by == "fairewall"


# ---------------------------------------------------------- over HTTP + audit

def test_two_gateway_apps_share_one_database_end_to_end(db):
    def app():
        return TestClient(create_app(policy=policy(), api_key="agent-key",
                                     reviewer_api_key="boss-key", database=db))

    one, two = app(), app()
    one.post("/v1/inspect/input", headers=AGENT, json={
        "text": "web page", "trust": "untrusted", "source": "web", "session_id": "s1"})
    r = two.post("/v1/inspect/tool", headers=AGENT, json={
        "tool": "send_email", "arguments": {"to": "a@b.c"}, "session_id": "s1"}).json()
    assert r["blocked"]

    held_req = one.post("/v1/inspect/tool", headers=AGENT, json={
        "tool": "contract", "arguments": {"customer": "Priya"}, "session_id": "s2",
        "principal_id": "agent-7", "hold_for_approval": True}).json()["approval"]
    assert [x["id"] for x in two.get("/v1/approvals?status_filter=pending",
                                      headers=REVIEWER).json()["approvals"]] == [held_req["id"]]
    ok = two.post("/v1/approvals/%s/approve" % held_req["id"], headers=REVIEWER,
                  json={"reviewer": "legal"})
    again = one.post("/v1/approvals/%s/approve" % held_req["id"], headers=REVIEWER,
                     json={"reviewer": "legal-2"})
    assert ok.status_code == 200 and again.status_code == 409

    # Each instance wrote its own audit chain; one anchor batch covers both.
    batch = Anchorer(db).seal()
    assert len(batch["ranges"]) == 2 and batch["size"] > 4
    assert Anchorer(db).verify()["valid"]
