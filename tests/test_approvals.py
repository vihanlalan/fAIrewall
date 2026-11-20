"""Human approval queue: held calls, approve/reject, re-check, expiry, HTTP."""

import pytest
from fastapi.testclient import TestClient

from fairewall import (
    ApprovalError,
    ApprovalQueue,
    ApprovalRequest,
    ApprovalStatus,
    Firewall,
    GovernanceSDK,
    Policy,
    Principal,
    ToolPolicy,
)
from fairewall.proxy import create_app


def _policy():
    return Policy(
        max_spend_per_transaction=500.0,
        max_spend_per_session=600.0,
        tools={
            "send_contract": ToolPolicy("send_contract", require_human_approval=True),
            "refund": ToolPolicy("refund", require_human_approval=True,
                                 max_values={"amount": 400.0}),
            "lookup": ToolPolicy("lookup"),
        },
    )


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def fw():
    return Firewall(policy=_policy())


@pytest.fixture
def queue(fw):
    return ApprovalQueue(fw)


def test_clean_call_runs_immediately(queue):
    ran = []
    out = queue.run("lookup", lambda q: ran.append(q) or "found", {"q": "ord_1"}, session_id="s")
    assert out == "found" and ran == ["ord_1"]
    assert queue.pending() == []


def test_hard_block_is_not_queued(queue):
    # Over the per-tool cap: a hard block, not something a reviewer can wave through.
    out = queue.run("refund", lambda amount: "paid", {"amount": 900.0}, session_id="s")
    assert isinstance(out, str) and out.startswith("SECURITY BLOCK")
    assert queue.pending() == []


def test_approval_required_call_is_held_then_runs(queue, fw):
    ran = []
    held = queue.run("send_contract", lambda customer: ran.append(customer) or "sent",
                     {"customer": "Priya"}, session_id="s",
                     principal=Principal(id="agent-1"))
    assert isinstance(held, ApprovalRequest)
    assert held.pending and ran == []
    assert "PENDING HUMAN APPROVAL" in str(held)
    assert [r.id for r in queue.pending()] == [held.id]

    result = queue.approve_and_run(held.id, reviewer="ops-lead", note="ok")
    assert result == "sent" and ran == ["Priya"]
    req = queue.get(held.id)
    assert req.status is ApprovalStatus.APPROVED and req.executed
    assert req.decided_by == "ops-lead" and req.note == "ok"

    events = [r["event"] for r in fw.audit.records()]
    assert "approval_requested" in events and "approval_granted" in events
    assert events.index("approval_granted") < events.index("tool_call_executed")
    assert fw.audit.verify().valid


def test_flagged_call_is_held(fw):
    # A rule in flag_only_rules turns a block into a FLAG: that must be held too.
    fw.policy.flag_only_rules = ["financial"]
    q = ApprovalQueue(fw)
    held = q.run("lookup", lambda amount: "x", {"amount": 9000.0}, session_id="s")
    assert isinstance(held, ApprovalRequest)


def test_reject_never_runs(queue):
    ran = []
    held = queue.run("send_contract", lambda customer: ran.append(1), {"customer": "K"},
                     session_id="s")
    req = queue.reject(held.id, reviewer="ops-lead", note="wrong template")
    assert req.status is ApprovalStatus.REJECTED and ran == []
    with pytest.raises(ApprovalError):
        queue.approve(held.id, reviewer="ops-lead")


def test_cannot_decide_twice_or_unknown(queue):
    held = queue.run("send_contract", lambda customer: "sent", {"customer": "K"}, session_id="s")
    queue.approve(held.id, reviewer="a")
    with pytest.raises(ApprovalError, match="already approved"):
        queue.approve(held.id, reviewer="b")
    with pytest.raises(ApprovalError, match="No approval request"):
        queue.approve("nope", reviewer="a")


def test_reviewer_required_and_no_self_approval(queue):
    held = queue.run("send_contract", lambda customer: "sent", {"customer": "K"},
                     session_id="s", principal=Principal(id="agent-1"))
    with pytest.raises(ApprovalError, match="reviewer name"):
        queue.approve(held.id, reviewer="  ")
    with pytest.raises(ApprovalError, match="own request"):
        queue.approve(held.id, reviewer="agent-1")
    assert queue.get(held.id).pending


def test_recheck_rejects_when_budget_used_up_while_waiting(queue):
    # Two $350 refunds held; session budget is $600. Approving both must not overspend.
    paid = []
    a = queue.run("refund", lambda amount: paid.append(amount) or "ok", {"amount": 350.0},
                  session_id="s")
    b = queue.run("refund", lambda amount: paid.append(amount) or "ok", {"amount": 350.0},
                  session_id="s")
    assert queue.approve_and_run(a.id, reviewer="fin") == "ok"
    assert queue.approve_and_run(b.id, reviewer="fin") is None
    req = queue.get(b.id)
    assert req.status is ApprovalStatus.REJECTED and req.decided_by == "fairewall"
    assert "policy now blocks" in req.note
    assert paid == [350.0]


def test_recheck_rejects_when_session_became_tainted(fw):
    fw.policy.tools["send_contract"].forbid_when_tainted = True
    q = ApprovalQueue(fw)
    held = q.run("send_contract", lambda customer: "sent", {"customer": "K"}, session_id="s")
    fw.session("s").taint("web_page")
    q.approve(held.id, reviewer="ops")
    assert q.get(held.id).status is ApprovalStatus.REJECTED


def test_requests_expire(fw):
    clock = Clock()
    q = ApprovalQueue(fw, ttl_seconds=60, clock=clock)
    held = q.run("send_contract", lambda customer: "sent", {"customer": "K"}, session_id="s")
    clock.now += 61
    assert q.get(held.id).status is ApprovalStatus.EXPIRED
    with pytest.raises(ApprovalError, match="already expired"):
        q.approve(held.id, reviewer="ops")
    assert "approval_expired" in [r["event"] for r in fw.audit.records()]


def test_full_queue_fails_closed(fw):
    q = ApprovalQueue(fw, max_requests=1)
    q.run("send_contract", lambda customer: "sent", {"customer": "A"}, session_id="s")
    out = q.run("send_contract", lambda customer: "sent", {"customer": "B"}, session_id="s")
    assert isinstance(out, str) and out.startswith("SECURITY BLOCK")


def test_full_queue_evicts_decided_first(fw):
    q = ApprovalQueue(fw, max_requests=1)
    first = q.run("send_contract", lambda customer: "sent", {"customer": "A"}, session_id="s")
    q.reject(first.id, reviewer="ops")
    second = q.run("send_contract", lambda customer: "sent", {"customer": "B"}, session_id="s")
    assert isinstance(second, ApprovalRequest)
    assert q.get(first.id) is None


def test_shadow_mode_never_holds():
    fw = Firewall(policy=_policy(), shadow=True)
    q = ApprovalQueue(fw)
    assert q.run("send_contract", lambda customer: "sent", {"customer": "K"}) == "sent"
    assert q.pending() == []


def test_sdk_exposes_queue():
    sdk = GovernanceSDK(policy=_policy())
    held = sdk.approvals.run("send_contract", lambda customer: "sent", {"customer": "K"})
    assert isinstance(held, ApprovalRequest)
    assert sdk.approvals is sdk.approvals


# ------------------------------------------------------------------ HTTP


@pytest.fixture
def client():
    return TestClient(create_app(policy=_policy(), api_key="agent-key",
                                 reviewer_api_key="reviewer-key"))


AGENT = {"X-API-Key": "agent-key"}
REVIEWER = {"X-API-Key": "reviewer-key"}


def _hold(client, tool="send_contract", args=None):
    resp = client.post("/v1/inspect/tool", headers=AGENT, json={
        "tool": tool, "arguments": args or {"customer": "Priya"},
        "session_id": "h1", "principal_id": "agent-1", "hold_for_approval": True})
    assert resp.status_code == 200
    return resp.json()


def test_http_hold_poll_approve(client):
    body = _hold(client)
    assert body["pending_approval"] is True and body["allowed"] is False
    rid = body["approval"]["id"]

    assert client.get("/v1/approvals/" + rid, headers=AGENT).json()["status"] == "pending"
    listed = client.get("/v1/approvals?status_filter=pending", headers=REVIEWER).json()
    assert [r["id"] for r in listed["approvals"]] == [rid]

    resp = client.post("/v1/approvals/%s/approve" % rid, headers=REVIEWER,
                       json={"reviewer": "ops-lead", "note": "fine"})
    assert resp.status_code == 200 and resp.json()["status"] == "approved"
    assert client.get("/v1/approvals/" + rid, headers=AGENT).json()["decided_by"] == "ops-lead"

    again = client.post("/v1/approvals/%s/approve" % rid, headers=REVIEWER,
                        json={"reviewer": "ops-lead"})
    assert again.status_code == 409


def test_http_agent_key_cannot_review(client):
    rid = _hold(client)["approval"]["id"]
    assert client.get("/v1/approvals", headers=AGENT).status_code == 401
    resp = client.post("/v1/approvals/%s/approve" % rid, headers=AGENT,
                       json={"reviewer": "agent-1"})
    assert resp.status_code == 401
    assert client.get("/v1/approvals/" + rid).status_code == 401


def test_http_reject_and_unknown(client):
    rid = _hold(client)["approval"]["id"]
    resp = client.post("/v1/approvals/%s/reject" % rid, headers=REVIEWER,
                       json={"reviewer": "ops", "note": "no"})
    assert resp.json()["status"] == "rejected"
    missing = client.post("/v1/approvals/nope/approve", headers=REVIEWER, json={"reviewer": "ops"})
    assert missing.status_code == 404


def test_http_without_hold_flag_is_unchanged(client):
    resp = client.post("/v1/inspect/tool", headers=AGENT,
                       json={"tool": "send_contract", "arguments": {"customer": "K"}})
    body = resp.json()
    assert body["blocked"] is True and "pending_approval" not in body


def test_http_hard_block_not_held(client):
    body = _hold(client, tool="refund", args={"amount": 900.0})
    assert body["blocked"] is True and "pending_approval" not in body
