"""The judge-facing demo: each scenario lands on the verdict the pitch promises."""

import pytest
from fastapi.testclient import TestClient

from fairewall.demo import create_demo_app


@pytest.fixture
def client():
    return TestClient(create_demo_app())


def run(client, scenario):
    resp = client.post("/demo/api/run/" + scenario)
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_page_and_scenarios_load(client):
    page = client.get("/demo")
    assert page.status_code == 200 and "fAIrewall" in page.text
    ids = [s["id"] for s in client.get("/demo/api/scenarios").json()["scenarios"]]
    assert ids == ["invoice", "contract", "hijack", "key_leak", "disguised", "roleplay", "loop", "refunds"]
    assert client.post("/demo/api/run/nope").status_code == 404


def test_invoice_is_allowed_and_runs(client):
    r = run(client, "invoice")
    assert r["calls"][0]["verdict"] == "allow"
    assert "ran (simulated)" in r["calls"][0]["outcome"]
    assert all(c["status"] in ("pass", "skipped") for c in r["calls"][0]["checks"])


def test_contract_escalates_into_queue(client):
    r = run(client, "contract")
    call = r["calls"][0]
    assert call["verdict"] == "escalate" and call["approval_id"]
    queue = client.get("/demo/api/approvals").json()
    assert queue["pending"] == 1


def test_hijack_is_blocked_with_taint_and_cap(client):
    r = run(client, "hijack")
    assert r["inbound"]["verdict"] == "block" and r["inbound"]["tainted"]
    rules = {f["rule_id"] for f in r["calls"][0]["findings"]}
    assert r["calls"][0]["verdict"] == "block"
    assert "financial.transaction_limit" in rules
    assert any(rid.startswith("taint.") for rid in rules)


def test_key_leak_is_blocked_by_egress(client):
    r = run(client, "key_leak")
    call = r["calls"][0]
    assert call["verdict"] == "block"
    assert "egress.secret_material" in {f["rule_id"] for f in call["findings"]}


def _check(rows, key):
    return next(r for r in rows if r["key"] == key)


def test_trace_lists_every_check_with_plain_reasons(client):
    r = run(client, "hijack")
    keys = [c["key"] for c in r["calls"][0]["checks"]]
    assert keys == ["schema", "taint", "financial", "velocity", "payload", "egress", "ai"]
    call = r["calls"][0]["checks"]
    assert _check(call, "taint")["status"] == "block"
    assert _check(call, "financial")["status"] == "block"
    assert _check(call, "velocity")["status"] == "pass"
    # Rules already decided, so the AI tier is skipped and says why.
    assert _check(call, "ai")["status"] == "skipped"
    assert "already decided" in _check(call, "ai")["detail"]
    assert r["without"] and r["story"]


def test_roleplay_is_caught_by_ai_tier_not_patterns(client):
    r = run(client, "roleplay")
    checks = r["inbound"]["checks"]
    assert _check(checks, "phrases")["status"] == "pass"
    ai = _check(checks, "ai")
    assert ai["status"] == "escalate" and ai["score"] >= 0.5
    assert r["inbound"]["verdict"] == "escalate"
    assert r["calls"][0]["verdict"] == "block"  # taint lock still stops the send


def test_disguised_theft_slips_past_text_checks_but_taint_holds(client):
    r = run(client, "disguised")
    checks = r["inbound"]["checks"]
    assert _check(checks, "phrases")["status"] == "pass"
    assert _check(checks, "ai")["status"] == "pass"  # the model misses it; we show that
    call = r["calls"][0]
    assert call["verdict"] == "block"
    assert _check(call["checks"], "taint")["status"] == "block"


def test_loop_hits_rate_limit(client):
    r = run(client, "loop")
    assert r["counts"] == {"allow": 20, "escalate": 0, "block": 10}
    assert any(f["rule_id"].startswith("velocity.") for f in r["calls"][-1]["findings"])


def test_two_refunds_recheck_on_approval(client):
    r = run(client, "refunds")
    a, b = (c["approval_id"] for c in r["calls"])
    first = client.post("/demo/api/approvals/%s/approve" % a, json={"reviewer": "finance-lead"}).json()
    assert first["status"] == "approved" and first["executed"]
    second = client.post("/demo/api/approvals/%s/approve" % b, json={"reviewer": "finance-lead"}).json()
    assert second["status"] == "rejected" and second["decided_by"] == "fairewall"
    again = client.post("/demo/api/approvals/%s/approve" % b, json={"reviewer": "finance-lead"})
    assert again.status_code == 409
    # The rejection names the real reason, not the already-satisfied approval rule.
    assert "financial.session_budget" in second["note"]
    assert "human_approval_required" not in second["note"]
    verdicts = {r["verdict"] for r in client.get("/demo/api/audit").json()["records"]}
    assert {"escalate", "ran after approval"} <= verdicts


def test_report_and_diff(client):
    rep = client.post("/demo/api/report", json={"count": 500, "minutes_per_review": 3}).json()
    assert sum(rep["buckets"].values()) == rep["total_calls"] == 500
    assert rep["synthetic"] is True
    same = client.post("/demo/api/diff", json={"refund_cap": 200, "count": 500}).json()
    assert same["changed"] == 0
    tighter = client.post("/demo/api/diff", json={"refund_cap": 50, "count": 500}).json()
    assert tighter["stricter"] > 0 and tighter["looser"] == 0
    looser = client.post("/demo/api/diff", json={"refund_cap": 200, "contract_needs_approval": False,
                                                  "count": 500}).json()
    assert looser["looser"] > 0


def test_audit_and_tamper_on_copy(client):
    assert client.post("/demo/api/audit/tamper", json={}).status_code == 409
    run(client, "hijack")
    run(client, "invoice")
    audit = client.get("/demo/api/audit").json()
    assert audit["valid"] and audit["total"] >= 3
    t = client.post("/demo/api/audit/tamper", json={}).json()
    assert t["valid"] is False and t["broken_at"] is not None
    assert client.get("/demo/api/audit").json()["valid"] is True  # live log untouched


def test_reset_clears_state(client):
    run(client, "contract")
    client.post("/demo/api/reset")
    assert client.get("/demo/api/approvals").json()["pending"] == 0
    assert client.get("/demo/api/audit").json()["total"] == 0
