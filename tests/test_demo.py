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
    assert ids == ["invoice", "contract", "hijack", "key_leak", "loop", "refunds"]
    assert client.post("/demo/api/run/nope").status_code == 404


def test_invoice_is_allowed_and_runs(client):
    r = run(client, "invoice")
    assert r["calls"][0]["verdict"] == "allow"
    assert r["calls"][0]["outcome"] == "ran (simulated)"


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
