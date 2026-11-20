import pytest
from fastapi.testclient import TestClient

from fairewall.demo import create_demo_app, refunds


def test_scripted_ledger_and_inline_approval():
    client = TestClient(create_demo_app())
    page = client.get("/demo").text
    assert 'id="run-refund"' in page.split("<button", 2)[1]
    data = client.post("/demo/api/refunds/run/recorded").json()
    assert data["source"] == "recorded"
    lookup, held, blocked = data["calls"]
    assert [a["status"] for a in data["calls"]] == ["executed", "pending", "blocked"]
    assert lookup["ledger_effect"] is None
    assert blocked["ledger_effect"]["entries"] == 0
    url = "/demo/api/refunds/runs/" + data["run_id"]
    for cap, expected in [(60, 80), (100, None), (140, 120)]:
        diff = client.get("/demo/api/refunds/preview", params={"cap": cap}).json()
        assert diff["changed"] == int(expected is not None)
        assert diff["old"]["fingerprint"] == held["policy_fingerprint"]
        if expected:
            change = diff["examples"][0]
            assert change["arguments"]["amount"] == expected
            assert (change["old"], change["new"]) == (("blocked", "human_review") if cap == 140 else ("human_review", "blocked"))
    assert client.get(url).json() == data
    review = url + "/" + held["action_id"] + "/approve"
    approved = client.post(review).json()["calls"][1]
    assert approved["receipt"]["amount_minor"] == 4000 and approved["ledger_effect"]["entries"] == 1
    assert client.post(review).status_code == 409


def test_gemini_live_requires_explicit_configuration(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    client = TestClient(create_demo_app())
    assert not client.get("/demo/api/refunds/mode").json()["live_model"]
    assert client.post("/demo/api/refunds/run/live").status_code == 503


@pytest.mark.parametrize("team,disagreements", [("apparel", 0), ("home", 1)])
def test_buyer_report(team, disagreements):
    report = refunds.buyer_report(team)
    diff = report["diff"]
    assert report["synthetic"] and diff["old"]["buckets"]["human_review"] == 10
    assert diff["new"]["buckets"] == {"auto_approved": 6, "human_review": 3, "blocked": 1}
    metrics = diff["refund_metrics"]
    assert metrics["proposed_p95_ms"] >= 0
    assert sum(b.get("compared", 0) for b in metrics["bands"].values()) == 7
    assert sum(b.get("disagreements", 0) for b in metrics["bands"].values()) == disagreements


def test_live_provenance_and_unexpected_proposal(monkeypatch):
    import io
    import json
    monkeypatch.setenv("GEMINI_API_KEY", "fixture")
    monkeypatch.setenv("FAIREWALL_GEMINI_MODEL", "gemini-test")
    parts = [{"functionCall": {"name": tool, "args": args}}
             for tool, args in refunds.CASES]

    def provider(req, timeout):
        assert req.full_url.endswith("gemini-test:generateContent")
        return io.BytesIO(json.dumps({"candidates": [{"content": {"parts": parts}}]}).encode())

    monkeypatch.setattr(refunds, "urlopen", provider)
    client = TestClient(create_demo_app())
    assert client.post("/demo/api/refunds/run/live").json()["model"] == "gemini-test"
    parts.pop()
    assert client.post("/demo/api/refunds/run/live").status_code == 502


def test_reviewer_access_rejection_and_expiry(monkeypatch):
    monkeypatch.setenv("FAIREWALL_REVIEWER_KEY", "test-reviewer")
    client = TestClient(create_demo_app())
    run = client.post("/demo/api/refunds/run/recorded").json()
    status = "/demo/api/refunds/runs/" + run["run_id"]
    target = status + "/" + run["calls"][1]["action_id"] + "/reject"
    assert run["reviewer"] is None and client.post(target).status_code == 401
    auth = {"authorization": "Bearer test-reviewer"}
    assert client.get(status, headers=auth).json()["reviewer"] == "sandbox-reviewer"
    rejected = client.post(target, headers=auth).json()["calls"][1]
    assert rejected["status"] == "rejected" and rejected["receipt"] is None
    from fairewall.demo import DemoState
    state = DemoState()
    run = refunds.walkthrough(state, "recorded")
    state.refund_queue._clock = lambda: float("inf")
    expired = refunds.get_run(state, run["run_id"])["calls"][1]
    assert expired["status"] == "expired" and expired["receipt"] is None


@pytest.mark.parametrize("cap", ["nan", "inf", "0", "-1"])
def test_preview_invalid_cap(cap):
    assert TestClient(create_demo_app()).get("/demo/api/refunds/preview", params={"cap": cap}).status_code == 422
