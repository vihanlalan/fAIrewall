"""The Lab, end to end: chapters, All checks, isolation, review races, failures, shared state."""
import json
import threading

import pytest
from fastapi.testclient import TestClient

from fairewall.detectors import Detector, DetectorResult
from fairewall.integrations.gemini import ModelError
from fairewall.lab import Lab
from fairewall.lab import fixtures as fx
from fairewall.lab.app import create_lab_app


@pytest.fixture
def lab(tmp_path):
    return Lab(str(tmp_path / "lab"))


@pytest.fixture
def ws(lab):
    return lab.create_workspace()["workspace"]


def events(run, kind):
    return [t for t in run["trace"] if t["event"] == kind]


def stage(event, name, detector=None):
    for s in event["stages"]:
        if s["stage"] == name and (detector is None or s.get("detector") == detector):
            return s
    return None


# ------------------------------------------------------------------ chapters

def test_ch1_normal_refund_dispatches_once_with_a_receipt(lab, ws):
    run = lab.start_run(ws, chapter=1)
    refund = [a for a in run["agent"]["actions"] if a["tool"] == "refund"][0]
    assert refund["status"] == "executed"
    assert len(run["effects"]["refunds"]) == 1 and run["effects"]["refunds"][0]["amount"] == 50000
    assert len([t for t in events(run, "dispatch") if t["action_id"] == refund["action_id"]]) == 1
    assert run["agent"]["source"] == "recorded" and run["proposal_source"] == "recorded"
    assert run["agent"]["policy_latency_ms"] > 0


def test_ch2_deterministic_block_skips_model_armor_and_writes_nothing(lab, ws):
    run = lab.start_run(ws, chapter=2)
    sub = events(run, "submit")[0]
    assert sub["outcome"] == "block" and "financial.transaction_limit" in sub["rule_ids"]
    assert stage(sub, "router")["status"] == "skipped"
    assert stage(sub, "detector", "model_armor")["status"] == "skipped"
    assert run["effects"] == {"refunds": [], "outbox": []} and not events(run, "dispatch")


def test_ch3_injection_never_reaches_the_model_and_clean_content_taints(lab, ws):
    run = lab.start_run(ws, chapter=3)
    assert run["status"] == "input_blocked" and run["agent"] is None
    assert "injection.instruction_override" in events(run, "screen")[0]["rule_ids"]
    assert not events(run, "proposal")
    clean = lab.start_run(ws, chapter=3, variant=True)
    assert events(clean, "screen")[0]["outcome"] == "approve" and clean["session"]["tainted"]
    sub = events(clean, "submit")[0]
    assert sub["outcome"] == "block" and sub["rule_ids"] == ["taint.untrusted_context"]
    assert clean["effects"]["refunds"] == []


def test_ch4_novel_destination_is_held_and_approval_delivers_once(lab, ws):
    run = lab.start_run(ws, chapter=4)
    held = run["agent"]["actions"][0]
    assert held["status"] == "pending_approval" and "baseline.novel_action" in held["reason_codes"]
    assert lab.inbox(ws)["actions"][0]["action_id"] == held["action_id"]
    lab.review(ws, held["action_id"], approve=True)
    after = lab.run_view(ws, run["run_id"])
    assert len(after["effects"]["outbox"]) == 1 and after["effects"]["outbox"][0]["recipient"] == "pickups@returns-partner.in"
    assert events(after, "reviewer_decision")[0]["outcome"] == "approved"
    assert events(after, "review")  # the re-check on approval is in the trace too
    # Rejected: nothing delivered.
    run2 = lab.start_run(ws, chapter=4)
    lab.review(ws, run2["agent"]["actions"][0]["action_id"], approve=False)
    assert lab.run_view(ws, run2["run_id"])["effects"]["outbox"] == []


def test_ch4_hard_destination_deny_is_not_overridable(lab, ws):
    run = lab.start_run(ws, chapter=4, variant=True)
    act = run["agent"]["actions"][0]
    assert act["status"] == "blocked" and "egress.unapproved_destination" in act["reason_codes"]
    assert all(a["action_id"] != act["action_id"] for a in lab.inbox(ws)["actions"])


def test_ch5_learning_case_blocks_the_variant_names_the_case_and_can_be_revoked(lab, ws):
    first = lab.start_run(ws, chapter=5)
    assert first["status"] == "input_held" and first["detail"]["case_id"]
    case = first["detail"]["case_id"]
    lab.label(ws, case, "malicious")
    variant = lab.start_run(ws, kind="website", fixture="courier-weak-variant")
    screen = events(variant, "screen")[0]
    assert variant["status"] == "input_blocked" and screen["rule_ids"] == ["adaptive.learned_threat"]
    assert stage(screen, "memory")["evidence"]["case_id"] == case
    control = lab.start_run(ws, kind="website", fixture="courier-benign")
    assert control["status"] not in ("input_blocked", "input_held")
    lab.revoke(ws, case)
    again = lab.start_run(ws, kind="website", fixture="courier-weak-variant")
    assert "adaptive.learned_threat" not in events(again, "screen")[0]["rule_ids"]


def test_ch6_canary_blocks_masks_and_freezes_the_run(lab, ws):
    run = lab.start_run(ws, chapter=6)
    send, nxt = run["agent"]["actions"][:2]
    assert send["status"] == "blocked" and "canary.tripped" in send["reason_codes"]
    assert nxt["status"] == "blocked" and "killswitch.frozen" in nxt["reason_codes"]
    assert run["effects"]["outbox"] == [] and run["session"]["frozen"]
    value = lab.canary_value(ws)
    assert value and value not in json.dumps(run) and value not in json.dumps(lab.inbox(ws))
    assert value not in json.dumps(lab.trace(ws))


def test_ch7_out_of_scope_is_held_and_the_agent_cannot_widen(lab, ws):
    run = lab.start_run(ws, chapter=7)
    refund = [a for a in run["agent"]["actions"] if a["tool"] == "refund"][0]
    assert refund["status"] == "pending_approval" and "scope.argument_out_of_scope" in refund["reason_codes"]
    from fairewall.lab.runtime import LabError
    with pytest.raises(LabError) as err:
        lab.set_scope(ws, run["run_id"], {"tools": ["lookup_order", "refund", "send_email"],
                                          "args": {"order_id": ["ORD-1002", "ORD-1001"]}}, reviewer=False)
    assert err.value.status == 403
    lab.set_scope(ws, run["run_id"], {"tools": ["lookup_order"], "args": {"order_id": ["ORD-1002"]},
                                      "max_spend": 1000}, reviewer=False)  # narrowing is fine


def test_ch8_freeze_is_seen_by_both_gateways_and_refuses_dispatch(lab, ws):
    lab.start_run(ws, chapter=1)
    out = lab.freeze(ws)
    assert [g["observed"] for g in out["gateways"]] == [True, True]
    assert all("killswitch.frozen" in g["rule_ids"] for g in out["gateways"])
    assert all(g["propagation_ms"] >= 0 for g in out["gateways"])
    assert out["governed_dispatch"]["dispatched"] is False
    assert "killswitch.frozen" in out["governed_dispatch"]["rule_ids"]
    assert out["already_dispatched"] and all("not recalled" in a["status"] for a in out["already_dispatched"])
    assert lab.unfreeze(ws)["released"]


def test_ch9_evidence_proof_and_tamper(lab, ws, monkeypatch):
    from fairewall.lab.runtime import run_anchor_from_env

    ev = lab.evidence(ws)
    assert ev["synthetic_proof"]["record"]["synthetic"] is True and ev["proof_check"]["valid"]
    t = lab.tamper(ws)
    assert t["original"]["valid"] and not t["tampered_copy"]["valid"]
    lab.start_run(ws, chapter=1)
    fresh = lab.evidence(ws)["fresh"]
    assert fresh and not any(f["anchored"] for f in fresh)
    monkeypatch.setenv("LAB_DATA_DIR", str(lab.data))
    monkeypatch.delenv("FAIREWALL_DATABASE_URL", raising=False)
    monkeypatch.delenv("FAIREWALL_ANCHOR_BUCKET", raising=False)
    monkeypatch.delenv("FAIREWALL_ANCHOR_KEY", raising=False)
    assert run_anchor_from_env() == 0
    assert all(f["anchored"] for f in lab.evidence(ws)["fresh"])


def test_ch10_shadow_comparison_keeps_the_active_policy_until_promoted(lab, ws):
    lab.start_run(ws, chapter=1)
    before = lab.policy_info(ws)
    cmp = lab.rollout_compare(ws, {"max_spend_per_transaction": 2000, "review_above": 500})
    assert cmp["diff"]["changed"] >= 1 and cmp["enforcing"] == before
    assert all(o["shadow"] for o in cmp["observed"])
    promoted = lab.rollout_set(ws, "promote")
    assert promoted["enforcing"]["fingerprint"] != before["fingerprint"]
    assert all(not o["shadow"] for o in promoted["observed"])
    # Now a Rs 2,500 refund is over the new cap.
    run = lab.start_run(ws, kind="operator", text="Customer on ORD-1003 wants Rs 2,500 refund", source="recorded")
    assert any("financial.transaction_limit" in a["reason_codes"] for a in run["agent"]["actions"])


# ---------------------------------------------------------------- all checks

@pytest.mark.parametrize("vid", [v["id"] for v in fx.VARIANTS])
def test_every_check_fires_its_named_rule(lab, ws, vid):
    out = lab.run_variant(ws, vid)
    assert out["passed"], out


# ------------------------------------------------------- review and failures

def test_denial_on_recheck_dispatches_nothing(lab, ws):
    run = lab.start_run(ws, chapter=4)
    aid = run["agent"]["actions"][0]["action_id"]
    lab.freeze(ws)
    out = lab.review(ws, aid, approve=True)
    assert out["action"]["status"] == "blocked"
    assert lab.run_view(ws, run["run_id"])["effects"]["outbox"] == []
    assert events(lab.run_view(ws, run["run_id"]), "review")


def test_concurrent_approvals_dispatch_once(lab, ws):
    run = lab.start_run(ws, chapter=4)
    aid = run["agent"]["actions"][0]["action_id"]
    results = []

    def approve():
        try:
            results.append(lab.review(ws, aid, approve=True)["already_decided"])
        except Exception as exc:  # noqa: BLE001
            results.append(exc)

    threads = [threading.Thread(target=approve) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(lab.run_view(ws, run["run_id"])["effects"]["outbox"]) == 1
    assert results.count(False) == 1


class Boom(Detector):
    name, deep = "model_armor", True

    def detect(self, text):
        raise RuntimeError("Model Armor unreachable")


def test_model_armor_failure_is_shown_as_failed_and_fails_per_policy(tmp_path):
    lab = Lab(str(tmp_path / "lab"), model_armor=Boom())
    ws = lab.create_workspace()["workspace"]
    run = lab.start_run(ws, chapter=3, variant=True)
    screen = events(run, "screen")[0]
    armor = stage(screen, "detector", "model_armor")
    assert armor["status"] == "failed" and "unreachable" in armor["reason"]


class DownGemini:
    model, backend = "gemini-x", "vertex:test"

    def generate(self, *a, **k):
        raise ModelError("timeout", "Vertex AI timed out")


def test_live_model_failure_dispatches_nothing_and_says_so(tmp_path):
    lab = Lab(str(tmp_path / "lab"), live_client=DownGemini())
    ws = lab.create_workspace()["workspace"]
    run = lab.start_run(ws, chapter=1, source="live")
    assert run["status"] == "model_error" and run["effects"]["refunds"] == []
    assert run["proposal_source"] == "live"


def test_two_lab_processes_share_one_database(tmp_path):
    a, b = Lab(str(tmp_path / "lab")), Lab(str(tmp_path / "lab"))
    ws = a.create_workspace()["workspace"]
    run = a.start_run(ws, chapter=4)
    aid = run["agent"]["actions"][0]["action_id"]
    assert b.inbox(ws)["actions"][0]["action_id"] == aid
    b.review(ws, aid, approve=True)
    assert a.review(ws, aid, approve=True)["already_decided"] is True
    assert len(a.ledger.state(ws)["outbox"]) == 1


# --------------------------------------------------------- HTTP and isolation

def test_http_isolation_between_sandboxes(lab):
    c = TestClient(create_lab_app(lab))
    one, two = c.post("/api/workspaces").json(), c.post("/api/workspaces").json()
    p1 = {"Authorization": "Bearer " + one["propose_token"]}
    r1 = {"Authorization": "Bearer " + one["review_token"]}
    p2 = {"Authorization": "Bearer " + two["propose_token"]}
    r2 = {"Authorization": "Bearer " + two["review_token"]}
    run = c.post("/api/runs", headers=p1, json={"chapter": 4}).json()
    aid = run["agent"]["actions"][0]["action_id"]
    assert c.get("/api/runs/" + run["run_id"], headers=p2).status_code == 404
    assert c.post("/api/actions/%s/review" % aid, headers=r2, json={"approve": True}).status_code == 404
    assert c.get("/api/inbox", headers=r2).json()["actions"] == []
    # Roles: proposing needs the propose token, reviewing the review token.
    assert c.post("/api/actions/%s/review" % aid, headers=p1, json={"approve": True}).status_code == 403
    assert c.post("/api/runs", headers=r1, json={"chapter": 1}).status_code == 403
    assert c.post("/api/actions/%s/review" % aid, headers=r1, json={"approve": True}).status_code == 200
    held = c.post("/api/runs", headers=p1, json={"chapter": 5}).json()
    assert c.post("/api/cases/%s/label" % held["detail"]["case_id"], headers=r2,
                  json={"verdict": "malicious"}).status_code == 404
    c.post("/api/killswitch/freeze", headers=r2, json={})
    assert c.post("/api/runs", headers=p1, json={"chapter": 1}).json()["agent"]["actions"][0]["status"] == "executed"
    assert c.get("/api/runs", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_http_page_and_status_render(lab):
    c = TestClient(create_lab_app(lab))
    page = c.get("/")
    assert page.status_code == 200 and "fAIrewall Lab" in page.text and "/ui/theme.css" in page.text
    assert c.get("/ui/theme.css").status_code == 200
    st = c.get("/api/status").json()
    assert st["gemini"] is None and st["model_armor"] is None and len(st["gateways"]) == 2
    assert len(c.get("/api/chapters").json()["chapters"]) == 10


def test_input_limits_and_quotas(tmp_path):
    lab = Lab(str(tmp_path / "lab"), limits={"runs_per_hour": 2})
    ws = lab.create_workspace()["workspace"]
    from fairewall.lab.runtime import LabError
    with pytest.raises(LabError) as big:
        lab.start_run(ws, kind="operator", text="x" * 2001)
    assert big.value.status == 413
    lab.start_run(ws, chapter=2)
    with pytest.raises(LabError) as quota:
        lab.start_run(ws, chapter=2)
    assert quota.value.status == 429
    with pytest.raises(LabError) as live:
        Lab(str(tmp_path / "lab2")).start_run(lab.create_workspace()["workspace"], chapter=1, source="live")
    assert live.value.status in (429, 503)


def test_remote_gateway_over_http_sees_the_lab_freeze(tmp_path, monkeypatch):
    """The Cloud Run path: a separate gateway server, called with an identity token in
    Authorization and the fAIrewall key in X-API-Key, reading freezes from the shared database."""
    import socket
    import time as _time

    import uvicorn

    from fairewall.lab import runtime as rt
    from fairewall.proxy import create_app

    data = tmp_path / "lab"
    data.mkdir()
    gw_app = create_app(api_key="gw-key", reviewer_api_key="gw-review", database=str(data / "gateway.sqlite"))
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = uvicorn.Server(uvicorn.Config(gw_app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        _time.sleep(0.05)
    monkeypatch.setattr(rt, "_id_token", lambda audience: "google-identity-token")
    monkeypatch.setenv("K_SERVICE", "http-test-gateway")
    try:
        url = "http://127.0.0.1:%d" % port
        lab = Lab(str(data), gateway_urls={"gateway-a": url, "gateway-b": url}, gateway_key="gw-key")
        ws = lab.create_workspace()["workspace"]
        out = lab.freeze(ws)
        assert [g["mode"] for g in out["gateways"]] == ["remote service", "remote service"]
        assert [g["service"] for g in out["gateways"]] == ["http-test-gateway", "http-test-gateway"]
        assert all(g["observed"] and "killswitch.frozen" in g["rule_ids"] for g in out["gateways"])
        assert all(g["propagation_ms"] < 5000 for g in out["gateways"])
    finally:
        server.should_exit = True
        thread.join(timeout=5)
