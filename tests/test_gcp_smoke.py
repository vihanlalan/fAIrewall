import importlib.util
from pathlib import Path

import pytest


SPEC = importlib.util.spec_from_file_location(
    "gcp_smoke", Path(__file__).resolve().parents[1] / "deploy" / "gcp" / "smoke.py")
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


def cloud_fixture(*, model_source="live", armor_provenance="live call", armor_status="pass",
                  armor_filter="NO_MATCH_FOUND", second_gateway="fw-gateway-b",
                  second_observed=True, proof_valid=True, publication="confirmed"):
    def send(path, *, token="", body=None):
        if path == "/api/status":
            return {"gemini": "vertex:asia-south1", "model_armor": "an-armor-template"}
        if path == "/api/workspaces":
            return {"propose_token": "proposal-token", "review_token": "review-token"}
        if path == "/api/runs":
            if body.get("chapter") == 2:
                return {"effects": {"refunds": []}, "trace": [{
                    "event": "submit", "outcome": "block", "rule_ids": ["financial.transaction_limit"],
                    "stages": [{"detector": "model_armor", "status": "skipped"}],
                }]}
            if body.get("chapter") == 5:
                return {"status": "input_held", "detail": {"case_id": "example"}}
            if body.get("fixture") == "courier-weak-variant":
                return {"status": "input_blocked", "trace": [
                    {"event": "screen", "rule_ids": ["adaptive.learned_threat"]}]}
            if body.get("source") == "live":
                return {"status": "completed", "agent": {
                    "source": model_source, "model": "gemini", "actions": [{"tool": "lookup_order"}]},
                    "trace": [{"event": "proposal", "evidence": {"backend": "vertex:asia-south1"}}]}
            return {"trace": [{"event": "screen", "stages": [{
                "detector": "model_armor", "status": armor_status, "provenance": armor_provenance,
                "evidence": {"filters": {"pi_and_jailbreak": armor_filter}},
            }]}]}
        if path == "/api/cases/example/label":
            assert token == "review-token"
            return {}
        if path == "/api/killswitch/freeze":
            return {"gateways": [
                {"service": service, "mode": "remote service", "observed": observed,
                 "rule_ids": ["killswitch.frozen"]}
                for service, observed in (("fw-gateway-a", True), (second_gateway, second_observed))
            ], "governed_dispatch": {"dispatched": False}}
        if path == "/api/killswitch/unfreeze":
            assert token == "review-token"
            return {"released": True}
        if path == "/api/evidence":
            return {"proof_check": {"valid": proof_valid},
                    "published": [{"backend": "bucket", "status": publication}],
                    "synthetic_proof": {"commitment": "proof-root", "receipts": {"bucket": {"generation": "1"}}}}
        raise AssertionError(f"Unexpected smoke request to {path}")

    return send


def test_cloud_smoke_requires_and_accepts_live_evidence():
    smoke.run(cloud_fixture(), wait_seconds=0)


@pytest.mark.parametrize(("response", "message"), [
    ({"model_source": "recorded"}, "Vertex AI did not"),
    ({"armor_provenance": "cached"}, "No live Model Armor"),
    ({"armor_status": "failed"}, "No live Model Armor"),
    ({"armor_filter": "EXECUTION_SKIPPED"}, "No live Model Armor"),
    ({"second_gateway": "fw-gateway-a"}, "Both distinct"),
    ({"second_observed": False}, "Both distinct"),
    ({"proof_valid": False}, "Evidence proof"),
    ({"publication": "pending"}, "Evidence proof"),
])
def test_cloud_smoke_rejects_unverified_claims(response, message):
    with pytest.raises(smoke.SmokeFailure, match=message):
        smoke.run(cloud_fixture(**response), wait_seconds=0)
