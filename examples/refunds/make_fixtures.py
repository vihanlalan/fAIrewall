"""Write examples/refunds/fixtures/*.json: real backend responses for frontend work.

Every fixture comes from an actual run of the backend (recorded model, real
fAIrewall decisions, real sandbox ledger), so the frontend builds against the
exact contract the live backend returns. Regenerate after any contract change:

    python examples/refunds/make_fixtures.py
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from backend import create_backend  # noqa: E402

OUT = HERE / "fixtures"
OP = {"Authorization": "Bearer fixture-operator"}
RV = {"Authorization": "Bearer fixture-reviewer"}


def main() -> None:
    from fastapi.testclient import TestClient

    OUT.mkdir(exist_ok=True)
    written = []

    def save(name: str, data) -> None:
        (OUT / (name + ".json")).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        written.append(name)

    def fresh(**kw):
        tmp = tempfile.mkdtemp()
        app = create_backend(tmp, operator_keys={"fixture-operator": "frontend"},
                             reviewer_keys={"fixture-reviewer": "finance-reviewer"}, **kw)
        return TestClient(app), app, tmp

    # Happy path: held, approved, answered with the receipt.
    c, app, tmp = fresh()
    save("health", c.get("/api/health").json())
    run = c.post("/api/runs", headers=OP, json={
        "message": "Customer on ORD-1001 says the blender arrived cracked and wants $40 back."}).json()
    save("run_awaiting_approval", run)
    save("reviews_pending", c.get("/api/reviews", headers=RV).json())
    decided = c.post("/api/reviews/" + run["action_id"], headers=RV, json={"approve": True}).json()
    save("review_approved", decided)
    save("run_completed_refunded", decided["runs"][0])
    save("action_executed", c.get("/api/actions/" + run["action_id"], headers=OP).json())
    save("review_duplicate", c.post("/api/reviews/" + run["action_id"], headers=RV, json={"approve": True}).json())
    save("run_blocked_over_cap", c.post("/api/runs", headers=OP, json={
        "message": "Customer on ORD-1001 wants $140 back."}).json())
    save("run_lookup_only", c.post("/api/runs", headers=OP, json={
        "message": "What's the status of ORD-1002?"}).json())
    declined = c.post("/api/runs", headers=OP, json={
        "message": "ORD-1003: the chair broke, customer wants $50 back."}).json()
    save("run_declined_by_ledger", c.post("/api/reviews/" + declined["action_id"], headers=RV,
                                          json={"approve": True}).json()["runs"][0])
    rejected = c.post("/api/runs", headers=OP, json={"message": "Refund $40 on ORD-1001 again."}).json()
    save("run_rejected_by_reviewer", c.post("/api/reviews/" + rejected["action_id"], headers=RV,
                                            json={"approve": False}).json()["runs"][0])
    save("ledger", c.get("/api/ledger", headers=OP).json())
    save("runs_list", c.get("/api/runs", headers=OP).json())
    save("error_live_not_configured", {"status_code": 503, "body": c.post(
        "/api/runs", headers=OP, json={"message": "hi", "source": "live"}).json()})
    app.state.desk.close()
    shutil.rmtree(tmp, ignore_errors=True)

    # The refund's outcome is unknown, then settled from the ledger.
    c, app, tmp = fresh(fault="lost_response")
    run = c.post("/api/runs", headers=OP, json={"message": "Refund $40 on ORD-1001."}).json()
    stuck = c.post("/api/reviews/" + run["action_id"], headers=RV, json={"approve": True}).json()
    save("run_needs_reconciliation", stuck["runs"][0])
    save("reconciled", c.post("/api/actions/%s/reconcile" % run["action_id"], headers=RV).json())
    app.state.desk.close()
    shutil.rmtree(tmp, ignore_errors=True)

    print("Wrote %d fixtures to %s:" % (len(written), OUT))
    for name in written:
        print("  " + name + ".json")


if __name__ == "__main__":
    main()
