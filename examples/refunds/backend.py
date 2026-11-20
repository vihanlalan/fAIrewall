"""Refund desk backend: one live (or recorded) agent run, governed end to end.

    python examples/refunds/backend.py            # http://127.0.0.1:8090/docs

Configuration (environment, or examples/refunds/.env; see .env.example):

    GEMINI_API_KEY        live Gemini runs. Without it only recorded runs work.
    GEMINI_MODEL          model for live runs (default: gemini-2.5-flash).
    REFUND_OPERATOR_KEY   key the frontend sends to start and read runs.
    REFUND_REVIEWER_KEY   key a finance reviewer sends to approve or reject.
    REFUND_REVIEWER_NAME  the reviewer's name recorded on decisions.
    REFUND_DATA_DIR       where the SQLite files live (default: examples/refunds/data).
    REFUND_CORS_ORIGINS   comma-separated origins allowed to call the API.

The agent's identity and the reviewer's identity come from this server's
configuration, never from request bodies. Responses are the small redacted
contract in CONTRACT.md, not raw action records.
"""
from __future__ import annotations

import hmac
import os
import secrets
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
try:  # running from a source checkout without installing
    import fairewall  # noqa: F401
except ImportError:  # pragma: no cover
    sys.path.insert(0, str(HERE.parents[1] / "src"))

from fastapi import FastAPI, Header, HTTPException  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from pydantic import BaseModel  # noqa: E402

from fairewall.approvals import ApprovalError  # noqa: E402
from fairewall.integrations.gemini import GeminiClient, ModelError, RecordedClient  # noqa: E402
from fairewall.runs import AgentRunner  # noqa: E402
from workflow import AGENT, SYSTEM_PROMPT, RefundDesk, project  # noqa: E402

RECORDINGS = HERE / "recordings.json"


class StartRun(BaseModel):
    message: str
    source: str = "recorded"           # "live" (Gemini) or "recorded"
    scenario: Optional[str] = None     # recorded only; picked from the message when omitted


class Decision(BaseModel):
    approve: bool


def load_env_file(path: Path) -> None:
    """Minimal KEY=VALUE loader; existing environment variables win."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def create_backend(data_dir, *, operator_keys: Dict[str, str], reviewer_keys: Dict[str, str],
                   live_client: Any = None, recorded_client: Optional[RecordedClient] = None,
                   fault: Optional[str] = None, setup_reviewer: Optional[str] = "demo-setup",
                   cors_origins: Optional[List[str]] = None) -> FastAPI:
    """Build the API. ``live_client`` is a GeminiClient, or None when no key is set."""
    if not operator_keys or not reviewer_keys or set(operator_keys) & set(reviewer_keys) \
            or "" in {*operator_keys, *reviewer_keys}:
        raise ValueError("Configure separate, non-empty operator and reviewer keys")
    desk = RefundDesk(data_dir, fault=fault)
    if setup_reviewer:
        # Demo setup: review both tool definitions now, so that no refund
        # approval later is ever a definition review in disguise.
        desk.review_definitions(setup_reviewer)
    recorded = recorded_client or RecordedClient.from_file(str(RECORDINGS))
    clients: Dict[str, Any] = {"recorded": recorded}
    if live_client is not None:
        clients["live"] = live_client
    runner = AgentRunner(desk.store, str(Path(data_dir) / "runs.sqlite"), AGENT,
                         clients=clients, system=SYSTEM_PROMPT, project=project)
    resumed = runner.recover()           # runs a dead process left mid-step
    for run_id in resumed:
        runner.resume(run_id)
    review_lock = threading.Lock()

    app = FastAPI(title="fAIrewall refund desk", version="1.0")
    app.state.desk, app.state.runner = desk, runner
    if cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=cors_origins, allow_methods=["GET", "POST"],
                           allow_headers=["Authorization", "Content-Type"])

    def who(authorization: Optional[str], *maps: Dict[str, str]) -> str:
        supplied = (authorization or "")[7:] if (authorization or "").lower().startswith("bearer ") else ""
        for mapping in maps:
            for key, name in mapping.items():
                if supplied and hmac.compare_digest(supplied.encode(), key.encode()):
                    return name
        raise HTTPException(401, "Missing or wrong key (Authorization: Bearer <key>).")

    def action_view(action_id: str) -> Dict[str, Any]:
        try:
            record = desk.store.get(action_id)
        except ApprovalError:
            raise HTTPException(404, "Unknown action")
        view = project(record)
        view.pop("model_payload", None)
        view["timeline"] = [{"status": e["status"], "reviewer": e["reviewer"], "at": e["at"],
                             "policy_hash": e["policy_hash"]} for e in record["events"]]
        if record.get("reconciliation"):
            view["reconciliation"] = record["reconciliation"]
        view["expires_at"] = record["expires"]
        return view

    def runs_waiting_on(action_id: str) -> List[str]:
        with runner._tx() as db:
            return [r["id"] for r in db.execute("SELECT id FROM runs WHERE pending_action_id=?", (action_id,))]

    # --------------------------------------------------------------- public

    @app.get("/api/health")
    def health() -> Dict[str, Any]:
        return {"status": "ok", "live_model": "live" in clients,
                "model": getattr(clients.get("live"), "model", None),
                "recorded_scenarios": {k: v.get("description", "") for k, v in recorded.scenarios.items()},
                "policy_version": "%s (%s)" % (desk.policy.version, desk.policy.fingerprint()[:12]),
                "definitions_pending_review": [d["tool"] for d in desk.store.pending_definitions()]}

    # ----------------------------------------------------------------- runs

    @app.post("/api/runs", status_code=201)
    def start_run(payload: StartRun, authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        who(authorization, operator_keys)
        if payload.source not in ("live", "recorded"):
            raise HTTPException(400, "source must be live or recorded")
        if payload.source == "live" and "live" not in clients:
            raise HTTPException(503, "Live Gemini runs are not configured: set GEMINI_API_KEY and restart.")
        scenario = payload.scenario
        if payload.source == "recorded":
            scenario = scenario or recorded.pick(payload.message)
            if scenario not in recorded.scenarios:
                raise HTTPException(400, "No recorded scenario matches; pass one of %s"
                                    % sorted(recorded.scenarios))
        try:
            return runner.start(payload.message, source=payload.source, scenario=scenario)
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @app.get("/api/runs")
    def list_runs(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        who(authorization, operator_keys, reviewer_keys)
        return {"runs": runner.list()}

    @app.get("/api/runs/{run_id}")
    def get_run(run_id: str, authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        who(authorization, operator_keys, reviewer_keys)
        try:
            return runner.view(run_id)
        except KeyError:
            raise HTTPException(404, "Unknown run")

    @app.post("/api/runs/{run_id}/retry")
    def retry_run(run_id: str, authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        """Retry after a model error or empty reply. Never re-runs an executed action."""
        who(authorization, operator_keys)
        try:
            return runner.resume(run_id)
        except KeyError:
            raise HTTPException(404, "Unknown run")

    # -------------------------------------------------------------- reviews

    @app.get("/api/reviews")
    def pending_reviews(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        who(authorization, reviewer_keys)
        items = []
        for record in desk.store.pending():
            view = project(record)
            view.pop("model_payload", None)
            view["expires_at"] = record["expires"]
            view["run_ids"] = runs_waiting_on(record["id"])
            items.append(view)
        return {"pending": items}

    @app.post("/api/reviews/{action_id}")
    def decide(action_id: str, payload: Decision, authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        """Approve or reject a held action. The decision is re-checked against the
        current policy first. A second decision on the same action returns the
        first one's outcome instead of failing."""
        reviewer = who(authorization, reviewer_keys)
        already = False
        started = time.perf_counter()
        with review_lock:
            try:
                desk.store.review(action_id, reviewer, payload.approve)
            except ApprovalError as exc:
                if "already decided" not in str(exc):
                    raise HTTPException(409, str(exc))
                already = True
            except Exception:
                # Only a handler failing mid-dispatch is expected here; the store
                # has then marked the action 'uncertain'. Anything else is a bug.
                if desk.store.get(action_id)["status"] not in ("uncertain", "dispatching"):
                    raise
        review_ms = (time.perf_counter() - started) * 1000 - desk.store.last_handler_ms
        runs = runner.resume_for_action(action_id)
        return {"action": action_view(action_id), "already_decided": already,
                "decision_latency_ms": round(max(0.0, review_ms), 3), "runs": runs}

    @app.post("/api/actions/{action_id}/reconcile")
    def reconcile(action_id: str, authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        """Settle an interrupted refund from the ledger's own record. Never re-sends it."""
        operator = who(authorization, reviewer_keys)
        try:
            desk.reconcile(action_id, operator)
        except (ValueError, ApprovalError) as exc:
            raise HTTPException(409, str(exc))
        return {"action": action_view(action_id), "runs": runner.resume_for_action(action_id)}

    @app.get("/api/actions/{action_id}")
    def get_action(action_id: str, authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        who(authorization, operator_keys, reviewer_keys)
        return action_view(action_id)

    # --------------------------------------------------------------- ledger

    @app.get("/api/ledger")
    def ledger(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        """The sandbox ledger, and whether it agrees with fAIrewall's action records."""
        who(authorization, operator_keys, reviewer_keys)
        rows = desk.ledger.refunds()
        problems = []
        for row in rows:  # every ledger row must be an executed action with that receipt
            try:
                record = desk.store.get(row["idempotency_key"])
            except ApprovalError:
                problems.append({"receipt": row["receipt"], "problem": "no fAIrewall action for this refund"})
                continue
            result = record.get("result") or {}
            if record["status"] != "executed" or result.get("receipt") != row["receipt"]:
                problems.append({"receipt": row["receipt"], "action_id": record["id"],
                                 "problem": "action is %s" % record["status"]})
        receipts = {r["receipt"] for r in rows}
        with desk.store.transaction() as db:
            executed = [r["id"] for r in db.execute(
                "SELECT id FROM actions WHERE tool='refund' AND status='executed'"
                " AND json_extract(result,'$.outcome')='refunded'")]
        for action_id in executed:  # every executed refund must have its ledger row
            result = desk.store.get(action_id)["result"]
            if result.get("receipt") not in receipts:
                problems.append({"action_id": action_id, "problem": "executed, but no ledger row"})
        return {"orders": desk.ledger.orders(),
                "refunds": [{"receipt": r["receipt"], "action_id": r["idempotency_key"],
                             "order_id": r["order_id"], "amount_cents": r["amount_cents"],
                             "created_at": r["created_at"]} for r in rows],
                "consistency": {"ledger_refunds": len(rows), "executed_refund_actions": len(executed),
                                "agrees": not problems, "problems": problems}}

    return app


def main() -> None:  # pragma: no cover - manual entry point
    import argparse

    import uvicorn

    load_env_file(HERE / ".env")
    parser = argparse.ArgumentParser(description="fAIrewall refund desk backend")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--fault", choices=["before_write", "lost_response"], default=None,
                        help="Simulate a ledger failure on refunds (reconciliation demo)")
    args = parser.parse_args()

    operator = os.environ.get("REFUND_OPERATOR_KEY") or "op_" + secrets.token_urlsafe(16)
    reviewer = os.environ.get("REFUND_REVIEWER_KEY") or "rv_" + secrets.token_urlsafe(16)
    reviewer_name = os.environ.get("REFUND_REVIEWER_NAME", "finance-reviewer")
    live = None
    try:
        live = GeminiClient()
    except ModelError as exc:
        print("[refund desk] Live Gemini off: %s Recorded runs still work." % exc)
    origins = [o.strip() for o in os.environ.get(
        "REFUND_CORS_ORIGINS", "http://localhost:3000,http://localhost:5173").split(",") if o.strip()]
    data_dir = Path(os.environ.get("REFUND_DATA_DIR", HERE / "data"))
    app = create_backend(data_dir, operator_keys={operator: "frontend"},
                         reviewer_keys={reviewer: reviewer_name}, live_client=live,
                         fault=args.fault, cors_origins=origins)
    print("[refund desk] API docs:  http://%s:%d/docs" % (args.host, args.port))
    print("[refund desk] Data:      %s" % data_dir)
    print("[refund desk] Model:     %s" % (live.model if live else "recorded only"))
    if not os.environ.get("REFUND_OPERATOR_KEY"):
        print("[refund desk] Operator key (this run only): %s" % operator)
    if not os.environ.get("REFUND_REVIEWER_KEY"):
        print("[refund desk] Reviewer key (this run only): %s" % reviewer)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
