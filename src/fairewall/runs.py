"""Agent runs: a model proposes, fAIrewall decides, the run pauses and resumes safely.

The runner sits between a model client (live Gemini or a recording) and an
ActionStore. Its rules:

* The model never executes anything. Each proposed call is submitted to the
  ActionStore under a server-owned principal and a stable idempotency key
  derived from (run, tool, arguments), so retrying a turn can never run a
  call twice.
* One tool call per turn. The whole turn is validated before any call runs;
  a turn with several calls, an unknown tool or bad arguments is answered
  with "not executed" and nothing runs.
* A call that needs a person pauses the run. When the reviewer decides, the
  run resumes and the model is told the actual outcome.
* A dispatch whose outcome is unknown (the business system failed mid-call)
  stops the run in ``needs_reconciliation``. Nothing is re-sent, and the final
  message says the outcome is unconfirmed instead of letting the model guess.
* Every step is saved. If the process dies after the model proposed a call,
  resuming re-submits that same call; the idempotency key returns the action
  already recorded instead of running it again.

Run status values: running, awaiting_approval, completed, needs_reconciliation,
model_error, no_response, unsupported_response, turn_limit, interrupted.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from typing import Any, Callable, Dict, List, Optional

from .actions import ActionStore, canonical
from .approvals import ApprovalError
from .integrations.gemini import (
    ModelError, ToolCall, declarations_for, parse_turn, tool_results_content, user_content,
)
from .types import Principal

# Statuses a run can be resumed from, and by what.
RESUMABLE = ("awaiting_approval", "needs_reconciliation", "model_error", "no_response",
             "unsupported_response", "interrupted")
TERMINAL_ACTION = {"executed", "blocked", "rejected", "expired", "cancelled"}

DEFAULT_RECONCILE_TEXT = (
    "I can't confirm whether this went through: the system that carries it out did not answer. "
    "It has been marked for reconciliation and will not be sent again automatically. "
    "Please don't tell the customer it is done until it has been confirmed.")


def public_status(record: Dict[str, Any]) -> str:
    status = record["status"]
    if status == "pending":
        return "pending_approval"
    if status in ("dispatching", "uncertain"):
        return "needs_reconciliation"
    result = record.get("result")
    if status == "executed" and isinstance(result, dict) and result.get("outcome") == "declined":
        return "declined"
    return status


def default_project(record: Dict[str, Any]) -> Dict[str, Any]:
    """The small, redacted view of an action: what the UI and the model may see."""
    status = public_status(record)
    result = record.get("result") if isinstance(record.get("result"), dict) else {}
    codes = [r for r in record.get("rules") or [] if r != "registry.definition_review" or status == "pending_approval"]
    if status == "declined" and result.get("reason"):
        codes.append("handler." + result["reason"])
    return {
        "action_id": record["id"], "tool": record["tool"], "status": status,
        "reason_codes": codes, "receipt": result.get("receipt"), "ledger_effect": None,
        "policy_hash": record.get("policy_hash"), "reviewer": record.get("reviewer"),
        "model_payload": {"status": status, **({"reason_codes": codes} if codes else {})},
    }


class AgentRunner:
    """Drives model runs against an ActionStore. One instance per backend process.

    clients: {"live": GeminiClient(...), "recorded": RecordedClient(...)}; a run
    keeps using the client for its ``source``.
    project: record -> view dict (see ``default_project``); its "model_payload"
    is what the model receives, so keep it to the fields the model needs.
    """

    def __init__(self, store: ActionStore, path: str, principal: Principal, *,
                 clients: Dict[str, Any], system: str,
                 project: Callable[[Dict[str, Any]], Dict[str, Any]] = default_project,
                 max_turns: int = 6, reconcile_text: str = DEFAULT_RECONCILE_TEXT) -> None:
        self.store, self.path, self.principal = store, str(path), principal
        self.clients, self.system, self.project = clients, system, project
        self.max_turns, self.reconcile_text = max_turns, reconcile_text
        self.tools = declarations_for([a.definition for a in store.actions.values()])
        with self._tx() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY, status TEXT NOT NULL, source TEXT NOT NULL, model TEXT,
                scenario TEXT, session TEXT NOT NULL, message TEXT NOT NULL, history TEXT NOT NULL,
                pending_action_id TEXT, final_text TEXT, error TEXT,
                model_ms REAL NOT NULL DEFAULT 0, policy_ms REAL NOT NULL DEFAULT 0,
                turns INTEGER NOT NULL DEFAULT 0, created REAL NOT NULL, updated REAL NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS run_actions (
                run_id TEXT NOT NULL, action_id TEXT NOT NULL, tool TEXT NOT NULL,
                idx INTEGER NOT NULL, policy_ms REAL NOT NULL, PRIMARY KEY (run_id, action_id))""")

    @contextmanager
    def _tx(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        try:
            with db:
                db.execute("BEGIN IMMEDIATE")
                yield db
        finally:
            db.close()

    # --------------------------------------------------------------- public

    def start(self, message: str, *, source: str = "recorded", scenario: Optional[str] = None,
              session: Optional[str] = None) -> Dict[str, Any]:
        if not message or not message.strip():
            raise ValueError("A message is required.")
        if source not in self.clients:
            raise ModelError("not_configured", "No %s model is configured." % source)
        run_id = "run_" + uuid.uuid4().hex[:16]
        now = time.time()
        with self._tx() as db:
            db.execute("INSERT INTO runs (id, status, source, model, scenario, session, message, history,"
                       " created, updated) VALUES (?,?,?,?,?,?,?,?,?,?)",
                       (run_id, "running", source, getattr(self.clients[source], "model", None),
                        scenario, session or run_id, message.strip(),
                        json.dumps([user_content(message.strip())]), now, now))
        self._drive(run_id)
        return self.view(run_id)

    def resume(self, run_id: str) -> Dict[str, Any]:
        """Continue a paused or failed run. Safe to call twice: only one caller wins."""
        if self._claim(run_id):
            self._drive(run_id)
        return self.view(run_id)

    def resume_for_action(self, action_id: str) -> List[Dict[str, Any]]:
        """Resume every run waiting on this action (after a review or reconciliation)."""
        with self._tx() as db:
            ids = [r["id"] for r in db.execute(
                "SELECT id FROM runs WHERE pending_action_id=? AND status IN ('awaiting_approval',"
                " 'needs_reconciliation')", (action_id,))]
        return [self.resume(run_id) for run_id in ids]

    def recover(self, stale_after: float = 0.0) -> List[str]:
        """After a restart: runs left 'running' by a dead process become resumable."""
        with self._tx() as db:
            ids = [r["id"] for r in db.execute("SELECT id FROM runs WHERE status='running' AND updated<=?",
                                                (time.time() - stale_after,))]
            for run_id in ids:
                db.execute("UPDATE runs SET status='interrupted' WHERE id=? AND status='running'", (run_id,))
        return ids

    def list(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._tx() as db:
            ids = [r["id"] for r in db.execute("SELECT id FROM runs ORDER BY created DESC LIMIT ?", (limit,))]
        return [self.view(i) for i in ids]

    def view(self, run_id: str) -> Dict[str, Any]:
        """The backend contract for one run. Small and redacted by design."""
        run = self._load(run_id)
        with self._tx() as db:
            links = [dict(r) for r in db.execute(
                "SELECT * FROM run_actions WHERE run_id=? ORDER BY idx", (run_id,))]
        actions = []
        for link in links:
            item = self.project(self.store.get(link["action_id"]))
            item.pop("model_payload", None)
            item["policy_latency_ms"] = round(link["policy_ms"], 3)
            actions.append(item)
        latest = actions[-1] if actions else {}
        policy = self.store.policy
        return {
            "run_id": run["id"], "status": run["status"], "source": run["source"],
            "model": run["model"], "scenario": run["scenario"], "message": run["message"],
            "final_text": run["final_text"],
            "action_id": latest.get("action_id"), "reason_codes": latest.get("reason_codes", []),
            "receipt": latest.get("receipt"), "ledger_effect": latest.get("ledger_effect"),
            "policy_version": "%s (%s)" % (policy.version, policy.fingerprint()[:12]),
            "model_latency_ms": round(run["model_ms"], 1), "policy_latency_ms": round(run["policy_ms"], 3),
            "turns": run["turns"], "awaiting_action_id": run["pending_action_id"]
            if run["status"] in ("awaiting_approval", "needs_reconciliation") else None,
            "actions": actions, "error": run["error"],
            "created_at": run["created"], "updated_at": run["updated"],
        }

    # ------------------------------------------------------------- internals

    def _load(self, run_id: str) -> Dict[str, Any]:
        with self._tx() as db:
            row = db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        if row is None:
            raise KeyError("Unknown run %s" % run_id)
        run = dict(row)
        run["history"] = json.loads(run["history"])
        run["error"] = json.loads(run["error"]) if run["error"] else None
        return run

    def _save(self, run: Dict[str, Any]) -> None:
        with self._tx() as db:
            db.execute("UPDATE runs SET status=?, model=?, history=?, pending_action_id=?, final_text=?,"
                       " error=?, model_ms=?, policy_ms=?, turns=?, updated=? WHERE id=?",
                       (run["status"], run["model"], json.dumps(run["history"]), run["pending_action_id"],
                        run["final_text"], json.dumps(run["error"]) if run["error"] else None,
                        run["model_ms"], run["policy_ms"], run["turns"], time.time(), run["id"]))

    def _claim(self, run_id: str) -> bool:
        """Atomically move a resumable run to 'running'. False if someone else has it."""
        with self._tx() as db:
            cur = db.execute("UPDATE runs SET status='running', error=NULL, updated=? WHERE id=? AND status IN (%s)"
                             % ",".join("?" * len(RESUMABLE)), (time.time(), run_id, *RESUMABLE))
            return cur.rowcount == 1

    def _stop(self, run: Dict[str, Any], status: str, **fields: Any) -> None:
        run["status"] = status
        run.update(fields)
        self._save(run)

    def _key(self, run_id: str, call: ToolCall) -> str:
        digest = hashlib.sha256(canonical([call.name, call.args]).encode()).hexdigest()[:24]
        return "run:%s:%s" % (run_id, digest)

    def _drive(self, run_id: str) -> None:
        run = self._load(run_id)
        run["pending_action_id"] = None
        while True:
            last = run["history"][-1] if run["history"] else None
            if last and last.get("role") == "model":
                calls, text, _ = parse_turn(last)
                if not calls:
                    return self._stop(run, "completed", final_text=text.strip())
                if not self._handle_turn(run, calls):
                    return  # paused or stopped; already saved
                continue

            if run["turns"] >= self.max_turns:
                return self._stop(run, "turn_limit", error={"kind": "turn_limit",
                                                            "message": "Stopped after %d model turns." % self.max_turns})
            client = self.clients.get(run["source"])
            if client is None:
                return self._stop(run, "model_error", error={"kind": "not_configured",
                                                             "message": "No %s model is configured." % run["source"]})
            try:
                resp = client.generate(run["history"], tools=self.tools, system=self.system,
                                       scenario=run["scenario"])
            except ModelError as exc:
                return self._stop(run, "model_error", error={"kind": exc.kind, "message": str(exc)})
            run["turns"] += 1
            run["model_ms"] += resp.latency_ms
            run["model"] = resp.model or run["model"]
            if resp.content is None or (not resp.calls and not resp.text.strip() and not resp.unsupported):
                return self._stop(run, "no_response", error={"kind": "empty_response",
                                                             "finish_reason": resp.finish_reason})
            if resp.unsupported and not resp.calls:
                return self._stop(run, "unsupported_response", error={
                    "kind": "unsupported_response", "parts": sorted(set(resp.unsupported))})
            # Saved before anything runs: a crash from here on resubmits the
            # same call, and the idempotency key makes that a lookup.
            run["history"].append(resp.content)
            self._save(run)

    def _handle_turn(self, run: Dict[str, Any], calls: List[ToolCall]) -> bool:
        """Validate and submit one model turn. True to keep driving, False if paused/stopped."""
        problem = None
        if len(calls) > 1:
            problem = "one_call_per_turn"
        elif calls[0].name not in self.store.actions:
            problem = "unknown_tool"
        elif not isinstance(calls[0].args, dict):
            problem = "invalid_arguments"
        if problem:
            run["history"].append(tool_results_content(
                [(c, {"status": "not_executed", "reason": problem}) for c in calls]))
            self._save(run)
            return True

        call = calls[0]
        key = self._key(run["id"], call)
        started = time.perf_counter()
        try:
            record = self.store.submit(call.name, call.args, run["session"], self.principal, key)
        except ApprovalError as exc:
            run["history"].append(tool_results_content(
                [(call, {"status": "not_executed", "reason": str(exc)})]))
            self._save(run)
            return True
        except Exception:
            # The handler failed mid-dispatch. The store marked the action
            # uncertain; find it by its key rather than guess.
            record = self.store.find(self.principal.id, key)
            if record is None:
                raise
        policy_ms = max(0.0, (time.perf_counter() - started) * 1000 - self.store.last_handler_ms)
        with self._tx() as db:
            idx = db.execute("SELECT COUNT(*) FROM run_actions WHERE run_id=?", (run["id"],)).fetchone()[0]
            cur = db.execute("INSERT OR IGNORE INTO run_actions VALUES (?,?,?,?,?)",
                             (run["id"], record["id"], call.name, idx, policy_ms))
            added = cur.rowcount == 1
        if added:
            run["policy_ms"] += policy_ms

        view = self.project(record)
        status = view["status"]
        if status == "pending_approval":
            self._stop(run, "awaiting_approval", pending_action_id=record["id"])
            return False
        if status == "needs_reconciliation":
            self._stop(run, "needs_reconciliation", pending_action_id=record["id"],
                       final_text=self.reconcile_text)
            return False
        run["history"].append(tool_results_content([(call, view["model_payload"])]))
        self._save(run)
        return True
