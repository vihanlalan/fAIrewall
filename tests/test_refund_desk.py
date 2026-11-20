"""Refund desk end to end: ledger units, agent runs, reviews and ordinary failures.

Step 1: the $40 refund writes 0 rows while pending, 1 after approval, 1 after a
retry; the $140 refund writes none.
Step 2: a model run (recorded here; live Gemini uses the same code path) looks
up, proposes, pauses for review and answers consistently with the ledger.
Step 4: restart during a pending approval, duplicate and concurrent approval,
a policy change while waiting, a model timeout after the refund executed, and
a refund whose outcome is unknown.
"""

import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples" / "refunds"))

from backend import create_backend  # noqa: E402
from workflow import AGENT, RefundDesk  # noqa: E402

from fairewall.approvals import ApprovalError  # noqa: E402
from fairewall.integrations.gemini import (  # noqa: E402
    ModelError, ModelResponse, RecordedClient, declarations_for, normalize_args, parse_turn,
    tool_results_content,
)

OP = {"Authorization": "Bearer op-key"}
RV = {"Authorization": "Bearer rv-key"}
MSG_40 = "Customer on ORD-1001 says the blender arrived cracked and wants $40 back."
MSG_140 = "Customer on ORD-1001 wants $140 back."


def backend(path, **kw):
    app = create_backend(path, operator_keys={"op-key": "frontend"},
                         reviewer_keys={"rv-key": "finance-lead"}, **kw)
    return TestClient(app), app


def rows(app):
    return len(app.state.desk.ledger.refunds())


# ------------------------------------------------------------------ step 1

def test_units_are_cents_in_schema_ledger_and_policy(tmp_path):
    desk = RefundDesk(tmp_path)
    desk.review_definitions("setup")
    at_cap = desk.store.submit("refund", {"order_id": "ORD-1001", "amount_cents": 10000}, "a", AGENT, "cap")
    over = desk.store.submit("refund", {"order_id": "ORD-1001", "amount_cents": 10001}, "b", AGENT, "over")
    assert at_cap["status"] == "pending"                        # $100.00 is within the $100 cap
    assert over["status"] == "blocked" and "financial.transaction_limit" in over["rules"]
    dollars = desk.store.submit("refund", {"order_id": "ORD-1001", "amount_cents": 40.5}, "c", AGENT, "frac")
    assert dollars["status"] == "blocked" and "registry.invalid_arguments" in dollars["rules"]
    extra = desk.store.submit("refund", {"order_id": "ORD-1001", "amount_cents": 4000, "note": "x"},
                              "d", AGENT, "extra")
    assert extra["status"] == "blocked"                         # additionalProperties: false
    assert desk.ledger.refunds() == []
    desk.close()


def test_step1_done_criteria(tmp_path):
    desk = RefundDesk(tmp_path)
    assert [d["tool"] for d in desk.review_definitions("setup")] == ["lookup_order", "refund"]
    look = desk.store.submit("lookup_order", {"order_id": "ORD-1001"}, "s", AGENT, "l1")
    assert look["status"] == "executed" and look["result"]["refundable_cents"] == 12000
    small = desk.store.submit("refund", {"order_id": "ORD-1001", "amount_cents": 4000}, "s", AGENT, "r40")
    big = desk.store.submit("refund", {"order_id": "ORD-1001", "amount_cents": 14000}, "s", AGENT, "r140")
    assert small["status"] == "pending" and small["rules"] == ["schema.human_approval_required"]
    assert big["status"] == "blocked" and len(desk.ledger.refunds()) == 0
    assert desk.store.review(small["id"], "finance")["status"] == "executed"
    assert len(desk.ledger.refunds()) == 1
    retry = desk.store.submit("refund", {"order_id": "ORD-1001", "amount_cents": 4000}, "s", AGENT, "r40")
    assert retry["id"] == small["id"] and len(desk.ledger.refunds()) == 1
    assert desk.ledger.order("ORD-1001")["refunded_cents"] == 4000
    desk.close()


def test_definition_review_is_separate_from_refund_decisions(tmp_path):
    desk = RefundDesk(tmp_path)
    look = desk.store.submit("lookup_order", {"order_id": "ORD-1001"}, "s", AGENT, "l1")
    assert look["status"] == "pending" and "registry.definition_review" in look["rules"]
    assert {d["tool"] for d in desk.store.pending_definitions()} == {"lookup_order", "refund"}
    desk.store.review_definition("refund", "security")
    assert [d["tool"] for d in desk.store.pending_definitions()] == ["lookup_order"]
    # Reviewing the refund *definition* approved no refund.
    held = desk.store.submit("refund", {"order_id": "ORD-1001", "amount_cents": 4000}, "s", AGENT, "r")
    assert held["status"] == "pending" and held["rules"] == ["schema.human_approval_required"]
    with pytest.raises(ApprovalError):
        desk.store.review_definition("refund", "  ")
    desk.close()


def test_ledger_checks_refundable_amount_at_write_time(tmp_path):
    desk = RefundDesk(tmp_path)
    desk.review_definitions("setup")
    held = desk.store.submit("refund", {"order_id": "ORD-1003", "amount_cents": 5000}, "s", AGENT, "r")
    done = desk.store.review(held["id"], "finance")
    assert done["status"] == "executed" and done["result"]["outcome"] == "declined"
    assert done["result"]["reason"] == "exceeds_refundable" and desk.ledger.refunds() == []
    desk.close()


# ------------------------------------------------------------- step 2 + 3

def test_recorded_run_pauses_for_review_and_answers_from_the_ledger(tmp_path):
    client, app = backend(tmp_path)
    run = client.post("/api/runs", json={"message": MSG_40}, headers=OP).json()
    assert run["status"] == "awaiting_approval" and run["source"] == "recorded"
    assert run["reason_codes"] == ["schema.human_approval_required"]
    assert run["ledger_effect"] == {"changed": False} and rows(app) == 0
    assert [a["tool"] for a in run["actions"]] == ["lookup_order", "refund"]
    for field in ("run_id", "action_id", "source", "model", "status", "reason_codes", "policy_version",
                  "receipt", "ledger_effect", "model_latency_ms", "policy_latency_ms"):
        assert field in run
    assert "arguments" not in json.dumps(run) and "principal" not in json.dumps(run)

    pending = client.get("/api/reviews", headers=RV).json()["pending"]
    assert [(p["order_id"], p["amount_cents"], p["run_ids"]) for p in pending] == [
        ("ORD-1001", 4000, [run["run_id"]])]
    decided = client.post("/api/reviews/" + run["action_id"], json={"approve": True}, headers=RV).json()
    final = decided["runs"][0]
    assert final["status"] == "completed" and rows(app) == 1
    receipt = app.state.desk.ledger.refunds()[0]["receipt"]
    assert final["receipt"] == receipt and receipt in final["final_text"]
    assert final["ledger_effect"] == {"changed": True, "type": "refund", "order_id": "ORD-1001",
                                      "amount_cents": 4000, "receipt": receipt}
    assert decided["action"]["reviewer"] == "finance-lead"     # from server config, not the request
    ledger = client.get("/api/ledger", headers=OP).json()
    assert ledger["consistency"]["agrees"] is True and ledger["consistency"]["ledger_refunds"] == 1


def test_blocked_run_gives_an_accurate_answer(tmp_path):
    client, app = backend(tmp_path)
    run = client.post("/api/runs", json={"message": MSG_140}, headers=OP).json()
    assert run["status"] == "completed" and rows(app) == 0
    assert run["reason_codes"] == ["schema.human_approval_required", "financial.transaction_limit"]
    assert "Nothing was refunded" in run["final_text"] and "$100.00" in run["final_text"]
    assert "finance approval" not in run["final_text"]


def test_rejected_refund_answer_says_nothing_was_refunded(tmp_path):
    client, app = backend(tmp_path)
    run = client.post("/api/runs", json={"message": MSG_40}, headers=OP).json()
    final = client.post("/api/reviews/" + run["action_id"], json={"approve": False}, headers=RV).json()["runs"][0]
    assert final["status"] == "completed" and "nothing was refunded" in final["final_text"]
    assert rows(app) == 0


def test_auth_and_live_configuration(tmp_path):
    client, _ = backend(tmp_path)
    assert client.post("/api/runs", json={"message": MSG_40}).status_code == 401
    assert client.post("/api/runs", json={"message": MSG_40}, headers=RV).status_code == 401
    assert client.get("/api/reviews", headers=OP).status_code == 401
    live = client.post("/api/runs", json={"message": MSG_40, "source": "live"}, headers=OP)
    assert live.status_code == 503 and "GEMINI_API_KEY" in live.json()["detail"]
    assert client.get("/api/health").json()["live_model"] is False
    with pytest.raises(ValueError):
        create_backend(tmp_path / "x", operator_keys={"same": "a"}, reviewer_keys={"same": "b"})


# ------------------------------------------------------------------ step 4

def test_approval_after_restart_resumes_the_saved_turn(tmp_path):
    client, app = backend(tmp_path)
    run = client.post("/api/runs", json={"message": MSG_40}, headers=OP).json()
    app.state.desk.close()
    client2, app2 = backend(tmp_path)                           # the service restarted
    decided = client2.post("/api/reviews/" + run["action_id"], json={"approve": True}, headers=RV).json()
    assert decided["runs"][0]["status"] == "completed" and rows(app2) == 1
    assert client2.get("/api/runs/" + run["run_id"], headers=OP).json()["receipt"]


def test_crash_after_model_proposed_resubmits_without_running_twice(tmp_path):
    client, app = backend(tmp_path)
    run = client.post("/api/runs", json={"message": MSG_40}, headers=OP).json()
    client.post("/api/reviews/" + run["action_id"], json={"approve": True}, headers=RV)
    runner = app.state.runner
    # Simulate a process that died right after saving the model's refund proposal.
    with runner._tx() as db:
        hist = json.loads(db.execute("SELECT history FROM runs WHERE id=?", (run["run_id"],)).fetchone()[0])
        proposal = next(i for i, c in enumerate(hist)
                        if c["role"] == "model" and "refund" in json.dumps(c) and "lookup" not in json.dumps(c))
        db.execute("UPDATE runs SET status='running', history=? WHERE id=?",
                   (json.dumps(hist[:proposal + 1]), run["run_id"]))
    assert runner.recover() == [run["run_id"]]
    again = runner.resume(run["run_id"])
    assert again["status"] == "completed" and rows(app) == 1


def test_duplicate_and_concurrent_approval_write_once(tmp_path):
    client, app = backend(tmp_path)
    run = client.post("/api/runs", json={"message": MSG_40}, headers=OP).json()
    url = "/api/reviews/" + run["action_id"]

    def approve(_):
        return client.post(url, json={"approve": True}, headers=RV).json()

    with ThreadPoolExecutor(4) as pool:
        results = list(pool.map(approve, range(4)))
    assert {r["action"]["status"] for r in results} == {"executed"}
    assert sum(1 for r in results if not r["already_decided"]) == 1
    assert rows(app) == 1
    again = client.post("/api/runs", json={"message": MSG_40}, headers=OP).json()  # a new run is a new action
    assert again["action_id"] != run["action_id"]
    assert client.get("/api/runs/" + run["run_id"], headers=OP).json()["status"] == "completed"


def test_policy_change_while_waiting_is_rechecked(tmp_path):
    client, app = backend(tmp_path)
    run = client.post("/api/runs", json={"message": MSG_40}, headers=OP).json()
    app.state.desk.policy.max_spend_per_transaction = 30         # cap lowered while it waits
    decided = client.post("/api/reviews/" + run["action_id"], json={"approve": True}, headers=RV).json()
    assert decided["action"]["status"] == "blocked"
    assert "financial.transaction_limit" in decided["action"]["reason_codes"]
    final = decided["runs"][0]
    assert final["status"] == "completed" and "nothing was refunded" in final["final_text"]
    assert rows(app) == 0


class FlakyAfterRefund(RecordedClient):
    """Times out once on the turn after the refund result, like a dropped Gemini call."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.failed = False

    def generate(self, history, **kw):
        answered = sum(1 for c in history for p in c.get("parts", []) if p.get("function_response"))
        if answered == 2 and not self.failed:
            self.failed = True
            raise ModelError("timeout", "deadline exceeded")
        return super().generate(history, **kw)


def test_model_timeout_after_refund_executed_retries_without_new_refund(tmp_path):
    flaky = FlakyAfterRefund.from_file(str(ROOT / "examples/refunds/recordings.json"))
    client, app = backend(tmp_path, recorded_client=flaky)
    run = client.post("/api/runs", json={"message": MSG_40}, headers=OP).json()
    after = client.post("/api/reviews/" + run["action_id"], json={"approve": True}, headers=RV).json()["runs"][0]
    assert after["status"] == "model_error" and after["error"]["kind"] == "timeout"
    assert rows(app) == 1 and after["receipt"]                  # the refund did happen
    retried = client.post("/api/runs/%s/retry" % run["run_id"], headers=OP).json()
    assert retried["status"] == "completed" and retried["receipt"] in retried["final_text"]
    assert rows(app) == 1


@pytest.mark.parametrize("fault,executed", [("lost_response", True), ("before_write", False)])
def test_uncertain_refund_enters_reconciliation_and_never_redispatches(tmp_path, fault, executed):
    client, app = backend(tmp_path, fault=fault)
    run = client.post("/api/runs", json={"message": MSG_40}, headers=OP).json()
    decided = client.post("/api/reviews/" + run["action_id"], json={"approve": True}, headers=RV).json()
    stuck = decided["runs"][0]
    assert decided["action"]["status"] == "needs_reconciliation"
    assert stuck["status"] == "needs_reconciliation"
    assert "can't confirm" in stuck["final_text"] and "Refunded" not in stuck["final_text"]
    assert rows(app) == (1 if executed else 0)
    # Retrying the run or re-submitting must not dispatch again.
    assert client.post("/api/runs/%s/retry" % run["run_id"], headers=OP).json()["status"] == "needs_reconciliation"
    assert rows(app) == (1 if executed else 0)
    # Reconcile from the ledger's own record, then the run finishes truthfully.
    settled = client.post("/api/actions/%s/reconcile" % run["action_id"], headers=RV).json()
    assert settled["action"]["status"] == ("executed" if executed else "cancelled")
    final = settled["runs"][0]
    assert final["status"] == "completed" and rows(app) == (1 if executed else 0)
    if executed:
        assert app.state.desk.ledger.refunds()[0]["receipt"] in final["final_text"]
    else:
        assert "nothing was refunded" in final["final_text"].lower()
    assert client.get("/api/ledger", headers=OP).json()["consistency"]["agrees"] is True


# ------------------------------------------------------------ gemini adapter

def test_declarations_share_the_registry_schema():
    from workflow import REFUND
    decl = declarations_for([REFUND])[0]
    assert decl["name"] == "refund" and decl["parameters"]["required"] == ["order_id", "amount_cents"]
    assert "additionalProperties" not in decl["parameters"]      # enforced by the gateway, not the model
    assert decl["parameters"]["properties"]["amount_cents"]["type"] == "integer"


def test_gemini_numbers_and_turn_parsing():
    assert normalize_args({"amount_cents": 4000.0, "x": [1.0, 1.5]}) == {"amount_cents": 4000, "x": [1, 1.5]}
    turn = {"role": "model", "parts": [{"text": "thinking", "thought": True},
                                       {"function_call": {"name": "refund", "args": {"amount_cents": 4000.0}, "id": "c1"},
                                        "thought_signature": "AAE="}]}
    calls, text, unsupported = parse_turn(turn)
    assert calls[0].args == {"amount_cents": 4000} and calls[0].id == "c1" and text == "" and not unsupported
    reply = tool_results_content([(calls[0], {"status": "executed"})])
    assert reply["parts"][0]["function_response"] == {"name": "refund", "response": {"status": "executed"}, "id": "c1"}


def test_gemini_contents_round_trip_with_thought_signatures():
    types = pytest.importorskip("google.genai.types")
    stored = {"role": "model", "parts": [{"function_call": {"name": "refund", "args": {"a": 1}, "id": "c1"},
                                          "thought_signature": "AAFzaWc="}]}
    content = types.Content.model_validate(stored)
    assert content.parts[0].thought_signature == b"\x00\x01sig"
    assert json.loads(content.model_dump_json(exclude_none=True)) == stored


def test_placeholder_key_never_makes_live_calls(monkeypatch):
    from fairewall.integrations.gemini import GeminiClient
    monkeypatch.setenv("GEMINI_API_KEY", "your-gemini-api-key")
    with pytest.raises(ModelError) as exc:
        GeminiClient()
    assert exc.value.kind == "not_configured"


class Scripted:
    """A stand-in model returning given responses, to test the runner's guards."""
    source, model = "recorded", "scripted"

    def __init__(self, responses):
        self.responses = list(responses)

    def generate(self, history, **kw):
        return self.responses.pop(0)


def _runner(tmp_path, responses):
    from fairewall.runs import AgentRunner
    from workflow import SYSTEM_PROMPT, project
    desk = RefundDesk(tmp_path)
    desk.review_definitions("setup")
    return desk, AgentRunner(desk.store, str(tmp_path / "runs.sqlite"), AGENT,
                             clients={"recorded": Scripted(responses)}, system=SYSTEM_PROMPT, project=project)


def _call(name, args, i=0):
    return {"role": "model", "parts": [{"function_call": {"name": name, "args": args, "id": "c%d" % i}}]}


def _resp(content):
    calls, text, unsupported = parse_turn(content)
    return ModelResponse(content=content, calls=calls, text=text, unsupported=unsupported, model="scripted")


def test_two_calls_in_one_turn_run_nothing(tmp_path):
    both = {"role": "model", "parts": _call("refund", {"order_id": "ORD-1001", "amount_cents": 100})["parts"]
            + _call("lookup_order", {"order_id": "ORD-1001"}, 1)["parts"]}
    final = {"role": "model", "parts": [{"text": "I can only do one thing at a time."}]}
    desk, runner = _runner(tmp_path, [_resp(both), _resp(final)])
    run = runner.start("refund and look up")
    assert run["status"] == "completed" and run["actions"] == [] and desk.ledger.refunds() == []
    desk.close()


def test_empty_unknown_and_unsupported_responses_have_clear_statuses(tmp_path):
    desk, runner = _runner(tmp_path, [ModelResponse(content=None, finish_reason="SAFETY", model="scripted")])
    run = runner.start("hello")
    assert run["status"] == "no_response" and run["error"]["finish_reason"] == "SAFETY"
    desk.close()
    unsupported = {"role": "model", "parts": [{"executable_code": {"code": "print(1)"}}]}
    desk, runner = _runner(tmp_path / "b", [_resp(unsupported)])
    assert runner.start("hello")["status"] == "unsupported_response"
    desk.close()
    unknown = _call("delete_everything", {})
    done = {"role": "model", "parts": [{"text": "That tool doesn't exist."}]}
    desk, runner = _runner(tmp_path / "c", [_resp(unknown), _resp(done)])
    run = runner.start("go")
    assert run["status"] == "completed" and run["actions"] == []
    desk.close()


def test_turn_limit_stops_a_looping_model(tmp_path):
    loop = [_resp(_call("lookup_order", {"order_id": "ORD-100%d" % (i % 3 + 1)}, i)) for i in range(10)]
    desk, runner = _runner(tmp_path, loop)
    run = runner.start("look everything up forever")
    assert run["status"] == "turn_limit" and run["turns"] == runner.max_turns
    desk.close()
