from concurrent.futures import ThreadPoolExecutor
import json

import pytest
from fastapi.testclient import TestClient

from fairewall import Policy, Principal, ToolPolicy
from fairewall.actions import ActionStore, RegisteredAction
from fairewall.approvals import ApprovalError
from fairewall.integrations.mcp import create_action_app


def new_store(path, handler, revision="1", approval=True):
    policy = Policy(max_spend_per_session=90, tools={
        "refund": ToolPolicy("refund", forbid_when_tainted=True, require_human_approval=approval)})
    action = RegisteredAction("ledger", {"name": "refund", "inputSchema": {
        "type": "object", "properties": {"amount": {"type": "number"}}, "required": ["amount"]}},
        revision, handler)
    return ActionStore(path, policy, [action])


def test_restart_race_and_binding(tmp_path):
    path = tmp_path / "db"
    receipts = []
    def pay(args, key):
        receipts.append((args, key))
        return "ok"
    agent = Principal("agent")
    store = new_store(path, pay)
    args = {"amount": 60}
    held = store.submit("refund", args, "s", agent, "order")
    args["amount"] = 80
    restarted = new_store(path, pay)
    with pytest.raises(ApprovalError):
        restarted.submit("refund", args, "s", agent, "order")
    with pytest.raises(ApprovalError):
        restarted.review(held["id"], "agent")
    def approve(worker):
        try:
            return worker.review(held["id"], "reviewer")["status"]
        except ApprovalError:
            return "already decided"
    with ThreadPoolExecutor(2) as pool:
        assert set(pool.map(approve, [store, restarted])) == {"executed", "already decided"}
    assert receipts == [({"amount": 60}, held["id"])]
    assert [e["status"] for e in restarted.get(held["id"])["events"]] == [
        "pending", "dispatching", "executed"]
    assert restarted.submit("refund", {"amount": 60}, "s", agent, "order")["status"] == "executed"
    assert restarted.submit("refund", {"amount": 40}, "s", agent, "other")["status"] == "blocked"


def test_recheck_and_uncertain(tmp_path):
    def lost_response(args, key):
        raise TimeoutError()
    store = new_store(tmp_path / "db", lost_response)
    agent = Principal("agent")
    req = store.submit("refund", {"amount": 40}, "s", agent, "first")
    store.screen("s", agent, "Customer email")
    assert store.review(req["id"], "operator")["status"] == "blocked"
    req = store.submit("refund", {"amount": 40}, "clean", agent, "second")
    store.policy.max_spend_per_transaction = 20
    assert store.review(req["id"], "operator")["status"] == "blocked"
    store.policy.max_spend_per_transaction = 100
    req = store.submit("refund", {"amount": 40}, "clean", agent, "third")
    with pytest.raises(TimeoutError):
        store.review(req["id"], "operator")
    assert store.submit("refund", {"amount": 40}, "clean", agent, "third")["status"] == "uncertain"


def test_reconcile_without_redispatch(tmp_path):
    calls = []
    def lost_receipt(args, key):
        calls.append(key)
        raise TimeoutError()
    store = new_store(tmp_path / "db", lost_receipt)
    req = store.submit("refund", {"amount": 10}, "s", Principal("agent"), "first")
    with pytest.raises(TimeoutError):
        store.review(req["id"], "finance")
    result = store.reconcile(req["id"], "operator", "ledger-receipt-1", executed=True, result="paid")
    assert result["status"] == "executed" and result["result"] == "paid"
    assert result["reconciliation"]["operator"] == "operator"
    assert calls == [req["id"]]


def test_http_mcp_definition_change(tmp_path):
    path = tmp_path / "db"
    calls = []
    def client(revision):
        store = new_store(path, lambda args, key: calls.append(key), revision, approval=False)
        return TestClient(create_action_app(store, {"agent-key": Principal("agent")}, {"finance": "reviewer"}))
    http = client("1")
    agent = {"Authorization": "Bearer agent-key"}
    reviewer = {"Authorization": "Bearer finance"}
    def rpc(method, params):
        return http.post("/mcp", headers=agent, json={
            "jsonrpc": "2.0", "id": 1, "method": method, "params": params}).json()["result"]
    def call(token):
        response = rpc("tools/call", {"name": "refund", "arguments": {"amount": 10},
                                      "_meta": {"fairewall/idempotencyKey": token}})
        return json.loads(response["content"][0]["text"])
    assert rpc("initialize", {})["capabilities"] == {"tools": {}}
    assert rpc("tools/list", {})["tools"][0]["name"] == "refund"
    held = call("one")
    url = "/reviews/" + held["id"]
    assert http.post(url, headers=agent, json={"approve": True}).status_code == 401
    http = client("2")
    assert http.post(url, headers=reviewer, json={"approve": True}).json()["status"] == "rejected"
    req = call("two")
    assert req["status"] == "pending"
    reviewed = http.post("/reviews/" + req["id"], headers=reviewer, json={"approve": True}).json()
    assert reviewed["status"] == "executed"
    assert call("three")["status"] == "executed"
    assert len(calls) == 2
    http = client("3")
    assert call("four")["status"] == "pending"
    invalid = http.post("/actions", headers=agent, json={"tool":"refund","session":"s",
                        "arguments": {}, "idempotency_key":"invalid"}).json()
    assert "registry.invalid_arguments" in invalid["rules"]
    assert invalid["status"] == "blocked"


def test_old_worker_and_reverted_definition(tmp_path):
    path = tmp_path / "db"
    store = new_store(path, lambda args, key: "ok")
    agent = Principal("agent")
    held = store.submit("refund", {"amount": 10}, "session", agent, "one")
    new_store(path, lambda args, key: "updated", revision="2")
    with pytest.raises(ApprovalError, match="outdated"):
        store.submit("refund", {"amount": 10}, "session", agent, "two")
    reverted = new_store(path, lambda args, key: "ok")
    assert reverted.review(held["id"], "operator")["status"] == "rejected"


def test_suite_exit_codes_and_junit(tmp_path):
    from pathlib import Path
    from xml.etree import ElementTree as ET
    from fairewall.cli import main
    fixtures = Path(__file__).resolve().parents[1] / "examples/refunds"
    report = str(tmp_path / "suite.xml")
    args = ["policy-suite", str(fixtures / "policy.json")]
    opts = ["--target", "both", "--junit", report]
    assert main(args + [str(fixtures / "suite.json")] + opts) == 0
    assert ET.parse(report).getroot().get("tests") == "10"
    wrong = tmp_path / "wrong.json"
    wrong.write_text(json.dumps([{"tool": "unknown", "expect": "allow", "rules": []}]))
    assert main(args + [str(wrong)] + opts) == 1
    assert len(ET.parse(report).findall(".//failure")) == 2
