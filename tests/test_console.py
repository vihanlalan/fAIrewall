"""Gateway console: the page loads, and its data endpoints are behind the API key."""

from fastapi.testclient import TestClient

from fairewall import Policy, ToolPolicy
from fairewall.proxy import create_app


def _client(**kw):
    policy = Policy(tools={"process_refund": ToolPolicy("process_refund", max_values={"amount": 400.0})})
    return TestClient(create_app(policy=policy, **kw))


def test_root_redirects_to_console_and_page_loads():
    c = _client(api_key="k")
    page = c.get("/")
    assert page.status_code == 200 and "Gateway console" in page.text


def test_console_info_is_public_but_reveals_no_secrets():
    info = _client(api_key="k", reviewer_api_key="r").get("/v1/console/info").json()
    assert info == {"auth_required": True, "separate_reviewer_key": True, "shadow": False, "version": "0.2.0"}
    assert _client().get("/v1/console/info").json()["auth_required"] is False


def test_policy_and_recent_audit_need_the_key():
    c = _client(api_key="k")
    assert c.get("/v1/policy").status_code == 401
    assert c.get("/v1/audit/recent").status_code == 401
    pol = c.get("/v1/policy", headers={"X-API-Key": "k"}).json()
    assert pol["policy"]["tools"]["process_refund"]["max_values"] == {"amount": 400.0}


def test_recent_audit_shows_newest_decision_first():
    c = _client(api_key="k")
    h = {"X-API-Key": "k"}
    c.post("/v1/inspect/tool", headers=h, json={"tool": "process_refund", "arguments": {"amount": 100}})
    c.post("/v1/inspect/tool", headers=h, json={"tool": "process_refund", "arguments": {"amount": 900}})
    rows = c.get("/v1/audit/recent?limit=10", headers=h).json()["records"]
    assert rows[0]["action"] == "block" and rows[0]["tool"] == "process_refund"
    assert any(f["rule_id"] == "financial.transaction_limit" for f in rows[0]["findings"])
    assert rows[0]["seq"] > rows[-1]["seq"]
