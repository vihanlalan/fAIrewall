"""Control plane: versions, rollout, drift, fleet events, fleet kill switch, auth."""

import json

import pytest
from fastapi.testclient import TestClient

from fairewall import Firewall, Policy, ToolPolicy
from fairewall.control import ControlPlaneSync, ControlStore, create_control_app
from fairewall.proxy import create_app

ADMIN = {"X-API-Key": "admin-key", "X-Actor": "vihan"}

POLICY_V1 = {"version": "1", "tools": {"process_refund": {"max_values": {"amount": 400}},
                                       "send_email": {"forbid_when_tainted": True}}}
POLICY_V2 = {"version": "2", "tools": {"process_refund": {"max_values": {"amount": 100}},
                                       "send_email": {"forbid_when_tainted": True}}}


@pytest.fixture
def cp():
    store = ControlStore()
    return TestClient(create_control_app(store=store, admin_key="admin-key")), store


def _register(client, name="gw-1", env="production"):
    r = client.post("/cp/v1/gateways", json={"name": name, "environment": env}, headers=ADMIN)
    assert r.status_code == 200
    return r.json()


def _gateway(client, token, fw=None, auth=True, reviewer=True):
    """A gateway firewall wired to the test control plane without real sockets."""
    fw = fw or Firewall()
    sync = ControlPlaneSync(fw, "http://cp.invalid", token, auth_required=auth,
                            separate_reviewer_key=reviewer)

    def post(payload):
        r = client.post("/cp/v1/agent/sync", json=json.loads(json.dumps(payload, default=str)),
                        headers={"Authorization": "Bearer " + token})
        if r.status_code != 200:
            raise RuntimeError("HTTP %d" % r.status_code)
        return r.json()

    sync._post = post
    return fw, sync


def _version(client, body, name="refunds", note=""):
    r = client.post("/cp/v1/policies", json={"name": name, "body": body, "note": note}, headers=ADMIN)
    assert r.status_code == 200, r.text
    return r.json()


def _deploy(client, env, name, version, shadow=False):
    r = client.post("/cp/v1/environments/%s/deploy" % env,
                    json={"policy": name, "version": version, "shadow": shadow}, headers=ADMIN)
    assert r.status_code == 200, r.text
    return r.json()


# ----------------------------------------------------------------- auth

def test_admin_endpoints_need_the_key_and_dashboard_is_public(cp):
    client, _ = cp
    assert client.get("/cp/v1/overview").status_code == 401
    assert client.get("/cp/v1/overview", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/cp/v1/overview", headers=ADMIN).status_code == 200
    assert "Control plane" in client.get("/").text
    assert client.get("/cp/v1/info").json()["auth_required"] is True


def test_gateway_token_is_shown_once_and_stored_hashed(cp):
    client, store = cp
    reg = _register(client)
    token = reg["token"]
    assert token.startswith("fwgw_")
    tables = ("policy_versions", "environments", "gateways", "events", "fleet_freezes", "changes")
    dump = json.dumps([[dict(r) for r in store._rows("SELECT * FROM " + t)] for t in tables])
    assert reg["gateway"]["id"] in dump  # the dump really holds the gateway
    assert token not in dump
    assert "token" not in json.dumps(client.get("/cp/v1/gateways", headers=ADMIN).json())


def test_unknown_or_removed_gateway_token_is_refused(cp):
    client, _ = cp
    assert client.post("/cp/v1/agent/sync", json={},
                       headers={"Authorization": "Bearer fwgw_nope"}).status_code == 401
    reg = _register(client)
    client.delete("/cp/v1/gateways/" + reg["gateway"]["id"], headers=ADMIN)
    assert client.post("/cp/v1/agent/sync", json={},
                       headers={"Authorization": "Bearer " + reg["token"]}).status_code == 401


# ------------------------------------------------------------- policies

def test_versions_are_validated_numbered_and_fingerprinted(cp):
    client, _ = cp
    v1 = _version(client, POLICY_V1, note="first")
    v2 = _version(client, POLICY_V2)
    assert (v1["version"], v2["version"]) == (1, 2)
    assert v1["fingerprint"] == Policy.from_dict(POLICY_V1).fingerprint()
    bad = client.post("/cp/v1/policies", json={"name": "refunds", "body": {"nonsense_key": 1}},
                      headers=ADMIN)
    assert bad.status_code == 400 and "Invalid policy" in bad.json()["detail"]
    assert client.post("/cp/v1/policies", json={"name": "bad name!", "body": {}},
                       headers=ADMIN).status_code == 400
    assert client.get("/cp/v1/policies/refunds/9", headers=ADMIN).status_code == 404


def test_deploy_reaches_gateway_and_health_is_full(cp):
    client, _ = cp
    reg = _register(client)
    _version(client, POLICY_V1)
    _deploy(client, "production", "refunds", 1)
    fw, sync = _gateway(client, reg["token"])
    assert sync.sync_once()
    assert fw.policy.fingerprint() == Policy.from_dict(POLICY_V1).fingerprint()
    assert fw.inspect("process_refund", {"amount": 500}, session_id="s").blocked
    assert fw.audit.records()[0]["event"] == "policy_applied"
    gw = client.get("/cp/v1/overview", headers=ADMIN).json()["gateways"][0]
    assert gw["health"]["score"] == 100 and gw["health"]["issues"] == []


def test_drift_is_detected_when_a_gateway_runs_something_else(cp):
    client, _ = cp
    reg = _register(client)
    _version(client, POLICY_V1)
    _deploy(client, "production", "refunds", 1)
    fw, sync = _gateway(client, reg["token"])
    sync.sync_once()
    fw.policy = Policy(max_spend_per_transaction=99999)  # someone edits it locally
    sync._applied_fingerprint = fw.policy.fingerprint()   # ...and the sync is fooled once
    report = sync._report()
    client.post("/cp/v1/agent/sync", json={"report": report, "log_id": "", "events": []},
                headers={"Authorization": "Bearer " + reg["token"]})
    ov = client.get("/cp/v1/overview", headers=ADMIN).json()
    health = ov["gateways"][0]["health"]
    assert health["score"] == 75 and any("Drift" in i for i in health["issues"])
    assert any("not on their assigned policy" in i for i in ov["issues"])


def test_shadow_rollout_then_promote_then_rollback(cp):
    client, _ = cp
    staging = _register(client, "gw-staging", "staging")
    prod = _register(client, "gw-prod", "production")
    _version(client, POLICY_V1)
    _version(client, POLICY_V2)
    _deploy(client, "production", "refunds", 1)
    _deploy(client, "staging", "refunds", 2, shadow=True)
    fw_s, sync_s = _gateway(client, staging["token"])
    fw_p, sync_p = _gateway(client, prod["token"])
    sync_s.sync_once(); sync_p.sync_once()
    assert fw_s.shadow is True and fw_p.shadow is False
    assert fw_s.inspect("process_refund", {"amount": 150}, session_id="s").allowed  # shadow: logs only

    r = client.post("/cp/v1/environments/production/promote", json={"source": "staging"}, headers=ADMIN)
    assert r.json()["version"] == 2 and r.json()["shadow"] is False
    sync_p.sync_once()
    assert fw_p.policy.fingerprint() == Policy.from_dict(POLICY_V2).fingerprint()

    _deploy(client, "production", "refunds", 1)  # roll back
    sync_p.sync_once()
    assert fw_p.policy.fingerprint() == Policy.from_dict(POLICY_V1).fingerprint()
    changes = client.get("/cp/v1/changes", headers=ADMIN).json()["changes"]
    rollback = changes[0]
    assert rollback["action"] == "deployed" and rollback["actor"] == "vihan"
    assert rollback["detail"]["previous"] == {"policy": "refunds", "version": 2, "shadow": False}


def test_tampered_policy_in_reply_is_not_applied(cp):
    client, _ = cp
    reg = _register(client)
    fw, sync = _gateway(client, reg["token"])
    before = fw.policy.fingerprint()
    sync._post = lambda payload: {"policy": {"name": "x", "version": 1, "fingerprint": "0" * 16,
                                             "shadow": False, "body": POLICY_V1}, "freezes": [],
                                  "acked_seq": -1}
    assert sync.sync_once() is False
    assert fw.policy.fingerprint() == before


def test_unreachable_control_plane_keeps_last_policy(cp):
    client, _ = cp
    reg = _register(client)
    _version(client, POLICY_V1)
    _deploy(client, "production", "refunds", 1)
    fw, sync = _gateway(client, reg["token"])
    sync.sync_once()

    def down(payload):
        raise OSError("connection refused")

    sync._post = down
    assert sync.sync_once() is False
    assert sync.status["ok"] is False and "connection refused" in sync.status["last_error"]
    assert fw.policy.fingerprint() == Policy.from_dict(POLICY_V1).fingerprint()
    assert fw.inspect("process_refund", {"amount": 500}, session_id="s").blocked


# --------------------------------------------------------------- events

def test_decisions_reach_the_fleet_feed_once(cp):
    client, store = cp
    reg = _register(client)
    _version(client, POLICY_V1)
    _deploy(client, "production", "refunds", 1)
    fw, sync = _gateway(client, reg["token"])
    sync.sync_once()                      # learns where the log stands
    fw.inspect("process_refund", {"amount": 900, "order_id": "o1"}, session_id="s")
    fw.inspect("process_refund", {"amount": 50, "order_id": "o2"}, session_id="s")
    sync.sync_once()
    sync.sync_once()                      # nothing new: must not duplicate
    blocks = client.get("/cp/v1/events?actions=block", headers=ADMIN).json()["events"]
    assert len(blocks) == 1 and blocks[0]["tool"] == "process_refund"
    assert blocks[0]["gateway"] == "gw-1" and blocks[0]["arguments"]["amount"] == 900
    every = client.get("/cp/v1/events?limit=50", headers=ADMIN).json()["events"]
    assert len([e for e in every if e["event"] == "tool_call_inspected"]) == 2


def test_restarted_gateway_with_fresh_log_is_not_mistaken_for_a_replay(cp):
    client, _ = cp
    reg = _register(client)
    for _ in range(2):  # two "boots", each with a new in-memory log starting at seq 0
        fw, sync = _gateway(client, reg["token"])
        fw.inspect("lookup", {}, session_id="s")
        sync.sync_once()
        fw.inspect("process_refund", {"amount": 99999}, session_id="s")
        sync.sync_once()
    blocks = client.get("/cp/v1/events?actions=block", headers=ADMIN).json()["events"]
    assert len(blocks) == 2


def test_compare_replays_real_traffic(cp):
    client, _ = cp
    reg = _register(client)
    _version(client, POLICY_V1)
    _deploy(client, "production", "refunds", 1)
    fw, sync = _gateway(client, reg["token"])
    sync.sync_once()
    for amount in (50, 150, 300):
        fw.inspect("process_refund", {"amount": amount}, session_id="s%d" % amount)
    sync.sync_once()
    stricter = client.post("/cp/v1/policies/compare", headers=ADMIN, json={
        "base": {"name": "refunds", "version": 1}, "draft": POLICY_V2}).json()
    assert stricter["events_replayed"] == 3
    assert stricter["replay"]["stricter"] == 2 and stricter["replay"]["looser"] == 0
    assert {"path": "tools.process_refund.max_values.amount", "before": 400.0, "after": 100.0,
            "kind": "changed"} in stricter["settings"]
    _version(client, POLICY_V2)
    looser = client.post("/cp/v1/policies/compare", headers=ADMIN, json={
        "base": {"name": "refunds", "version": 2}, "target": {"name": "refunds", "version": 1}}).json()
    assert looser["replay"]["looser"] == 2
    bad = client.post("/cp/v1/policies/compare", headers=ADMIN, json={
        "base": {"name": "refunds", "version": 1}, "draft": {"bogus": 1}})
    assert bad.status_code == 400


# ---------------------------------------------------------- kill switch

def test_fleet_freeze_reaches_gateways_and_release_lifts_only_its_own(cp):
    client, _ = cp
    reg = _register(client)
    fw, sync = _gateway(client, reg["token"])
    fw.freeze("session", "local-run", reason="local", by="gateway-ops")
    r = client.post("/cp/v1/killswitch/freeze", json={"scope": "principal", "target": "billing-bot",
                                                      "reason": "incident 7"}, headers=ADMIN)
    assert r.status_code == 200
    sync.sync_once()
    keys = {(f["scope"], f["target"]) for f in fw.freezes()}
    assert keys == {("session", "local-run"), ("principal", "billing-bot")}

    fw.unfreeze("principal", "billing-bot")   # released locally: the fleet freeze comes back
    sync.sync_once()
    assert ("principal", "billing-bot") in {(f["scope"], f["target"]) for f in fw.freezes()}

    client.post("/cp/v1/killswitch/unfreeze", json={"scope": "principal", "target": "billing-bot"},
                headers=ADMIN)
    sync.sync_once()
    assert {(f["scope"], f["target"]) for f in fw.freezes()} == {("session", "local-run")}


def test_fleet_freeze_released_while_gateway_was_down_is_lifted_after_restart(cp, tmp_path):
    client, _ = cp
    reg = _register(client)
    path = str(tmp_path / "ks.json")
    fw, sync = _gateway(client, reg["token"], fw=Firewall(kill_switch_path=path))
    client.post("/cp/v1/killswitch/freeze", json={}, headers=ADMIN)
    sync.sync_once()
    assert fw.freezes()
    client.post("/cp/v1/killswitch/unfreeze", json={}, headers=ADMIN)
    fw2, sync2 = _gateway(client, reg["token"], fw=Firewall(kill_switch_path=path))  # restart
    assert fw2.freezes()            # still frozen from disk until it hears otherwise
    sync2.sync_once()
    assert fw2.freezes() == []


# -------------------------------------------------------------- gateway

def test_gateway_health_endpoint_reports_control_plane(cp):
    client, _ = cp
    reg = _register(client)
    _version(client, POLICY_V1)
    _deploy(client, "production", "refunds", 1)
    fw, sync = _gateway(client, reg["token"])
    sync.sync_once()
    gateway = TestClient(create_app(firewall=fw))
    cp_status = gateway.get("/health").json()["control_plane"]
    assert cp_status["managed"] is True and cp_status["ok"] is True
    assert cp_status["policy"]["name"] == "refunds" and cp_status["policy"]["version"] == 1
    assert TestClient(create_app()).get("/health").json()["control_plane"] is None


def test_event_flood_is_capped_and_malformed_events_are_skipped(cp):
    client, store = cp
    reg = _register(client)
    events = [{"seq": i, "event": "tool_call_inspected", "tool": "t", "action": "allow"}
              for i in range(1500)] + [{"no_seq": True}]
    r = client.post("/cp/v1/agent/sync", json={"report": {}, "log_id": "abc", "events": events},
                    headers={"Authorization": "Bearer " + reg["token"]})
    assert r.status_code == 200 and r.json()["acked_seq"] == 999
