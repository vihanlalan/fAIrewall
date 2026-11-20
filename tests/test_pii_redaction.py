"""Single-item PII redaction in tool output: what is hidden, what is left alone."""

import json

import pytest
from fastapi.testclient import TestClient

from fairewall import Firewall, Policy, ToolPolicy
from fairewall.proxy import create_app
from fairewall.rules.egress import _VERHOEFF_D, _VERHOEFF_P, redact_pii, verhoeff_valid

_INV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)


def _aadhaar(base11: str) -> str:
    """Append the Verhoeff check digit, making a checksum-valid Aadhaar-shaped number."""
    c = 0
    for i, ch in enumerate(reversed(base11)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][int(ch)]]
    return base11 + str(_INV[c])


AADHAAR = _aadhaar("23456789012")
AADHAAR_SPACED = "%s %s %s" % (AADHAAR[:4], AADHAAR[4:8], AADHAAR[8:])
BAD_AADHAAR = AADHAAR[:-1] + str((int(AADHAAR[-1]) + 1) % 10)


def test_verhoeff_checksum():
    assert verhoeff_valid(AADHAAR)
    assert not verhoeff_valid(BAD_AADHAAR)


@pytest.mark.parametrize("value,kind", [
    ("asha.k@gmail.com", "email"),
    ("+91 98765 43210", "phone"),
    ("9876543210", "phone"),
    ("09876543210", "phone"),
    ("022-2345-6789", "phone"),
    ("+44 20 7946 0958", "phone"),
    ("(415) 555-0100", "phone"),
    (AADHAAR_SPACED, "aadhaar"),
    (AADHAAR, "aadhaar"),
    ("ABCPE1234F", "pan"),
    ("4111 1111 1111 1111", "card"),
    ("123-45-6789", "ssn"),
])
def test_each_identifier_is_redacted(value, kind):
    out, counts = redact_pii("Customer record: %s (verified)" % value)
    assert value not in out
    assert counts == {kind: 1}
    assert out.startswith("Customer record: [REDACTED:%s" % kind)


def test_card_keeps_last_four_for_support_agents():
    out, _ = redact_pii("card 4111-1111-1111-1111 on file")
    assert out == "card [REDACTED:card ending 1111] on file"


@pytest.mark.parametrize("text", [
    "Aadhaar-shaped but wrong checksum: " + "%s %s %s" % (BAD_AADHAAR[:4], BAD_AADHAAR[4:8], BAD_AADHAAR[8:]),
    "order ORD-9876543210 shipped",
    "invoice 1234567890123 paid",           # 13 digits, fails Luhn
    "delivered on 2026-11-20",
    "GSTIN 27ABCPE1234F1Z5",                 # contains a PAN, but is a different identifier
    "version 0.12.3 and amount 98765.43210",
    "ref 0123456789",
    "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.+",
    "Total: Rs 18,400 for 12 units",
])
def test_lookalikes_are_left_alone(text):
    out, counts = redact_pii(text)
    assert out == text and counts == {}


def test_only_requested_types_are_redacted():
    text = "asha@gmail.com, 9876543210, ABCPE1234F"
    out, counts = redact_pii(text, ["pan"])
    assert out == "asha@gmail.com, 9876543210, [REDACTED:pan]" and counts == {"pan": 1}


def test_redaction_stays_linear_on_hostile_input():
    import time
    for hostile in ("1 " * 30000, "1-" * 30000, "+1 " * 30000, "(1) " * 20000, "9" * 60000):
        started = time.perf_counter()
        redact_pii(hostile)
        assert (time.perf_counter() - started) * 1000 < 500


# ------------------------------------------------------------------ firewall

RECORD = "Asha Rao, asha@gmail.com, +91 98765 43210, PAN ABCPE1234F, Aadhaar %s" % AADHAAR_SPACED


def test_tool_output_is_redacted_and_logged_without_values():
    fw = Firewall()
    d, out = fw.inspect_output("lookup_customer", RECORD, ctx=fw.session("s"))
    assert d.allowed  # the call already ran; nothing blocks
    for value in ("asha@gmail.com", "98765 43210", "ABCPE1234F", AADHAAR_SPACED):
        assert value not in out
    f = next(f for f in d.findings if f.rule_id == "output.pii_redacted")
    assert f.evidence["pii_counts"] == {"email": 1, "phone": 1, "pan": 1, "aadhaar": 1}
    log = json.dumps(fw.audit.records())
    for value in ("asha@gmail.com", "ABCPE1234F", AADHAAR_SPACED):
        assert value not in log


def test_tool_may_be_allowed_contact_details():
    policy = Policy(tools={"lookup_customer": ToolPolicy("lookup_customer",
                                                         output_pii_allowed=["email", "phone"])})
    fw = Firewall(policy=policy)
    _, out = fw.inspect_output("lookup_customer", RECORD, ctx=fw.session("s"))
    assert "asha@gmail.com" in out and "+91 98765 43210" in out
    assert "ABCPE1234F" not in out and AADHAAR_SPACED not in out
    # Another tool still gets everything redacted.
    _, other = fw.inspect_output("web_search", RECORD, ctx=fw.session("s"))
    assert "asha@gmail.com" not in other


def test_redaction_can_be_turned_off_but_secrets_still_go():
    fw = Firewall(policy=Policy(output_pii_redaction=[]))
    _, out = fw.inspect_output("t", RECORD + " key AKIAIOSFODNN7EXAMPLE", ctx=fw.session("s"))
    assert "asha@gmail.com" in out and "AKIAIOSFODNN7EXAMPLE" not in out


def test_execute_returns_redacted_result():
    fw = Firewall()
    out = fw.execute("lookup_customer", lambda: RECORD, {}, session_id="s")
    assert "ABCPE1234F" not in out and "[REDACTED:pan]" in out


def test_policy_round_trip_and_validation():
    p = Policy.from_dict({"output_pii_redaction": ["aadhaar", "pan"],
                          "tools": {"crm": {"output_pii_allowed": ["email"]}}})
    assert p.output_pii_redaction == ["aadhaar", "pan"]
    assert p.tools["crm"].output_pii_allowed == ["email"]
    again = Policy.from_dict(p.to_dict())
    assert again.to_dict() == p.to_dict()
    assert Policy.from_dict({"output_pii_redaction": []}).output_pii_redaction == []
    assert set(Policy.from_dict({}).output_pii_redaction) == {"email", "phone", "aadhaar", "pan", "card", "ssn"}
    with pytest.raises(ValueError):
        Policy(output_pii_redaction=["passport"])
    with pytest.raises(ValueError):
        ToolPolicy("x", output_pii_allowed=["dob"])


# ------------------------------------------------------------------ gateway

def test_http_output_endpoint_redacts_pii():
    c = TestClient(create_app())
    r = c.post("/v1/inspect/output", json={"tool": "lookup_customer", "output": RECORD}).json()
    assert r["redacted"] is True and "ABCPE1234F" not in r["output"]
    assert any(f["rule_id"] == "output.pii_redacted" for f in r["decision"]["findings"])


def test_chat_proxy_redacts_tool_messages_before_the_model_sees_them(monkeypatch):
    import httpx

    sent = {}

    class FakeResponse:
        status_code = 200
        headers = {}
        content = b"{}"

        def json(self):
            return {"choices": [{"message": {"role": "assistant", "content": "ok"}}]}

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None, headers=None):
            sent["body"] = json
            return FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    c = TestClient(create_app(upstream_url="http://upstream.invalid"))
    body = {"model": "m", "messages": [
        {"role": "user", "content": "Find Asha's record"},
        {"role": "tool", "tool_call_id": "1", "content": RECORD},
        {"role": "user", "content": "Summarise it"},
    ]}
    r = c.post("/v1/chat/completions", json=body)
    assert r.status_code == 200
    forwarded = sent["body"]["messages"][1]["content"]
    assert "ABCPE1234F" not in forwarded and "asha@gmail.com" not in forwarded
    assert "[REDACTED:aadhaar]" in forwarded
