import json
import pytest
from fairewall.policy import Policy, ToolPolicy


def test_policy_defaults():
    p = Policy()
    assert p.version == "1"
    assert p.default_deny is False
    assert p.max_spend_per_transaction == 500.0
    assert p.max_spend_per_session == 2000.0
    assert p.max_calls_per_minute == 60
    assert "amount" in p.spend_arg_names
    assert len(p.fingerprint()) == 16


def test_policy_fingerprint_stability():
    p1 = Policy(max_spend_per_transaction=100.0)
    p2 = Policy(max_spend_per_transaction=100.0)
    p3 = Policy(max_spend_per_transaction=200.0)

    assert p1.fingerprint() == p2.fingerprint()
    assert p1.fingerprint() != p3.fingerprint()


def test_policy_serialization(tmp_path):
    tp = ToolPolicy(
        name="transfer_funds",
        allowed_roles=["finance"],
        required_args=["amount", "to_account"],
        allowed_args=["amount", "to_account", "memo"],
        max_values={"amount": 1000.0},
        arg_patterns={"to_account": r"^acc_\d+$"},
        rate_limit_per_minute=5,
        forbid_when_tainted=True,
        require_human_approval=True,
    )
    policy = Policy(
        version="2.0",
        default_deny=True,
        tools={"transfer_funds": tp},
    )

    d = policy.to_dict()
    restored = Policy.from_dict(d)
    assert restored.version == "2.0"
    assert restored.default_deny is True
    tool = restored.tool("transfer_funds")
    assert tool is not None
    assert tool.allowed_roles == ["finance"]
    assert tool.forbid_when_tainted is True
    assert tool.require_human_approval is True
    assert tool.max_values["amount"] == 1000.0


def test_policy_unknown_keys():
    bad_dict = {"unknown_feature": True, "version": "1"}
    with pytest.raises(ValueError, match="Unknown policy keys"):
        Policy.from_dict(bad_dict)


def test_policy_from_file(tmp_path):
    policy_file = str(tmp_path / "custom_policy.json")
    with open(policy_file, "w", encoding="utf-8") as f:
        json.dump({
            "version": "test",
            "default_deny": True,
            "max_spend_per_transaction": 750.0,
            "tools": {
                "search": {
                    "required_args": ["q"],
                }
            }
        }, f)

    p = Policy.from_file(policy_file)
    assert p.version == "test"
    assert p.default_deny is True
    assert p.max_spend_per_transaction == 750.0
    assert p.tool("search").required_args == ["q"]
