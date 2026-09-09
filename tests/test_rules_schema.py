import pytest
from fairewall.policy import Policy, ToolPolicy
from fairewall.rules.schema import SchemaRule
from fairewall.types import Action, Context, Principal, Severity, ToolCall


def test_schema_default_deny():
    rule = SchemaRule()
    call = ToolCall(tool="unregistered_tool", arguments={})
    ctx = Context()

    # Policy with default_deny=False
    p_allow = Policy(default_deny=False)
    findings = rule.evaluate(call, ctx, p_allow)
    assert len(findings) == 0

    # Policy with default_deny=True
    p_deny = Policy(default_deny=True)
    findings = rule.evaluate(call, ctx, p_deny)
    assert len(findings) == 1
    assert findings[0].rule_id == "schema.unknown_tool"
    assert findings[0].action == Action.BLOCK


def test_schema_roles_authorization():
    rule = SchemaRule()
    policy = Policy(
        tools={
            "database_drop": ToolPolicy(
                name="database_drop",
                allowed_roles=["superadmin"],
            )
        }
    )
    call = ToolCall(tool="database_drop", arguments={})

    # Principal without role
    p_user = Principal(id="alice", roles=["analyst"])
    ctx_user = Context(principal=p_user)
    findings = rule.evaluate(call, ctx_user, policy)
    assert len(findings) == 1
    assert findings[0].rule_id == "schema.role_denied"
    assert findings[0].action == Action.BLOCK

    # Principal with required role
    p_admin = Principal(id="bob", roles=["superadmin"])
    ctx_admin = Context(principal=p_admin)
    findings = rule.evaluate(call, ctx_admin, policy)
    assert len(findings) == 0


def test_schema_required_args():
    rule = SchemaRule()
    policy = Policy(
        tools={
            "refund": ToolPolicy(
                name="refund",
                required_args=["amount", "order_id"],
            )
        }
    )

    # Missing required argument
    call_missing = ToolCall(tool="refund", arguments={"amount": 50})
    findings = rule.evaluate(call_missing, Context(), policy)
    assert len(findings) == 1
    assert findings[0].rule_id == "schema.missing_arguments"
    assert findings[0].action == Action.BLOCK


def test_schema_parameter_smuggling():
    rule = SchemaRule()
    policy = Policy(
        tools={
            "refund": ToolPolicy(
                name="refund",
                required_args=["amount"],
                allowed_args=["amount", "order_id"],  # Strict allowlist
            )
        }
    )

    # Smuggled parameter injected
    call_smuggled = ToolCall(tool="refund", arguments={"amount": 50, "admin_override": "true"})
    findings = rule.evaluate(call_smuggled, Context(), policy)
    assert len(findings) == 1
    assert findings[0].rule_id == "schema.unexpected_arguments"
    assert findings[0].action == Action.BLOCK


def test_schema_arg_patterns():
    rule = SchemaRule()
    policy = Policy(
        tools={
            "get_order": ToolPolicy(
                name="get_order",
                arg_patterns={"order_id": r"^ord_[0-9]{4}$"},
            )
        }
    )

    # Non-matching pattern
    call_bad = ToolCall(tool="get_order", arguments={"order_id": "malicious_string; DROP TABLE;"})
    findings = rule.evaluate(call_bad, Context(), policy)
    assert len(findings) == 1
    assert findings[0].rule_id == "schema.pattern_mismatch"
    assert findings[0].action == Action.BLOCK

    # Matching pattern
    call_good = ToolCall(tool="get_order", arguments={"order_id": "ord_1234"})
    findings = rule.evaluate(call_good, Context(), policy)
    assert len(findings) == 0


def test_schema_human_approval():
    rule = SchemaRule()
    policy = Policy(
        tools={
            "delete_account": ToolPolicy(
                name="delete_account",
                require_human_approval=True,
            )
        }
    )
    call = ToolCall(tool="delete_account", arguments={"user_id": "u1"})
    findings = rule.evaluate(call, Context(), policy)
    assert len(findings) == 1
    assert findings[0].rule_id == "schema.human_approval_required"
    assert findings[0].action == Action.BLOCK
