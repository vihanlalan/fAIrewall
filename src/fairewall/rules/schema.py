"""Authorization and argument-shape guard.

Answers three questions no LLM should be trusted to answer about itself:
does this tool exist in policy, may this principal invoke it, and are the
arguments the shape the tool actually accepts?

Argument allowlisting is the underrated one. A compromised agent rarely invents
a new tool -- it smuggles an extra parameter into a legitimate one.
"""

from __future__ import annotations

import re
from typing import List, Optional

from ..policy import Policy, Rule
from ..types import Action, Context, Finding, Severity, ToolCall


class SchemaRule(Rule):
    id = "schema"

    def evaluate(self, call: ToolCall, ctx: Context, policy: Policy) -> List[Finding]:
        findings: List[Finding] = []
        tool_policy = policy.tool(call.tool)

        if tool_policy is None:
            if policy.default_deny:
                findings.append(
                    Finding(
                        rule_id="schema.unknown_tool",
                        action=Action.BLOCK,
                        severity=Severity.HIGH,
                        message=(
                            "Tool %s is not in the policy allowlist and default_deny "
                            "is enabled." % call.tool
                        ),
                        evidence={"tool": call.tool},
                    )
                )
            return findings

        if tool_policy.allowed_roles:
            if not any(ctx.principal.has_role(r) for r in tool_policy.allowed_roles):
                findings.append(
                    Finding(
                        rule_id="schema.role_denied",
                        action=Action.BLOCK,
                        severity=Severity.CRITICAL,
                        message=(
                            "Principal %s lacks any of the roles required for %s."
                            % (ctx.principal.id, call.tool)
                        ),
                        evidence={
                            "principal": ctx.principal.id,
                            "principal_roles": list(ctx.principal.roles),
                            "required_any_of": list(tool_policy.allowed_roles),
                        },
                    )
                )

        missing = [a for a in tool_policy.required_args if a not in call.arguments]
        if missing:
            findings.append(
                Finding(
                    rule_id="schema.missing_arguments",
                    action=Action.BLOCK,
                    severity=Severity.MEDIUM,
                    message="Call to %s omits required arguments: %s"
                            % (call.tool, ", ".join(sorted(missing))),
                    evidence={"tool": call.tool, "missing": sorted(missing)},
                )
            )

        if tool_policy.allowed_args:
            permitted = set(tool_policy.allowed_args) | set(tool_policy.required_args)
            extra = sorted(set(call.arguments) - permitted)
            if extra:
                findings.append(
                    Finding(
                        rule_id="schema.unexpected_arguments",
                        action=Action.BLOCK,
                        severity=Severity.HIGH,
                        message=(
                            "Call to %s carries arguments outside its declared schema: %s"
                            % (call.tool, ", ".join(extra))
                        ),
                        evidence={"tool": call.tool, "unexpected": extra},
                    )
                )

        for arg_name, pattern in tool_policy.arg_patterns.items():
            if arg_name not in call.arguments:
                continue
            value = call.arguments[arg_name]
            if not isinstance(value, str) or not re.fullmatch(pattern, value):
                findings.append(
                    Finding(
                        rule_id="schema.pattern_mismatch",
                        action=Action.BLOCK,
                        severity=Severity.HIGH,
                        message=(
                            "Argument %s of %s does not match its required format."
                            % (arg_name, call.tool)
                        ),
                        evidence={
                            "argument": arg_name,
                            "pattern": pattern,
                            "value_preview": str(value)[:80],
                        },
                    )
                )

        if tool_policy.require_human_approval:
            findings.append(
                Finding(
                    rule_id="schema.human_approval_required",
                    action=Action.BLOCK,
                    severity=Severity.MEDIUM,
                    message=(
                        "Tool %s requires human approval; the call has been held for "
                        "review rather than executed." % call.tool
                    ),
                    evidence={"tool": call.tool, "arguments": _preview(call.arguments)},
                )
            )
        return findings


def _preview(arguments, cap: int = 200):
    out = {}
    for key, value in arguments.items():
        text = str(value)
        out[key] = text if len(text) <= cap else text[:cap] + "..."
    return out
