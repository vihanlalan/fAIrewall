"""Payload and taint guards on the outbound path.

PayloadRule re-runs the injection signatures over tool *arguments*. Text that
reached the agent as data and is now being written back into a ticket, a
database row, or a message is how an injection becomes persistent: the next
agent to read that record is the real victim.

TaintRule is the single highest-value control in this codebase, and it is not a
detector at all. It enforces a structural rule: a session that has ingested
untrusted content may not invoke tools marked `forbid_when_tainted`. Reading
the web and moving money are separable capabilities, and separating them holds
even against an injection payload nobody has ever seen before.
"""

from __future__ import annotations

from typing import List

from ..policy import Policy, Rule
from ..types import Action, Context, Finding, Severity, ToolCall, Trust
from .injection import scan_text


class PayloadRule(Rule):
    id = "payload"

    def evaluate(self, call: ToolCall, ctx: Context, policy: Policy) -> List[Finding]:
        findings: List[Finding] = []
        for name, value in call.arguments.items():
            if not isinstance(value, str):
                continue
            # Arguments assembled by an agent that has read untrusted data are
            # themselves untrusted, so they are held to the stricter standard.
            trust = Trust.UNTRUSTED if ctx.tainted else Trust.USER
            for finding in scan_text(value, trust=trust, location="argument:" + name):
                findings.append(
                    Finding(
                        rule_id=finding.rule_id.replace("injection.", "payload."),
                        action=finding.action,
                        severity=finding.severity,
                        message=(
                            "Adversarial payload in argument %s: %s"
                            % (name, finding.message)
                        ),
                        evidence=dict(finding.evidence, argument=name, tool=call.tool),
                    )
                )
        return findings


class TaintRule(Rule):
    id = "taint"

    def evaluate(self, call: ToolCall, ctx: Context, policy: Policy) -> List[Finding]:
        tool_policy = policy.tool(call.tool)
        if not tool_policy or not tool_policy.forbid_when_tainted or not ctx.tainted:
            return []
        return [
            Finding(
                rule_id="taint.untrusted_context",
                action=Action.BLOCK,
                severity=Severity.CRITICAL,
                message=(
                    "Tool %s is forbidden in a session that has ingested untrusted "
                    "content. Sources: %s"
                    % (call.tool, ", ".join(ctx.taint_sources) or "unknown")
                ),
                evidence={"tool": call.tool, "taint_sources": list(ctx.taint_sources)},
            )
        ]
