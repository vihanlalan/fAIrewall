"""Core value types shared by every layer of the firewall.

Everything here is a plain dataclass with no third-party dependencies so the
enforcement path stays importable inside any customer process.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Action(str, Enum):
    """What the firewall decided to do about a call or a payload."""

    ALLOW = "allow"
    FLAG = "flag"      # let it through, but mark it for review
    BLOCK = "block"    # refuse; the agent gets an error string back


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Ordering used when several rules fire on the same call: the strictest wins.
_ACTION_RANK = {Action.ALLOW: 0, Action.FLAG: 1, Action.BLOCK: 2}
_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Trust(str, Enum):
    """Provenance of a piece of text entering the agent.

    The distinction that matters for indirect prompt injection: text the
    principal typed is a *request*, text the agent scraped is *data*. Only
    TRUSTED content may legitimately contain instructions.
    """

    TRUSTED = "trusted"          # operator/system prompt
    USER = "user"                # the authenticated human in the loop
    UNTRUSTED = "untrusted"      # tool output, web page, PDF, DB row, email


@dataclass
class Principal:
    """Who the agent is acting on behalf of, and what they may authorize."""

    id: str = "anonymous"
    roles: List[str] = field(default_factory=list)
    # Hard per-principal ceiling; None means "fall back to the policy default".
    max_spend: Optional[float] = None

    def has_role(self, role: str) -> bool:
        return role in self.roles


@dataclass
class ToolCall:
    """An action the agent has decided to take, before it happens."""

    tool: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])


@dataclass
class Context:
    """Session-scoped state the rules reason over.

    `session_id` is the rate-limiting and budget key: give each agent run its
    own context so one runaway loop cannot spend another tenant's budget.
    """

    session_id: str = "default"
    principal: Principal = field(default_factory=Principal)
    # Trust levels of content already ingested this session. If any UNTRUSTED
    # content came in, outbound calls are held to a stricter standard.
    tainted: bool = False
    taint_sources: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def taint(self, source: str) -> None:
        self.tainted = True
        if source not in self.taint_sources:
            self.taint_sources.append(source)


@dataclass
class Finding:
    """One rule's verdict on one call."""

    rule_id: str
    action: Action
    severity: Severity
    message: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        return {
            "rule_id": self.rule_id,
            "action": self.action.value,
            "severity": self.severity.value,
            "message": self.message,
            "evidence": self.evidence,
        }


@dataclass
class Decision:
    """The firewall's aggregate answer. Strictest finding wins."""

    action: Action
    findings: List[Finding] = field(default_factory=list)
    call_id: str = ""
    session_id: str = ""
    tool: str = ""
    timestamp: float = field(default_factory=time.time)
    latency_ms: float = 0.0
    # Which inspection tiers ran ("t0" = rules, "t1" = detectors) and why.
    tiers: List[str] = field(default_factory=lambda: ["t0"])
    route: str = ""

    @property
    def allowed(self) -> bool:
        return self.action is not Action.BLOCK

    @property
    def blocked(self) -> bool:
        return self.action is Action.BLOCK

    @property
    def flagged(self) -> bool:
        """True when the decision is FLAG (allowed but marked for review)."""
        return self.action is Action.FLAG

    @property
    def reason(self) -> str:
        """A single line safe to hand back to the agent as a tool error."""
        blocking = [f for f in self.findings if f.action is Action.BLOCK]
        chosen = blocking or self.findings
        if not chosen:
            return "Allowed."
        return "; ".join(f"[{f.rule_id}] {f.message}" for f in chosen)

    @property
    def severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max((f.severity for f in self.findings), key=lambda s: _SEVERITY_RANK[s])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "call_id": self.call_id,
            "session_id": self.session_id,
            "tool": self.tool,
            "action": self.action.value,
            "severity": self.severity.value,
            "timestamp": self.timestamp,
            "latency_ms": round(self.latency_ms, 3),
            "tiers": list(self.tiers),
            "route": self.route,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "action": f.action.value,
                    "severity": f.severity.value,
                    "message": f.message,
                    "evidence": f.evidence,
                }
                for f in self.findings
            ],
        }

    @classmethod
    def from_findings(cls, findings: List[Finding], **kw: Any) -> "Decision":
        action = Action.ALLOW
        for f in findings:
            if _ACTION_RANK[f.action] > _ACTION_RANK[action]:
                action = f.action
        return cls(action=action, findings=list(findings), **kw)


class FirewallBlock(Exception):
    """Raised by enforcement helpers configured to fail closed."""

    def __init__(self, decision: Decision):
        super().__init__(decision.reason)
        self.decision = decision
