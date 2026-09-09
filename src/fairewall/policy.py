"""Policy: the declarative configuration a customer writes, and the Rule ABC.

A Policy is deliberately boring data. It is loaded once, versioned, and hashed
into the audit log so an auditor can prove *which* ruleset was in force when a
given agent action was allowed.
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .types import Context, Finding, ToolCall


@dataclass
class ToolPolicy:
    """Per-tool constraints. Absence of an entry is governed by `default_deny`."""

    name: str
    # Roles permitted to invoke this tool at all.
    allowed_roles: List[str] = field(default_factory=list)
    # Argument names that must be present.
    required_args: List[str] = field(default_factory=list)
    # Argument names that may be present. Empty list = no restriction.
    allowed_args: List[str] = field(default_factory=list)
    # Numeric ceilings, e.g. {"amount": 500.0}.
    max_values: Dict[str, float] = field(default_factory=dict)
    # Regex each named argument must fully match, e.g. {"currency": "USD|EUR"}.
    arg_patterns: Dict[str, str] = field(default_factory=dict)
    # Calls per minute for this specific tool.
    rate_limit_per_minute: Optional[int] = None
    # If true, this tool may not run in a session that has ingested untrusted
    # content. This is the single most effective control against indirect
    # prompt injection: reading the web and wiring money are separable.
    forbid_when_tainted: bool = False
    # If true, block and surface for a human rather than deciding automatically.
    require_human_approval: bool = False
    # If true, executing this tool marks the session tainted with untrusted content.
    produces_untrusted_output: bool = False


@dataclass
class Policy:
    version: str = "1"
    # Tools not named below are denied outright when this is True.
    default_deny: bool = False
    # Global ceilings, used when a tool has no specific limit.
    max_spend_per_transaction: float = 500.0
    max_spend_per_session: float = 2000.0
    max_calls_per_minute: int = 60
    # Argument names treated as monetary for spend accounting.
    spend_arg_names: List[str] = field(default_factory=lambda: ["amount", "total", "value"])
    # Hosts an agent may send data to. Empty = no egress restriction.
    allowed_egress_domains: List[str] = field(default_factory=list)
    # Detectors that FLAG rather than BLOCK, for shadow-mode rollout.
    flag_only_rules: List[str] = field(default_factory=list)
    tools: Dict[str, ToolPolicy] = field(default_factory=dict)

    def tool(self, name: str) -> Optional[ToolPolicy]:
        return self.tools.get(name)

    def fingerprint(self) -> str:
        """Stable hash of the effective ruleset, recorded on every decision."""
        blob = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "default_deny": self.default_deny,
            "max_spend_per_transaction": self.max_spend_per_transaction,
            "max_spend_per_session": self.max_spend_per_session,
            "max_calls_per_minute": self.max_calls_per_minute,
            "spend_arg_names": self.spend_arg_names,
            "allowed_egress_domains": self.allowed_egress_domains,
            "flag_only_rules": self.flag_only_rules,
            "tools": {
                name: {
                    "allowed_roles": t.allowed_roles,
                    "required_args": t.required_args,
                    "allowed_args": t.allowed_args,
                    "max_values": t.max_values,
                    "arg_patterns": t.arg_patterns,
                    "rate_limit_per_minute": t.rate_limit_per_minute,
                    "forbid_when_tainted": t.forbid_when_tainted,
                    "require_human_approval": t.require_human_approval,
                    "produces_untrusted_output": t.produces_untrusted_output,
                }
                for name, t in sorted(self.tools.items())
            },
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Policy":
        raw_tools = data.get("tools", {}) or {}
        tools = {
            name: ToolPolicy(
                name=name,
                allowed_roles=cfg.get("allowed_roles", []) or [],
                required_args=cfg.get("required_args", []) or [],
                allowed_args=cfg.get("allowed_args", []) or [],
                max_values={k: float(v) for k, v in (cfg.get("max_values") or {}).items()},
                arg_patterns=cfg.get("arg_patterns", {}) or {},
                rate_limit_per_minute=cfg.get("rate_limit_per_minute"),
                forbid_when_tainted=bool(cfg.get("forbid_when_tainted", False)),
                require_human_approval=bool(cfg.get("require_human_approval", False)),
                produces_untrusted_output=bool(cfg.get("produces_untrusted_output", False)),
            )
            for name, cfg in raw_tools.items()
        }
        known = {
            "version", "default_deny", "max_spend_per_transaction",
            "max_spend_per_session", "max_calls_per_minute", "spend_arg_names",
            "allowed_egress_domains", "flag_only_rules",
        }
        unknown = set(data) - known - {"tools"}
        if unknown:
            raise ValueError(f"Unknown policy keys: {sorted(unknown)}")
        return cls(
            version=str(data.get("version", "1")),
            default_deny=bool(data.get("default_deny", False)),
            max_spend_per_transaction=float(data.get("max_spend_per_transaction", 500.0)),
            max_spend_per_session=float(data.get("max_spend_per_session", 2000.0)),
            max_calls_per_minute=int(data.get("max_calls_per_minute", 60)),
            spend_arg_names=data.get("spend_arg_names") or ["amount", "total", "value"],
            allowed_egress_domains=data.get("allowed_egress_domains") or [],
            flag_only_rules=data.get("flag_only_rules") or [],
            tools=tools,
        )

    @classmethod
    def from_file(cls, path: str) -> "Policy":
        """Load from JSON, or YAML when PyYAML is installed."""
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        if path.endswith((".yaml", ".yml")):
            try:
                import yaml  # type: ignore
            except ImportError as exc:  # pragma: no cover - env dependent
                raise ImportError("YAML policies require `pip install fairewall[yaml]`") from exc
            return cls.from_dict(yaml.safe_load(text) or {})
        return cls.from_dict(json.loads(text))


class Rule(ABC):
    """A deterministic check over a single tool call.

    Rules must be pure with respect to the call and may only mutate their own
    state (counters, windows) via `commit`, which the engine calls exactly once
    per *allowed* call. Keeping evaluation and commitment separate is what stops
    a blocked call from consuming budget or a rate-limit slot.
    """

    id: str = "rule"

    @abstractmethod
    def evaluate(self, call: ToolCall, ctx: Context, policy: Policy) -> List[Finding]:
        ...

    def commit(self, call: ToolCall, ctx: Context, policy: Policy) -> None:
        """Record state for a call that was actually permitted. Default: no-op."""

    def reset(self, session_id: Optional[str] = None) -> None:
        """Drop accumulated state, for one session or all of them."""
