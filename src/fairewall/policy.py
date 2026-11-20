"""Policy: the declarative configuration a customer writes, and the Rule ABC.

A Policy is deliberately boring data. It is loaded once, versioned, and hashed
into the audit log so an auditor can prove *which* ruleset was in force when a
given agent action was allowed.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .types import Context, Finding, ToolCall


_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NAME_SEPARATORS = re.compile(r"[\s\-.]+")


def normalize_tool_name(name: str) -> str:
    """Fold case, separators and camelCase so Send_Email == send-email == sendEmail."""
    spaced = _CAMEL_BOUNDARY.sub("_", name or "")
    return _NAME_SEPARATORS.sub("_", spaced).strip("_").lower()


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
    # "low" or "high". Decides whether the detector tier inspects every call to
    # this tool. None = inferred from the other constraints (see Policy.risk_tier).
    risk_tier: Optional[str] = None
    # Personal-data types this tool may return unredacted, e.g. ["email", "phone"]
    # for a customer lookup whose result the agent needs in order to reply.
    output_pii_allowed: List[str] = field(default_factory=list)

    review_above: Optional[float] = None

    def __post_init__(self) -> None:
        if self.review_above is not None and (not math.isfinite(self.review_above) or self.review_above < 0):
            raise ValueError("review_above must be a finite nonnegative amount")
        if self.risk_tier is not None and self.risk_tier not in RISK_TIERS:
            raise ValueError(
                f"Tool {self.name!r}: risk_tier must be one of {RISK_TIERS} or None, "
                f"got {self.risk_tier!r}"
            )
        _check_pii_types(self.output_pii_allowed, f"Tool {self.name!r}: output_pii_allowed")


RISK_TIERS = ("low", "high")

# Personal-data types fAIrewall can find and redact in tool output.
PII_TYPES = ("email", "phone", "aadhaar", "pan", "card", "ssn")


def _check_pii_types(values: List[str], where: str) -> None:
    bad = [v for v in values or [] if v not in PII_TYPES]
    if bad:
        raise ValueError(f"{where}: unknown PII types {bad}; choose from {list(PII_TYPES)}")


DEFAULT_SPEND_SCALES: Dict[str, float] = {
    "amount_cents": 0.01, "amount_paise": 0.01,
    "total_cents": 0.01, "total_paise": 0.01,
}


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
    # Spend fields in minor units, with the factor that converts them to major
    # units. Without this, {"amount_cents": 90000} was never capped at all.
    spend_arg_scales: Dict[str, float] = field(default_factory=lambda: dict(DEFAULT_SPEND_SCALES))
    # Hosts an agent may send data to. Empty = no egress restriction.
    allowed_egress_domains: List[str] = field(default_factory=list)
    # Detectors that FLAG rather than BLOCK, for shadow-mode rollout.
    flag_only_rules: List[str] = field(default_factory=list)
    tools: Dict[str, ToolPolicy] = field(default_factory=dict)
    # Risk tier for tools with no ToolPolicy entry. "high" fails safe.
    unknown_tool_risk: str = "high"
    # Detector scores at or above these thresholds FLAG / BLOCK. Part of the
    # fingerprinted policy so an auditor can see how sensitive the ML tier was.
    detector_flag_threshold: float = 0.5
    detector_block_threshold: float = 0.85
    # Personal-data types redacted from tool output before the agent (and the
    # model provider behind it) sees them. [] turns single-item redaction off.
    output_pii_redaction: List[str] = field(default_factory=lambda: list(PII_TYPES))

    def __post_init__(self) -> None:
        _check_pii_types(self.output_pii_redaction, "output_pii_redaction")
        if self.unknown_tool_risk not in RISK_TIERS:
            raise ValueError(
                f"unknown_tool_risk must be one of {RISK_TIERS}, got {self.unknown_tool_risk!r}"
            )
        for name, scale in (self.spend_arg_scales or {}).items():
            if not isinstance(scale, (int, float)) or scale <= 0:
                raise ValueError(f"spend_arg_scales[{name!r}] must be a positive number, got {scale!r}")
        if not 0.0 <= self.detector_flag_threshold <= self.detector_block_threshold <= 1.0:
            raise ValueError(
                "Detector thresholds must satisfy 0 <= flag_threshold <= block_threshold <= 1, "
                f"got flag={self.detector_flag_threshold}, block={self.detector_block_threshold}"
            )

    def tool(self, name: str) -> Optional[ToolPolicy]:
        exact = self.tools.get(name)
        if exact is not None:
            return exact
        wanted = normalize_tool_name(name)
        for key, tp in self.tools.items():
            if normalize_tool_name(key) == wanted:
                return tp
        return None

    def canonical_tool(self, name: str) -> str:
        """The policy's own spelling when one matches, else the normalized name.

        Rules key rate limits and budgets on the tool name, so every spelling of
        one tool must collapse to one key or renaming becomes a bypass.
        """
        if name in self.tools:
            return name
        wanted = normalize_tool_name(name)
        for key in self.tools:
            if normalize_tool_name(key) == wanted:
                return key
        return wanted or name

    def risk_tier(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> str:
        """Resolve a tool's risk tier from declared policy, never from prompt text.

        Inference treats any tool that moves money, needs a role, needs a human,
        or is fenced off from tainted sessions as high risk.
        """
        tp = self.tool(name)
        if tp is None:
            return self.unknown_tool_risk
        if tp.risk_tier is not None:
            return tp.risk_tier
        if (tp.forbid_when_tainted or tp.require_human_approval
                or tp.max_values or tp.allowed_roles):
            return "high"
        if arguments and any(a in arguments for a in
                             list(self.spend_arg_names) + list(self.spend_arg_scales or {})):
            return "high"
        return "low"

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
            "spend_arg_scales": dict(sorted((self.spend_arg_scales or {}).items())),
            "allowed_egress_domains": self.allowed_egress_domains,
            "flag_only_rules": self.flag_only_rules,
            "unknown_tool_risk": self.unknown_tool_risk,
            "detector_flag_threshold": self.detector_flag_threshold,
            "detector_block_threshold": self.detector_block_threshold,
            "output_pii_redaction": list(self.output_pii_redaction),
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
                    **({"review_above": t.review_above} if t.review_above is not None else {}),
                    "produces_untrusted_output": t.produces_untrusted_output,
                    "risk_tier": t.risk_tier,
                    "output_pii_allowed": list(t.output_pii_allowed),
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
                review_above=cfg.get("review_above"),
                produces_untrusted_output=bool(cfg.get("produces_untrusted_output", False)),
                risk_tier=cfg.get("risk_tier"),
                output_pii_allowed=list(cfg.get("output_pii_allowed") or []),
            )
            for name, cfg in raw_tools.items()
        }
        known = {
            "version", "default_deny", "max_spend_per_transaction",
            "max_spend_per_session", "max_calls_per_minute", "spend_arg_names",
            "spend_arg_scales", "allowed_egress_domains", "flag_only_rules", "unknown_tool_risk",
            "detector_flag_threshold", "detector_block_threshold", "output_pii_redaction",
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
            spend_arg_scales={str(k): float(v) for k, v in
                              (data.get("spend_arg_scales") or DEFAULT_SPEND_SCALES).items()},
            allowed_egress_domains=data.get("allowed_egress_domains") or [],
            flag_only_rules=data.get("flag_only_rules") or [],
            tools=tools,
            unknown_tool_risk=str(data.get("unknown_tool_risk", "high")),
            detector_flag_threshold=float(data.get("detector_flag_threshold", 0.5)),
            detector_block_threshold=float(data.get("detector_block_threshold", 0.85)),
            # An explicit [] means "redact nothing", so only a missing key gets the default.
            output_pii_redaction=(list(data["output_pii_redaction"] or [])
                                  if "output_pii_redaction" in data else list(PII_TYPES)),
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
