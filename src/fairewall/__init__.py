"""fAIrewall -- a deterministic security firewall for autonomous AI agents.

Two enforcement points, one audit trail:

    from fairewall import Firewall, Policy, ToolPolicy, Trust

    fw = Firewall(Policy(
        default_deny=True,
        max_spend_per_transaction=500.0,
        tools={"process_refund": ToolPolicy(
            "process_refund",
            required_args=["amount", "order_id"],
            forbid_when_tainted=True,
        )},
    ))

    @fw.guard()
    def process_refund(amount: float, order_id: str) -> str:
        return "refunded"

    process_refund(amount=120.0, order_id="ord_1", _session_id="s1")
"""

from .audit import AuditLog, ChainVerification, verify_chain, verify_file
from .detectors import Detector, DetectorResult, HeuristicDetector, OnnxDetector
from .firewall import Firewall, redact
from .policy import Policy, Rule, ToolPolicy
from .rules import default_rules
from .types import (
    Action,
    Context,
    Decision,
    Finding,
    FirewallBlock,
    Principal,
    Severity,
    ToolCall,
    Trust,
)

__version__ = "0.1.0"

__all__ = [
    "Firewall",
    "Policy",
    "ToolPolicy",
    "Rule",
    "Detector",
    "DetectorResult",
    "HeuristicDetector",
    "OnnxDetector",
    "AuditLog",
    "ChainVerification",
    "verify_chain",
    "verify_file",
    "default_rules",
    "redact",
    "Action",
    "Severity",
    "Trust",
    "Context",
    "Principal",
    "ToolCall",
    "Finding",
    "Decision",
    "FirewallBlock",
    "__version__",
]
