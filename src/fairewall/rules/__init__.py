"""Built-in rules. Every rule is deterministic, offline, and independently testable."""

from .egress import EgressRule
from .financial import FinancialRule
from .injection import SIGNATURES, scan_text
from .payload import PayloadRule, TaintRule
from .schema import SchemaRule
from .velocity import VelocityRule

__all__ = [
    "EgressRule",
    "FinancialRule",
    "PayloadRule",
    "SchemaRule",
    "TaintRule",
    "VelocityRule",
    "SIGNATURES",
    "scan_text",
]


def default_rules():
    """The stock ruleset, ordered cheapest-and-most-decisive first."""
    return [SchemaRule(), TaintRule(), FinancialRule(), VelocityRule(), PayloadRule(), EgressRule()]
