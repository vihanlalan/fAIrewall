"""Egress guard: where data goes, and what is riding along inside it.

Two distinct exfiltration paths, both of which look like ordinary traffic to a
network firewall because they *are* ordinary traffic -- an authorized agent
using an authorized tool with an authorized key:

  1. A destination the enterprise never approved (attacker-controlled domain).
  2. An approved destination carrying material that must never leave (API keys,
     private keys, bulk PII).
"""

from __future__ import annotations

import re
from typing import Any, Iterable, List, Tuple
from urllib.parse import urlparse

from ..policy import Policy, Rule
from ..types import Action, Context, Finding, Severity, ToolCall

_URL = re.compile(r"https?://([^/\s\"'<>)\]]+)", re.IGNORECASE)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")

# Shapes that are credentials regardless of what they are called.
_SECRETS: List[Tuple[str, re.Pattern, Severity]] = [
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), Severity.CRITICAL),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), Severity.CRITICAL),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), Severity.CRITICAL),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), Severity.CRITICAL),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), Severity.CRITICAL),
    ("stripe_key", re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{20,}\b"), Severity.CRITICAL),
    ("google_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), Severity.CRITICAL),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
     Severity.CRITICAL),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
     Severity.HIGH),
    ("bearer_header", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{20,}"), Severity.HIGH),
]

# Bulk-PII shapes. One is a support ticket; forty in one payload is a breach.
_PII = [
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), 3),
    ("credit_card", re.compile(r"\b(?:\d[ -]?){13,16}\b"), 3),
    ("email", _EMAIL, 25),
]


def _strings(value: Any, path: str = "") -> Iterable[Tuple[str, str]]:
    """Walk nested arguments, yielding (json-ish path, string) for every string."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, sub in value.items():
            yield from _strings(sub, path + "." + str(key) if path else str(key))
    elif isinstance(value, (list, tuple)):
        for index, sub in enumerate(value):
            yield from _strings(sub, "%s[%d]" % (path, index))


def _registrable(host: str) -> str:
    host = host.lower().split("@")[-1].split(":")[0].strip(".")
    return host


def _domain_allowed(host: str, allowed: List[str]) -> bool:
    host = _registrable(host)
    for entry in allowed:
        entry = _registrable(entry)
        if host == entry or host.endswith("." + entry):
            return True
    return False


class EgressRule(Rule):
    id = "egress"

    def evaluate(self, call: ToolCall, ctx: Context, policy: Policy) -> List[Finding]:
        findings: List[Finding] = []
        for path, text in _strings(call.arguments):
            findings.extend(self._check_destinations(path, text, policy))
            findings.extend(self._check_secrets(path, text))
            findings.extend(self._check_bulk_pii(path, text))
        return findings

    def _check_destinations(self, path: str, text: str, policy: Policy) -> List[Finding]:
        if not policy.allowed_egress_domains:
            return []
        findings = []
        hosts = set()
        for match in _URL.finditer(text):
            parsed = urlparse("http://" + match.group(1))
            if parsed.hostname:
                hosts.add(parsed.hostname)
        for match in _EMAIL.finditer(text):
            hosts.add(match.group(1))
        for host in sorted(hosts):
            if not _domain_allowed(host, policy.allowed_egress_domains):
                findings.append(
                    Finding(
                        rule_id="egress.unapproved_destination",
                        action=Action.BLOCK,
                        severity=Severity.HIGH,
                        message=(
                            "Argument %s references %s, which is not an approved egress "
                            "destination." % (path or "<root>", host)
                        ),
                        evidence={"argument": path, "host": host,
                                  "allowed": list(policy.allowed_egress_domains)},
                    )
                )
        return findings

    def _check_secrets(self, path: str, text: str) -> List[Finding]:
        findings = []
        for name, pattern, severity in _SECRETS:
            if pattern.search(text):
                findings.append(
                    Finding(
                        rule_id="egress.secret_material",
                        action=Action.BLOCK,
                        severity=severity,
                        message=(
                            "Argument %s contains what appears to be a %s. Credentials "
                            "must never transit a tool call."
                            % (path or "<root>", name.replace("_", " "))
                        ),
                        # Deliberately no excerpt: the audit log must not become
                        # the second place the secret leaked to.
                        evidence={"argument": path, "secret_type": name},
                    )
                )
        return findings

    def _check_bulk_pii(self, path: str, text: str) -> List[Finding]:
        findings = []
        for name, pattern, threshold in _PII:
            hits = len(set(pattern.findall(text)))
            if hits >= threshold:
                findings.append(
                    Finding(
                        rule_id="egress.bulk_pii",
                        action=Action.BLOCK,
                        severity=Severity.HIGH,
                        message=(
                            "Argument %s contains %d distinct %s values, consistent with "
                            "bulk data extraction rather than a single-record operation."
                            % (path or "<root>", hits, name)
                        ),
                        evidence={"argument": path, "pii_type": name,
                                  "distinct_count": hits, "threshold": threshold},
                    )
                )
        return findings
