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
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import urlparse

from ..policy import PII_TYPES, Policy, Rule
from ..types import Action, Context, Finding, Severity, ToolCall
from .injection import MAX_SCAN_BYTES, is_oversize

_URL = re.compile(r"https?://([^/\s\"'<>)\]]+)", re.IGNORECASE)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24})")

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

# Candidate card pattern: 13-19 digits optionally separated by spaces or hyphens.
# A separate Luhn check prunes tracking numbers / order IDs / phone numbers that
# share the same digit-count but fail the checksum.
_CARD_CANDIDATE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")


def redact_secrets(text: str) -> Tuple[str, List[str]]:
    """Replace every credential-shaped string with ``[REDACTED:<type>]``.

    Returns the redacted text and the secret types found. Used on tool *output*,
    so a key a tool happens to return never reaches the model's context.
    """
    found: List[str] = []
    for name, pattern, _severity in _SECRETS:
        text, n = pattern.subn("[REDACTED:%s]" % name, text)
        if n:
            found.append(name)
    return text, found


# --------------------------------------------------------------- single PII items
#
# Bulk PII (below) catches a breach in progress. These catch the single record:
# one customer's Aadhaar number in a CRM lookup is enough to be a DPDP Act
# incident if it lands in a third-party model's context or logs.

# Aadhaar: 12 digits, first digit 2-9, often grouped 4-4-4. The last digit is a
# Verhoeff check digit, which rules out ~90% of random 12-digit IDs.
_AADHAAR = re.compile(r"(?<![\w-])[2-9]\d{3}([ -]?)\d{4}\1\d{4}(?![\w-])")
# PAN: 5 letters, 4 digits, 1 letter. The 4th letter is the holder type
# (P person, C company, H HUF, F firm, A AOP, T trust, B BOI, L local body,
# J juridical person, G government).
_PAN = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]{3}[PCHFATBLJGpchfatbljg][A-Za-z]\d{4}[A-Za-z](?![A-Za-z0-9])")
_SSN = re.compile(r"(?<![\w-])\d{3}-\d{2}-\d{4}(?![\w-])")
# Indian mobile: optional +91 / 0091 / 0 prefix, then 10 digits starting 6-9,
# optionally split 5-5. Not preceded by a letter, digit, # or - so order
# numbers such as ORD-9876543210 are left alone.
_PHONE_IN = re.compile(r"(?<![\w+#/-])(?:(?:\+|00)91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?![\w-])")
# Indian landline with STD code: 0 + 2-4 digit code + local number, e.g. 022-2345-6789.
_PHONE_IN_LANDLINE = re.compile(r"(?<![\w+#/-])0\d{2,4}[\s-]\d{3,4}[\s-]?\d{4}(?![\w-])")
# International numbers written with a leading +, e.g. +1 415 555 0100.
_PHONE_INTL = re.compile(r"(?<![\w+])\+[1-9][\d\s().-]{7,18}\d(?![\w-])")
# North American numbers written with separators, e.g. (415) 555-0100.
_PHONE_NANP = re.compile(r"(?<![\w-])(?:\(\d{3}\)\s?|\d{3}[\s.-])\d{3}[\s.-]\d{4}(?![\w-])")

# Every numeric identifier above (phone, card, Aadhaar, SSN) has at least nine
# digits with at most two separator characters between neighbours. Text with no
# such run skips all of those patterns: one cheap pass instead of seven.
_NUMERIC_ID_HINT = re.compile(r"\d(?:[\s().+-]{0,2}\d){8}")

# Verhoeff tables (dihedral group D5), used by UIDAI for the Aadhaar check digit.
_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6), (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8), (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2), (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4), (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2), (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0), (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5), (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def verhoeff_valid(number: str) -> bool:
    """True if the digit string carries a valid Verhoeff check digit."""
    check = 0
    for i, ch in enumerate(reversed(number)):
        check = _VERHOEFF_D[check][_VERHOEFF_P[i % 8][int(ch)]]
    return check == 0


def _digits(text: str) -> str:
    return "".join(c for c in text if c.isdigit())


def redact_pii(text: str, types: Iterable[str] = PII_TYPES) -> Tuple[str, Dict[str, int]]:
    """Replace each personal identifier of the given *types* with a placeholder.

    Returns the redacted text and a count per type (never the values, so the
    result is safe to log). Cards keep their last four digits, which is what a
    support agent needs and what PCI DSS allows to be shown.

    Order matters: emails first (they contain digits), then the checksummed
    numbers (Aadhaar, cards), then the looser phone shapes last, so a phone
    pattern never eats part of an Aadhaar or card number.
    """
    wanted = set(types)
    counts: Dict[str, int] = {}

    def bump(kind: str) -> None:
        counts[kind] = counts.get(kind, 0) + 1

    numeric = bool(wanted & {"phone", "aadhaar", "card", "ssn"}) and bool(
        _NUMERIC_ID_HINT.search(text))

    if "email" in wanted and "@" in text:
        def _email(_m: "re.Match[str]") -> str:
            bump("email")
            return "[REDACTED:email]"
        text = _EMAIL.sub(_email, text)

    if "aadhaar" in wanted and numeric:
        def _aadhaar(m: "re.Match[str]") -> str:
            if not verhoeff_valid(_digits(m.group(0))):
                return m.group(0)
            bump("aadhaar")
            return "[REDACTED:aadhaar]"
        text = _AADHAAR.sub(_aadhaar, text)

    if "card" in wanted and numeric:
        def _card(m: "re.Match[str]") -> str:
            digits = _digits(m.group(0))
            if not _luhn_valid(digits):
                return m.group(0)
            bump("card")
            return "[REDACTED:card ending %s]" % digits[-4:]
        text = _CARD_CANDIDATE.sub(_card, text)

    if "pan" in wanted:
        def _pan(_m: "re.Match[str]") -> str:
            bump("pan")
            return "[REDACTED:pan]"
        text = _PAN.sub(_pan, text)

    if "ssn" in wanted and numeric:
        def _ssn(_m: "re.Match[str]") -> str:
            bump("ssn")
            return "[REDACTED:ssn]"
        text = _SSN.sub(_ssn, text)

    if "phone" in wanted and numeric:
        def _phone(m: "re.Match[str]") -> str:
            n = len(_digits(m.group(0)))
            if not 10 <= n <= 15:
                return m.group(0)
            bump("phone")
            return "[REDACTED:phone]"
        for pattern in (_PHONE_IN, _PHONE_IN_LANDLINE, _PHONE_INTL, _PHONE_NANP):
            if pattern is _PHONE_INTL and "+" not in text:
                continue
            text = pattern.sub(_phone, text)

    return text, counts


def _luhn_valid(number: str) -> bool:
    """Return True if *number* (digits only) satisfies the Luhn checksum.

    The Luhn algorithm is the standard checksum used on all major payment card
    networks (Visa, Mastercard, Amex, Discover, etc.).  Strings that merely
    happen to be 13-19 digits long but are not payment cards (order IDs,
    tracking numbers, phone numbers) fail this check and produce no finding.
    """
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# Bulk-PII shapes. One is a support ticket; forty in one payload is a breach.
_PII = [
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), 3),
    # credit_card uses the dedicated candidate regex + _luhn_valid() -- see _check_bulk_pii
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
            if is_oversize(text):
                findings.append(
                    Finding(
                        rule_id="egress.oversize_argument",
                        action=Action.BLOCK,
                        severity=Severity.HIGH,
                        message="Argument %s exceeds the %d-byte scan limit and was not "
                                "scanned." % (path or "<root>", MAX_SCAN_BYTES),
                        evidence={"argument": path, "length": len(text)},
                    )
                )
                continue
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
            # Count whole matches. findall() would return only the capture group,
            # so the email pattern counted distinct *domains*: a dump of 1,000
            # gmail.com addresses scored 1 and never tripped the threshold.
            hits = len({m.group(0).lower() for m in pattern.finditer(text)})
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

        # Credit card detection: candidate digit strings validated against the Luhn
        # checksum to eliminate false positives from order IDs, tracking numbers, and
        # phone numbers of similar length.
        card_threshold = 3
        luhn_hits: set = set()
        for match in _CARD_CANDIDATE.finditer(text):
            candidate = match.group(0)
            digits_only = candidate.replace(" ", "").replace("-", "")
            if _luhn_valid(digits_only):
                luhn_hits.add(digits_only)
        if len(luhn_hits) >= card_threshold:
            findings.append(
                Finding(
                    rule_id="egress.bulk_pii",
                    action=Action.BLOCK,
                    severity=Severity.HIGH,
                    message=(
                        "Argument %s contains %d distinct credit_card values (Luhn-validated), "
                        "consistent with bulk data extraction rather than a single-record operation."
                        % (path or "<root>", len(luhn_hits))
                    ),
                    evidence={"argument": path, "pii_type": "credit_card",
                              "distinct_count": len(luhn_hits), "threshold": card_threshold},
                )
            )
        return findings

