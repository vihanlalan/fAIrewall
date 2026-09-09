"""Inbound semantic guard: heuristic detection of prompt-injection payloads.

This is a *screen*, not a proof. Pattern matching cannot catch a determined
paraphrase, which is exactly why the outbound circuit breaker exists and why
`forbid_when_tainted` is the load-bearing control. What this layer buys you is
cheap, deterministic, explainable coverage of the commodity attacks that make
up the overwhelming majority of real traffic -- at microseconds, not a model
call.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Pattern, Tuple

from ..types import Action, Finding, Severity, Trust


@dataclass
class Signature:
    id: str
    pattern: Pattern[str]
    severity: Severity
    description: str


def _sig(id_: str, regex: str, severity: Severity, description: str) -> Signature:
    return Signature(id_, re.compile(regex, re.IGNORECASE | re.DOTALL), severity, description)


# Ordered roughly by how strongly each signal implies an attack rather than a
# coincidence of phrasing.
SIGNATURES: List[Signature] = [
    _sig(
        "instruction_override",
        r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}?"
        r"\b(all\s+)?(previous|prior|above|earlier|initial|original|system|any)\b"
        r"[^.\n]{0,30}?\b(instruction|prompt|rule|direction|command|guideline|constraint)s?\b",
        Severity.CRITICAL,
        "Attempts to void the agent's standing instructions.",
    ),
    _sig(
        "role_reassignment",
        r"\b(you\s+are\s+now|from\s+now\s+on\s+you|act\s+as|pretend\s+to\s+be|"
        r"your\s+new\s+(role|task|goal|objective)\s+is|new\s+persona)\b",
        Severity.HIGH,
        "Attempts to reassign the agent's role or objective.",
    ),
    _sig(
        "system_prompt_spoof",
        r"(^|\n)\s*(\[|<|#{1,3}\s*)?\s*(system|assistant|developer)\s*"
        r"(\]|>|:|\s+(note|message|prompt|instruction|override))",
        Severity.HIGH,
        "Content impersonates a system or developer turn.",
    ),
    _sig(
        "delimiter_injection",
        r"(<\|(im_start|im_end|endoftext|system|eot_id|start_header_id)\|>)|"
        r"(\[/?INST\])|(<<SYS>>)|(###\s*(instruction|system)\s*:)",
        Severity.HIGH,
        "Contains chat-template control tokens used to forge turn boundaries.",
    ),
    _sig(
        "secret_exfiltration",
        r"\b(reveal|print|output|show|repeat|send|forward|email|post|leak|dump|exfiltrat\w*)\b"
        r"[^.\n]{0,60}?\b(system\s+prompt|initial\s+instructions|api[\s_-]?keys?|"
        r"secrets?|credentials?|passwords?|tokens?|env(ironment)?\s+variables?|\.env)\b",
        Severity.CRITICAL,
        "Requests disclosure of prompts, keys, or credentials.",
    ),
    _sig(
        "destructive_action",
        r"\b(delete|drop|truncate|wipe|destroy|purge|rm\s+-rf)\b[^.\n]{0,40}?"
        r"\b(table|database|schema|records?|users?|accounts?|backups?|repo\w*|bucket)\b",
        Severity.CRITICAL,
        "Instructs a destructive data operation.",
    ),
    _sig(
        "privilege_escalation",
        r"\b(elevate|escalate|promote|grant|upgrade|set)\b[^.\n]{0,40}?"
        r"\b(to\s+)?(admin(istrator)?|root|superuser|sudo|owner|full\s+access|all\s+permissions)\b",
        Severity.CRITICAL,
        "Requests a privilege change.",
    ),
    _sig(
        "guardrail_bypass",
        r"\b(dan\s+mode|developer\s+mode|jailbreak|unfiltered|no\s+restrictions|"
        r"without\s+(any\s+)?(restrictions?|limits?|filters?|censorship)|"
        r"do\s+anything\s+now)\b",
        Severity.HIGH,
        "Known jailbreak framing.",
    ),
    _sig(
        "confidentiality_lure",
        r"\b(do\s+not|don'?t|never)\b[^.\n]{0,30}?\b(tell|inform|mention|notify|show|alert)\b"
        r"[^.\n]{0,30}?\b(the\s+)?(user|human|operator|anyone|owner)\b",
        Severity.HIGH,
        "Instructs the agent to conceal its actions from the principal.",
    ),
    _sig(
        "urgency_authority",
        r"\b(this\s+is\s+(an?\s+)?(urgent|emergency|official)|authorized\s+by\s+"
        r"(the\s+)?(admin|ceo|security|management)|approved\s+by\s+management)\b",
        Severity.MEDIUM,
        "Social-engineering pressure framing.",
    ),
    _sig(
        "encoded_payload",
        r"\b(base64|rot13|hex|decode|atob)\b[^.\n]{0,40}?\b(decode|then\s+(execute|run|follow))\b",
        Severity.MEDIUM,
        "Instructs decoding of an obfuscated payload.",
    ),
]

# Zero-width and bidi characters used to hide instructions from human reviewers
# while leaving them fully visible to the tokenizer.
_INVISIBLE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\U000e0000-\U000e007f]")


def _normalize(text: str) -> Tuple[str, bool]:
    """Strip invisible characters, reporting whether any were present."""
    cleaned = _INVISIBLE.sub("", text)
    return cleaned, cleaned != text


def scan_text(
    text: str,
    trust: Trust = Trust.USER,
    location: str = "input",
) -> List[Finding]:
    """Return findings for one string.

    Trust changes the *verdict*, not the detection: an instruction-shaped
    sentence typed by an authenticated user is often legitimate ("ignore my
    previous message"), while the identical sentence arriving inside a scraped
    invoice is an attack by construction.
    """
    if not text:
        return []

    normalized, had_invisible = _normalize(text)
    findings: List[Finding] = []

    if had_invisible:
        findings.append(
            Finding(
                rule_id="injection.invisible_characters",
                action=Action.BLOCK if trust is Trust.UNTRUSTED else Action.FLAG,
                severity=Severity.HIGH,
                message="Text contains zero-width or bidirectional control characters "
                        "that hide content from human review.",
                evidence={"location": location},
            )
        )

    for sig in SIGNATURES:
        match = sig.pattern.search(normalized)
        if not match:
            continue
        # Untrusted data must never carry instructions; user text that merely
        # looks instruction-shaped is flagged for the outbound layer to weigh.
        if trust is Trust.UNTRUSTED:
            action = Action.BLOCK
        elif sig.severity in (Severity.CRITICAL, Severity.HIGH):
            action = Action.BLOCK
        else:
            action = Action.FLAG
        findings.append(
            Finding(
                rule_id="injection." + sig.id,
                action=action,
                severity=sig.severity,
                message=sig.description + " (trust=" + trust.value + ")",
                evidence={
                    "location": location,
                    "match": _excerpt(normalized, match.start(), match.end()),
                },
            )
        )
    return findings


def _excerpt(text: str, start: int, end: int, pad: int = 24, cap: int = 160) -> str:
    """A short, log-safe window around the match."""
    lo, hi = max(0, start - pad), min(len(text), end + pad)
    snippet = text[lo:hi].replace("\n", " ").strip()
    if len(snippet) > cap:
        snippet = snippet[:cap] + "..."
    return ("..." if lo > 0 else "") + snippet + ("..." if hi < len(text) else "")


def highest_severity(findings: List[Finding]) -> Optional[Severity]:
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    present = [f.severity for f in findings]
    return max(present, key=order.index) if present else None
