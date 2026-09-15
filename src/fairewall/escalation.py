"""Router: decides, per call, whether the detector tier runs.

The routing inputs are deliberately things an attacker cannot rephrase away:
the declared risk of the tool being invoked, the session's provenance (taint),
and whether the deterministic rules were decisive or ambiguous. Prompt
keywords are never a routing input -- a keyword list is a map of what to avoid.

Detector findings are appended to rule findings and the strictest wins, so the
ML tier is monotonic: it can escalate ALLOW -> FLAG -> BLOCK, never the reverse.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, List, Sequence

from .detectors import Detector
from .policy import Policy
from .types import Action, Context, Finding, Severity, Trust

MAX_DETECTOR_CHARS = 20_000


@dataclass
class Route:
    escalate: bool
    reason: str
    # High-stakes routes treat a crashing detector as a block, not a pass.
    fail_closed: bool = False


def _decisive(findings: Sequence[Finding]) -> bool:
    return any(f.action is Action.BLOCK for f in findings)


def _ambiguous(findings: Sequence[Finding]) -> bool:
    return any(f.action is Action.FLAG for f in findings)


def route_outbound(risk_tier: str, ctx: Context, t0_findings: Sequence[Finding]) -> Route:
    if _decisive(t0_findings):
        return Route(False, "t0_decisive")
    if risk_tier == "high":
        return Route(True, "high_risk_tool", fail_closed=True)
    if ctx.tainted:
        return Route(True, "tainted_session")
    if _ambiguous(t0_findings):
        return Route(True, "t0_ambiguous")
    return Route(False, "low_risk_clean")


def route_inbound(trust: Trust, t0_findings: Sequence[Finding]) -> Route:
    if _decisive(t0_findings):
        return Route(False, "t0_decisive")
    if trust is Trust.UNTRUSTED:
        return Route(True, "untrusted_content")
    if _ambiguous(t0_findings):
        return Route(True, "t0_ambiguous")
    return Route(False, "trusted_clean" if trust is Trust.TRUSTED else "user_clean")


def arguments_text(arguments: Dict[str, Any]) -> str:
    return "\n".join(f"{k}: {v}" for k, v in arguments.items() if isinstance(v, str) and v)


def run_detectors(
    detectors: Sequence[Detector],
    text: str,
    route: Route,
    policy: Policy,
    location: str,
) -> List[Finding]:
    """Score text with each detector, stopping at the first block."""
    findings: List[Finding] = []
    text = text[:MAX_DETECTOR_CHARS]
    for det in detectors:
        started = time.perf_counter()
        try:
            result = det.detect(text)
        except Exception as exc:
            findings.append(Finding(
                rule_id=f"detector.{det.name}.error",
                action=Action.BLOCK if route.fail_closed else Action.FLAG,
                severity=Severity.HIGH,
                message=f"Detector {det.name} raised {type(exc).__name__}; "
                        + ("failing closed." if route.fail_closed else "flagging for review."),
                evidence={"error": str(exc)[:200], "route": route.reason, "location": location},
            ))
            if route.fail_closed:
                break
            continue

        score = min(1.0, max(0.0, float(result.score)))
        if score >= policy.detector_block_threshold:
            action, severity, threshold = Action.BLOCK, Severity.HIGH, policy.detector_block_threshold
        elif score >= policy.detector_flag_threshold:
            action, severity, threshold = Action.FLAG, Severity.MEDIUM, policy.detector_flag_threshold
        else:
            continue

        findings.append(Finding(
            rule_id=f"detector.{det.name}",
            action=action,
            severity=severity,
            message=f"Detector {det.name} scored {score:.2f} (>= {threshold:.2f}) "
                    f"on {location}; route={route.reason}.",
            evidence={
                **result.evidence,
                "score": round(score, 4),
                "label": result.label,
                "route": route.reason,
                "location": location,
                "detector_ms": round((time.perf_counter() - started) * 1000, 3),
            },
        ))
        if action is Action.BLOCK:
            break
    return findings
