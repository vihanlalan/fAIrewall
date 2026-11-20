"""Shadow-mode report: replay a tool-call log and show what fAIrewall would do.

The question this answers for a team that reviews every agent action by hand:
"of what my agents did last week, how much could have run without a person,
how much needs a person, and what should never have run?"

Nothing is executed. Each logged call is adjudicated and, if it would have been
permitted, committed to session state so budgets and rate limits behave as they
would live. Buckets:

    AUTO-APPROVED  decision ALLOW        no human needed
    HUMAN REVIEW   decision FLAG         allowed only after a person looks
    BLOCKED        decision BLOCK        would have been refused

Hours saved = auto-approved calls x minutes-per-review. The minutes figure is
supplied by the user (there is deliberately no default) and is printed as an
estimate, never as a measurement.
"""

from __future__ import annotations

import json
import math
import time
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .approvals import needs_human
from .detectors import Detector
from .firewall import Firewall, redact
from .harness import SYNTHETIC_NOTICE, demo_policy
from .policy import Policy
from .types import Action, Trust

_BUCKET = {Action.ALLOW: "auto_approved", Action.FLAG: "human_review", Action.BLOCK: "blocked"}
_EXPECTED_TO_BUCKET = {"allow": "auto_approved", "review": "human_review", "block": "blocked"}
_RANK = {"auto_approved": 0, "human_review": 1, "blocked": 2}


def load_log(path: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Read a JSONL log. Returns (meta, records); a ``_meta`` line is optional."""
    meta: Dict[str, Any] = {}
    records: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError("%s line %d is not valid JSON: %s" % (path, lineno, exc)) from exc
            if "_meta" in obj:
                meta = obj["_meta"] or {}
                continue
            if "tool" not in obj:
                raise ValueError("%s line %d has no 'tool' field" % (path, lineno))
            records.append(obj)
    return meta, records


def _bucket_for(decision: Any) -> str:
    """Map a decision to a report bucket.

    A call stopped *only* because the tool is configured to need a person's
    approval is HUMAN REVIEW, not a security block: nothing about it is hostile.
    """
    if decision.action is Action.BLOCK and needs_human(decision):
        return "human_review"
    return _BUCKET[decision.action]


def _replay_one(fw: Firewall, rec: Dict[str, Any], latencies: List[float]) -> Tuple[str, List[str]]:
    """Adjudicate one logged call on *fw*; return (bucket, rule ids that fired).

    A permitted call is committed so budgets and rate limits advance as they
    would have live. Nothing is executed.
    """
    ctx = fw.session(str(rec.get("session_id") or "log-default"))
    worst = "auto_approved"
    rule_ids: List[str] = []

    for field, trust in (("untrusted_input", Trust.UNTRUSTED), ("user_input", Trust.USER)):
        if rec.get(field):
            din = fw.inspect_input(str(rec[field]), trust=trust, ctx=ctx, source="log")
            latencies.append(din.latency_ms)
            if _RANK[_BUCKET[din.action]] > _RANK[worst]:
                worst = _BUCKET[din.action]
            rule_ids.extend(f.rule_id for f in din.findings)

    decision = fw.inspect(str(rec["tool"]), rec.get("arguments") or {}, ctx=ctx)
    latencies.append(decision.latency_ms)
    bucket = _bucket_for(decision)
    if _RANK[bucket] > _RANK[worst]:
        worst = bucket
    rule_ids.extend(f.rule_id for f in decision.findings)
    if not decision.blocked:
        fw.commit(str(rec["tool"]), rec.get("arguments") or {}, ctx)
    return worst, rule_ids


def _percentile(values: List[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round(pct / 100.0 * (len(ordered) - 1))))
    return ordered[index]


def build_report(
    records: Iterable[Dict[str, Any]],
    policy: Policy,
    minutes_per_review: float,
    synthetic: bool = False,
    detectors: Optional[Sequence[Detector]] = None,
) -> Dict[str, Any]:
    """Replay *records* through a fresh firewall and summarize the outcome."""
    if minutes_per_review <= 0:
        raise ValueError("minutes_per_review must be greater than zero")

    fw = Firewall(policy=policy, detectors=list(detectors or []))
    buckets: Counter = Counter()
    by_tool: Dict[str, Counter] = defaultdict(Counter)
    reasons: Dict[str, Counter] = {"human_review": Counter(), "blocked": Counter()}
    latencies: List[float] = []
    confusion: Counter = Counter()
    labeled = 0
    total = 0
    adv_total = 0
    adv_through = 0
    adv_text_only = 0  # stopped, but no structural rule fired: text inspection did the work
    adv_channel: Dict[str, List[int]] = defaultdict(lambda: [0, 0])
    adv_kind: Dict[str, List[int]] = defaultdict(lambda: [0, 0])
    adv_mut: Dict[str, List[int]] = defaultdict(lambda: [0, 0])

    for rec in records:
        total += 1
        worst, rule_ids = _replay_one(fw, rec, latencies)

        attack = rec.get("attack")
        if attack:
            got = worst == "auto_approved"
            adv_total += 1
            adv_through += got
            for table, key in ((adv_channel, attack.get("channel", "?")), (adv_kind, attack.get("kind", "?"))):
                table[key][0] += 1
                table[key][1] += got
            for m in attack.get("mutations") or ["(none)"]:
                adv_mut[m][0] += 1
                adv_mut[m][1] += got
            structural = any(not r.startswith(("injection.", "detector.")) for r in rule_ids)
            if not got and not structural:
                adv_text_only += 1

        buckets[worst] += 1
        by_tool[str(rec["tool"])][worst] += 1
        if worst in reasons:
            for rid in sorted(set(rule_ids)) or ["(no rule id)"]:
                reasons[worst][rid] += 1

        expected = _EXPECTED_TO_BUCKET.get(str(rec.get("expected", "")))
        if expected:
            labeled += 1
            confusion[(expected, worst)] += 1

    auto = buckets["auto_approved"]
    report: Dict[str, Any] = {
        "synthetic": synthetic,
        "notice": SYNTHETIC_NOTICE if synthetic else None,
        "total_calls": total,
        "buckets": {k: buckets[k] for k in ("auto_approved", "human_review", "blocked")},
        "percent": {k: round(100.0 * buckets[k] / total, 1) if total else 0.0
                    for k in ("auto_approved", "human_review", "blocked")},
        "minutes_per_review": minutes_per_review,
        "hours_saved_estimate": round(auto * minutes_per_review / 60.0, 2),
        "hours_saved_note": "ESTIMATE: auto-approved calls x %g min/review, minutes supplied by you."
                            % minutes_per_review,
        "by_tool": {t: {k: c[k] for k in ("auto_approved", "human_review", "blocked")}
                    for t, c in sorted(by_tool.items())},
        "top_reasons": {k: reasons[k].most_common(5) for k in reasons},
        "latency_ms": {"p50": round(_percentile(latencies, 50), 3),
                       "p99": round(_percentile(latencies, 99), 3),
                       "max": round(max(latencies), 3) if latencies else 0.0},
        "policy_fingerprint": policy.fingerprint(),
    }
    if adv_total:
        def table(d):
            return {k: {"attacks": v[0], "got_through": v[1]} for k, v in sorted(d.items())}
        report["adversary"] = {
            "attacks": adv_total,
            "got_through": adv_through,
            "got_through_pct": round(100.0 * adv_through / adv_total, 1),
            "stopped_only_by_text_inspection": adv_text_only,
            "by_channel": table(adv_channel),
            "by_kind": table(adv_kind),
            "by_mutation": table(adv_mut),
            "detectors": [d.name for d in (detectors or [])],
            "note": "Attacks are randomly generated by the same authors as the engine. "
                    "'Got through' = auto-approved with no human and no block. Real "
                    "attackers will try things this generator never imagined.",
        }
    if labeled:
        benign = sum(n for (exp, _), n in confusion.items() if exp == "auto_approved")
        benign_stopped = sum(n for (exp, got), n in confusion.items()
                             if exp == "auto_approved" and got != "auto_approved")
        harmful = sum(n for (exp, _), n in confusion.items() if exp == "blocked")
        harmful_passed = sum(n for (exp, got), n in confusion.items()
                             if exp == "blocked" and got == "auto_approved")
        report["author_labels"] = {
            "labeled_records": labeled,
            "benign_stopped": benign_stopped,
            "benign_total": benign,
            "benign_stopped_pct": round(100.0 * benign_stopped / benign, 2) if benign else 0.0,
            "harmful_auto_approved": harmful_passed,
            "harmful_total": harmful,
            "note": "TUNING SIGNAL ONLY: labels were written by the same authors as the rules. "
                    "This is not a false-positive rate; re-measure on a real log.",
        }
    return report


def render_text(report: Dict[str, Any]) -> str:
    """One-page, human-readable report."""
    lines: List[str] = []
    bar = "=" * 70
    if report["synthetic"]:
        lines += [bar, "  SYNTHETIC DATA - NOT CUSTOMER TRAFFIC", "  " + (report["notice"] or ""), bar]
    lines.append("fAIrewall shadow-mode report")
    lines.append("Calls replayed: %d   (nothing was executed)" % report["total_calls"])
    lines.append("")
    b, pc = report["buckets"], report["percent"]
    lines.append("  AUTO-APPROVED  %6d  (%5.1f%%)   no human needed" % (b["auto_approved"], pc["auto_approved"]))
    lines.append("  HUMAN REVIEW   %6d  (%5.1f%%)   a person should look" % (b["human_review"], pc["human_review"]))
    lines.append("  BLOCKED        %6d  (%5.1f%%)   would have been refused" % (b["blocked"], pc["blocked"]))
    lines.append("")
    lines.append("Review time saved: ~%.2f hours   [estimated]" % report["hours_saved_estimate"])
    lines.append("  " + report["hours_saved_note"])
    lines.append("")
    lines.append("By tool:")
    lines.append("  %-20s %8s %8s %8s" % ("tool", "auto", "review", "blocked"))
    for tool, c in report["by_tool"].items():
        lines.append("  %-20s %8d %8d %8d" % (tool, c["auto_approved"], c["human_review"], c["blocked"]))
    for key, title in (("blocked", "Top reasons for BLOCKED"), ("human_review", "Top reasons for HUMAN REVIEW")):
        rs = report["top_reasons"].get(key) or []
        if rs:
            lines.append("")
            lines.append(title + ":")
            for rid, n in rs:
                lines.append("  %5d  %s" % (n, rid))
    adv = report.get("adversary")
    if adv:
        lines.append("")
        lines.append("Random attacks (%d)  detectors: %s" % (adv["attacks"], ", ".join(adv["detectors"]) or "none"))
        lines.append("  Stopped: %d   GOT THROUGH: %d (%.1f%%)   [stopped by text alone, no structural rule: %d]"
                     % (adv["attacks"] - adv["got_through"], adv["got_through"], adv["got_through_pct"],
                        adv["stopped_only_by_text_inspection"]))
        for title, key in (("by channel", "by_channel"), ("by kind", "by_kind")):
            lines.append("  %s:" % title)
            for k, v in adv[key].items():
                lines.append("    %-28s %5d attacks, %4d got through" % (k, v["attacks"], v["got_through"]))
        lines.append("  " + adv["note"])
    lat = report["latency_ms"]
    lines.append("")
    lines.append("Decision latency: p50 %.3f ms, p99 %.3f ms, max %.3f ms" % (lat["p50"], lat["p99"], lat["max"]))
    al = report.get("author_labels")
    if al:
        lines.append("")
        lines.append("Author-labeled check (%d records): %d of %d benign actions were stopped (%.2f%%); "
                     "%d of %d harmful actions were auto-approved."
                     % (al["labeled_records"], al["benign_stopped"], al["benign_total"],
                        al["benign_stopped_pct"], al["harmful_auto_approved"], al["harmful_total"]))
        lines.append("  " + al["note"])
    lines.append("Policy fingerprint: %s" % report["policy_fingerprint"])
    if report["synthetic"]:
        lines += ["", bar, "  SYNTHETIC DATA - NOT CUSTOMER TRAFFIC", bar]
    return "\n".join(lines)


_BUCKET_LABEL = {"auto_approved": "AUTO-APPROVED", "human_review": "HUMAN REVIEW", "blocked": "BLOCKED"}


REFUND_BANDS = ((25, "$0–25"), (50, "Over $25–50"), (100, "Over $50–100"),
                (200, "Over $100–200"), (float("inf"), "Over $200"))


def build_diff(
    records: Iterable[Dict[str, Any]],
    old_policy: Policy,
    new_policy: Policy,
    detectors: Optional[Sequence[Detector]] = None,
    max_examples: int = 20,
    refund_metrics: bool = False,
) -> Dict[str, Any]:
    """Replay *records* under two policies and list every call whose verdict changes.

    Each policy gets its own fresh firewall, so budgets and rate limits evolve
    the way they would have under that policy alone. Nothing is executed.

    A change is *stricter* when the new policy puts the call in a more
    restrictive bucket (auto -> review -> blocked) and *looser* otherwise.
    Looser changes are the ones to read carefully before shipping a policy.
    """
    if max_examples < 0:
        raise ValueError("max_examples must be zero or more")
    fw_old = Firewall(policy=old_policy, detectors=list(detectors or []))
    fw_new = Firewall(policy=new_policy, detectors=list(detectors or []))
    old_buckets: Counter = Counter()
    new_buckets: Counter = Counter()
    transitions: Counter = Counter()
    by_tool: Dict[str, Counter] = defaultdict(Counter)
    # Kept per direction so stricter changes cannot crowd out the looser ones.
    found: Dict[str, List[Dict[str, Any]]] = {"looser": [], "stricter": []}
    latencies: List[float] = []
    total = stricter = looser = 0
    bands = defaultdict(Counter)
    old_ms, new_ms, delta_ms = [], [], []

    for index, rec in enumerate(records, 1):
        total += 1
        start = time.perf_counter_ns() if refund_metrics else 0
        old_b, old_rules = _replay_one(fw_old, rec, latencies)
        midpoint = time.perf_counter_ns() if refund_metrics else 0
        new_b, new_rules = _replay_one(fw_new, rec, latencies)
        if refund_metrics:
            old_ms.append((midpoint - start) / 1e6)
            new_ms.append((time.perf_counter_ns() - midpoint) / 1e6)
            delta_ms.append(new_ms[-1] - old_ms[-1])
            amount = (rec.get("arguments") or {}).get("amount")
            if (type(amount) not in (int, float) or not math.isfinite(amount) or amount < 0
                    or rec.get("reviewer_decision") not in (None, "approve", "refuse")):
                raise ValueError("Refund metrics require nonnegative numeric USD amounts and "
                                 "reviewer_decision approve, refuse or omitted (row %d)" % index)
            band = next((name for limit, name in REFUND_BANDS if amount <= limit), "Over $200")
            cohort = bands[band]
            cohort["requests"] += 1
            cohort["old_review"] += old_b == "human_review"
            cohort[new_b] += 1
            label = rec.get("reviewer_decision")
            if label in ("approve", "refuse") and new_b != "human_review":
                cohort["compared"] += 1
                cohort["disagreements"] += (new_b == "auto_approved") != (label == "approve")

        old_buckets[old_b] += 1
        new_buckets[new_b] += 1
        if old_b == new_b:
            continue
        direction = "stricter" if _RANK[new_b] > _RANK[old_b] else "looser"
        if direction == "stricter":
            stricter += 1
        else:
            looser += 1
        transitions[(old_b, new_b)] += 1
        tool = str(rec["tool"])
        by_tool[tool][direction] += 1
        if len(found[direction]) < max_examples:
            found[direction].append({
                "record": index,
                "session_id": str(rec.get("session_id") or "log-default"),
                "tool": tool,
                "arguments": redact(rec.get("arguments") or {}, cap=120),
                "old": old_b,
                "new": new_b,
                "direction": direction,
                # What fired only under the new policy, and what stopped firing.
                "rules_added": sorted(set(new_rules) - set(old_rules)),
                "rules_removed": sorted(set(old_rules) - set(new_rules)),
            })

    examples = (found["looser"] + found["stricter"])[:max_examples]
    keys = ("auto_approved", "human_review", "blocked")
    return {
        **({"refund_metrics": {
            "bands": {name: dict(bands[name]) for _, name in REFUND_BANDS if name in bands},
            "current_p95_ms": round(_percentile(old_ms, 95), 4),
            "proposed_p95_ms": round(_percentile(new_ms, 95), 4),
            "paired_added_p95_ms": round(_percentile(delta_ms, 95), 4),
        }} if refund_metrics else {}),
        "total_calls": total,
        "changed": stricter + looser,
        "stricter": stricter,
        "looser": looser,
        "old": {"fingerprint": old_policy.fingerprint(), "version": old_policy.version,
                "buckets": {k: old_buckets[k] for k in keys}},
        "new": {"fingerprint": new_policy.fingerprint(), "version": new_policy.version,
                "buckets": {k: new_buckets[k] for k in keys}},
        "transitions": [{"from": a, "to": b, "count": n}
                        for (a, b), n in sorted(transitions.items(),
                                                key=lambda kv: (-kv[1], kv[0]))],
        "by_tool": {t: {"stricter": c["stricter"], "looser": c["looser"]}
                    for t, c in sorted(by_tool.items())},
        "examples": examples,
        "examples_truncated": stricter + looser > len(examples),
    }


def render_diff_text(diff: Dict[str, Any]) -> str:
    """One-page, human-readable policy diff."""
    lines: List[str] = ["fAIrewall policy diff",
                        "Calls replayed: %d   (nothing was executed)" % diff["total_calls"],
                        "Old policy: %s (version %s)" % (diff["old"]["fingerprint"], diff["old"]["version"]),
                        "New policy: %s (version %s)" % (diff["new"]["fingerprint"], diff["new"]["version"]),
                        "",
                        "  %-14s %8s %8s %8s" % ("", "old", "new", "change")]
    for key in ("auto_approved", "human_review", "blocked"):
        o, n = diff["old"]["buckets"][key], diff["new"]["buckets"][key]
        lines.append("  %-14s %8d %8d %+8d" % (_BUCKET_LABEL[key], o, n, n - o))
    lines.append("")
    if "refund_metrics" in diff:
        metrics = diff["refund_metrics"]
        lines.append("USD band | requests | current review | proposed review | disagreements / compared")
        for band, counts in metrics["bands"].items():
            lines.append("%s | %d | %d | %d | %d / %d" % (band, counts["requests"],
                         counts["old_review"], counts.get("human_review", 0),
                         counts.get("disagreements", 0), counts.get("compared", 0)))
        lines.append("Local replay p95 (ms): current %.4f, proposed %.4f, paired added %.4f"
                     % (metrics["current_p95_ms"], metrics["proposed_p95_ms"], metrics["paired_added_p95_ms"]))
    if not diff["changed"]:
        lines.append("No call changes verdict under the new policy.")
        return "\n".join(lines)

    lines.append("Verdict changed on %d calls: %d stricter, %d LOOSER"
                 % (diff["changed"], diff["stricter"], diff["looser"]))
    if diff["looser"]:
        lines.append("  Looser = the new policy lets through something the old one stopped. Read these first.")
    lines.append("")
    lines.append("Changes:")
    for t in diff["transitions"]:
        lines.append("  %-14s -> %-14s %6d" % (_BUCKET_LABEL[t["from"]], _BUCKET_LABEL[t["to"]], t["count"]))
    lines.append("")
    lines.append("By tool:")
    lines.append("  %-20s %9s %9s" % ("tool", "stricter", "looser"))
    for tool, c in diff["by_tool"].items():
        lines.append("  %-20s %9d %9d" % (tool, c["stricter"], c["looser"]))
    if diff["examples"]:
        lines.append("")
        lines.append("Examples, looser first%s:" % (" (%d shown)" % len(diff["examples"]) if diff["examples_truncated"] else ""))
        for ex in diff["examples"]:
            mark = "LOOSER " if ex["direction"] == "looser" else "stricter"
            lines.append("  #%-5d %s  %s %s" % (ex["record"], mark, ex["tool"],
                                               json.dumps(ex["arguments"], sort_keys=True)))
            lines.append("          %s -> %s" % (_BUCKET_LABEL[ex["old"]], _BUCKET_LABEL[ex["new"]]))
            if ex["rules_added"]:
                lines.append("          now fires:      " + ", ".join(ex["rules_added"]))
            if ex["rules_removed"]:
                lines.append("          stopped firing: " + ", ".join(ex["rules_removed"]))
    return "\n".join(lines)


def default_policy_for(meta: Dict[str, Any]) -> Optional[Policy]:
    """The demo policy is used only for logs the harness itself generated."""
    return demo_policy() if meta.get("synthetic") else None
