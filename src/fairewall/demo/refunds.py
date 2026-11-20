"""Synthetic judge walkthrough and fictional, labelled buyer cohorts."""
import json
import os
import re
import uuid
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from fastapi import HTTPException

from ..approvals import ApprovalQueue, needs_human
from ..firewall import Firewall
from ..policy import Policy, ToolPolicy
from ..report import build_diff
from ..types import Principal

CASES = (("lookup_order", {"order": "DEMO-100"}), ("refund", {"order": "DEMO-101", "amount": 40}),
         ("refund", {"order": "DEMO-102", "amount": 140}))


def baseline():
    path = Path(__file__).with_name("refund-policy.json")
    if not path.exists():
        path = Path(__file__).resolve().parents[3] / "examples/refunds/policy.json"
    return Policy.from_file(str(path))


def preview(cap):
    current = baseline()
    draft = Policy.from_dict(current.to_dict())
    draft.max_spend_per_transaction = cap
    records = [{"session_id": f"case-{i}", "tool": "refund",
                "arguments": {"order": f"SAMPLE-{i}", "amount": amount}}
               for i, amount in enumerate((40, 80, 120, 40), 1)]
    records[-1]["untrusted_input"] = "Customer return email"
    return {"dataset": "Synthetic returns · four isolated orders", "current_cap": current.max_spend_per_transaction,
            "proposed_cap": cap, "session_cap": current.max_spend_per_session,
            **build_diff(records, current, draft)}

TEAMS = {
    "apparel": ("Apparel returns desk", 50, 200, [12, 18, 25, 31, 42, 50, 68, 90, 140, 201]),
    "home": ("Home goods support", 50, 150, [10, 22, 25, 32, 45, 50, 61, 99, 145, 220]),
}


def refund_policy(threshold, cap, manual=False):
    return Policy(version="manual" if manual else "refund-bands", default_deny=True,
                  max_spend_per_transaction=cap,
                  tools={"process_refund": ToolPolicy("process_refund", required_args=["order_id", "amount"],
                         allowed_args=["order_id", "amount"], require_human_approval=manual,
                         review_above=None if manual else threshold)})


def buyer_report(team):
    name, threshold, cap, amounts = TEAMS[team]
    records = []
    for i, amount in enumerate(amounts):
        # Distinct synthetic orders. The home-goods desk declined a damaged $45 return.
        refuse = amount > cap or (team == "home" and amount == 45)
        records.append({"session_id": f"case-{i}", "tool": "process_refund",
                        "arguments": {"order_id": f"SYN-{i}", "amount": amount},
                        "reviewer_decision": "refuse" if refuse else "approve"})
    diff = build_diff(records, refund_policy(threshold, 10000, manual=True),
                      refund_policy(threshold, cap), refund_metrics=True)
    workflows = {
        "apparel": "A support lead checks the order and signs off every return. The team would pilot routine "
                   "refunds in a band where automatic decisions match its reviewers.",
        "home": "Agents send all refund cases to a lead who also inspects damage evidence. The team would "
                "keep a band in review if even one proposed credit conflicts with the reviewer.",
    }
    return {"team": name, "synthetic": True, "workflow": workflows[team],
            "cap": cap, "threshold": threshold, "diff": diff}


def live_model():
    model = os.environ.get("FAIREWALL_GEMINI_MODEL", "")
    return model if re.fullmatch(r"gemini-[a-zA-Z0-9._-]+", model) and os.environ.get("GEMINI_API_KEY") else None


def proposals(mode):
    if mode == "recorded":
        return [{"name": tool, "args": dict(args)} for tool, args in CASES], None
    model = live_model()
    if not model:
        raise HTTPException(503, "Live Gemini is unconfigured. Choose Recorded walkthrough.")
    functions = []
    for tool in ("lookup_order", "refund"):
        fields = {"order": {"type": "STRING"}}
        if tool == "refund":
            fields["amount"] = {"type": "NUMBER"}
        functions.append({"name": tool, "parameters": {"type": "OBJECT", "properties": fields,
                                                       "required": list(fields)}})
    payload = {"contents": [{"parts": [{"text": "Propose three function calls in order: look up DEMO-100, "
                                   "refund DEMO-101 40 USD, refund DEMO-102 140 USD."}]}],
               "tools": [{"functionDeclarations": functions}],
               "toolConfig": {"functionCallingConfig": {"mode": "ANY"}}}
    req = Request(f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
                  data=json.dumps(payload).encode(), headers={"Content-Type": "application/json",
                  "x-goog-api-key": os.environ["GEMINI_API_KEY"]})
    try:
        with urlopen(req, timeout=18) as res:
            parts = json.load(res)["candidates"][0]["content"]["parts"]
        calls = [p["functionCall"] for p in parts if "functionCall" in p]
        if [(c["name"], c["args"]) for c in calls] != list(CASES):
            raise ValueError("unexpected proposals")
    except (URLError, TimeoutError, OSError, KeyError, IndexError, TypeError, ValueError):
        raise HTTPException(502, "Gemini did not return the three expected proposals. Retry or choose Recorded walkthrough.")
    return calls, model


def walkthrough(state, mode):
    from . import call_trace
    start = time.perf_counter()
    calls, model = proposals(mode)
    latency = (time.perf_counter() - start) * 1000 if model else None
    queue = state.refund_queue
    fw = queue.firewall
    ctx = fw.session(uuid.uuid4().hex, Principal("sandbox-agent"))
    ledger = {}
    results = []
    with fw.session_lock(ctx.session_id):
        for call in calls:
            tool, args = call["name"], call["args"]
            decision = fw.inspect(tool, args, ctx=ctx)
            action_id = decision.call_id
            def credit(order, amount, *, entry_id=action_id):
                ledger[entry_id] = {"receipt_id": "receipt-" + entry_id, "order": order,
                                    "amount_minor": round(amount * 100), "currency": "USD"}
                return ledger[entry_id]
            approval_id = None
            if needs_human(decision):
                approval_id = queue.submit(tool, args, ctx, decision, fn=credit).id
                status = "pending"
            elif decision.blocked:
                status = "blocked"
            else:
                fw._perform(tool, credit if tool == "refund" else lambda order: {"order": order},
                            args, ctx, decision)
                status = "executed"
            findings = sorted(decision.findings, key=lambda f: f.rule_id == "schema.human_approval_required")
            results.append(dict(action_id=action_id, approval_id=approval_id, tool=tool, status=status,
                            summary={"order": args["order"], "amount_minor": round(args["amount"] * 100)
                                     if "amount" in args else None, "currency": "USD"},
                            reason_codes=[f.rule_id for f in findings],
                            reason=findings[0].message if findings else "Order lookup permitted by the policy.",
                            policy_version=fw.policy.version, policy_fingerprint=fw.policy.fingerprint(),
                            policy_latency_ms=decision.latency_ms, trace=call_trace(tool,args,decision,ctx,fw.policy)))
        ctx.metadata.update(refund_ledger=ledger, run={"run_id":ctx.session_id,"model":model,"source":mode,
                            "model_latency_ms":latency,"calls":results,"reviewer":"sandbox-reviewer"})
    return get_run(state, ctx.session_id)


def get_run(state, run_id):
    queue = state.refund_queue
    ctx = queue.firewall.session(run_id)
    with queue.firewall.session_lock(run_id):
        if "run" not in ctx.metadata:
            raise HTTPException(404, "Run unavailable. Start a new sandbox run.")
        run = ctx.metadata["run"]
        calls = []
        for action in run["calls"]:
            row = dict(action)
            receipt = ctx.metadata["refund_ledger"].get(row["action_id"])
            if row["approval_id"]:
                request = queue.get(row["approval_id"])
                row["status"] = ("expired" if request is None else "executed" if request.executed else
                                 "uncertain" if request.status.value == "approved" else request.status.value)
                if request and request.executed:
                    row["reason"] = "Approved by %s. Policy rechecked before posting the refund." % request.decided_by
                elif row["status"] == "rejected":
                    row["reason"] = "Rejected by %s." % request.decided_by
                elif row["status"] == "expired":
                    row["reason"] = "The approval window has closed."
                if request and request.note:
                    row["review_note"] = request.note
            row["receipt"] = receipt if row["status"] == "executed" else None
            row["ledger_effect"] = (None if row["tool"] == "lookup_order" else
                                    {"entries": int(bool(receipt)), "amount_minor": receipt["amount_minor"] if receipt else 0})
            calls.append(row)
        return dict(run, calls=calls)


def new_refund_queue():
    return ApprovalQueue(Firewall(baseline()))
