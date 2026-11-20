"""Verify the deployed Lab's live paths. Uses only the Python standard library."""

import json
import os
import sys
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class SmokeFailure(RuntimeError):
    """A required deployment check did not pass."""


def require(condition, message):
    if not condition:
        raise SmokeFailure(message)


def request(base, path, *, token="", body=None):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = Request(base + path, data=data, headers=headers)
    try:
        with urlopen(req, timeout=125) as response:
            return json.load(response)
    except HTTPError as exc:
        raise SmokeFailure(f"{req.method} {path} returned HTTP {exc.code}") from exc
    except (URLError, TimeoutError, ValueError) as exc:
        raise SmokeFailure(f"{req.method} {path} failed: {exc}") from exc


def event_stages(run, event, detector):
    return [stage for row in run.get("trace", []) if row.get("event") == event
            for stage in row.get("stages", []) if stage.get("detector") == detector]


def published_evidence(call, token, *, wait_seconds, required_backends):
    deadline = time.monotonic() + wait_seconds
    while True:
        evidence = call("/api/evidence", token=token)
        proof = evidence.get("synthetic_proof") or {}
        receipts = proof.get("receipts") or {}
        confirmed = {row.get("backend") for row in evidence.get("published", [])
                     if row.get("status") == "confirmed"}
        if ((evidence.get("proof_check") or {}).get("valid") is True and proof.get("commitment")
                and all(receipts.get(backend) and backend in confirmed
                        for backend in required_backends)):
            print("PASS  Verified Merkle proof and published receipt for " + ", ".join(sorted(required_backends)))
            return
        if time.monotonic() >= deadline:
            raise SmokeFailure("Evidence proof or publication not verified. Run fw-anchor and inspect its logs.")
        time.sleep(min(5, max(0, deadline - time.monotonic())))


def run(call, *, wait_seconds=60, require_evm=False):
    status = call("/api/status")
    backend = status.get("gemini") or ""
    require(backend.startswith("vertex:"), "Lab is not configured to use Vertex AI Gemini.")
    require(status.get("model_armor"), "Lab does not have a Model Armor template.")
    tokens = call("/api/workspaces", body={})
    p, r = tokens["propose_token"], tokens["review_token"]

    denied = call("/api/runs", token=p, body={"chapter": 2})
    require(any(e.get("event") == "submit" and e.get("outcome") == "block"
                and "financial.transaction_limit" in e.get("rule_ids", []) for e in denied.get("trace", []))
            and not (denied.get("effects") or {}).get("refunds")
            and any(s.get("status") == "skipped" for s in event_stages(denied, "submit", "model_armor")),
            "Over-cap action did not prove a deterministic block with Model Armor skipped.")
    print("PASS  Deterministic block skipped Model Armor and produced no refund")

    # A fresh, harmless external message avoids counting a previous provider cache hit.
    routed = call("/api/runs", token=p, body={
        "kind": "website",
        "text": f"The warehouse confirms the parcel is ready for pickup. Reference {uuid.uuid4().hex}.",
    })
    require(any(s.get("provenance") == "live call"
                and s.get("status") in ("pass", "hold", "block")
                and any(value in ("MATCH_FOUND", "NO_MATCH_FOUND")
                        for value in (s.get("evidence", {}).get("filters") or {}).values())
                for s in event_stages(routed, "screen", "model_armor")),
            "No live Model Armor screening result. Check the template, IAM, and detector trace.")
    print("PASS  Live Model Armor returned an executed filter result")

    learning = call("/api/runs", token=p, body={"chapter": 5})
    case_id = (learning.get("detail") or {}).get("case_id")
    require(learning.get("status") == "input_held" and case_id, "Learning fixture did not open a review case.")
    call(f"/api/cases/{case_id}/label", token=r, body={"verdict": "malicious"})
    variant = call("/api/runs", token=p, body={"kind": "website", "fixture": "courier-weak-variant"})
    require(variant.get("status") == "input_blocked"
            and any(e.get("event") == "screen" and "adaptive.learned_threat" in e.get("rule_ids", [])
                    for e in variant.get("trace", [])),
            "The labeled example did not block the related fixture through learned memory.")
    print("PASS  A reviewer label changed the verdict on a related example")

    live = call("/api/runs", token=p, body={"chapter": 1, "source": "live"})
    agent = live.get("agent") or {}
    require(agent.get("source") == "live" and agent.get("model") and agent.get("actions")
            and live.get("status") not in ("model_error", "error")
            and any(e.get("event") == "proposal" and e.get("evidence", {}).get("backend") == backend
                    for e in live.get("trace", [])),
            "Vertex AI did not return a live tool proposal.")
    print(f"PASS  Vertex AI Gemini proposed a tool action ({agent['model']})")

    try:
        frozen = call("/api/killswitch/freeze", token=r, body={})
        gateways = frozen.get("gateways", [])
        services = {g.get("service") for g in gateways}
        require(len(gateways) == 2 and services == {"fw-gateway-a", "fw-gateway-b"}
                and all(g.get("mode") == "remote service" and g.get("observed") is True
                        and "killswitch.frozen" in g.get("rule_ids", []) for g in gateways)
                and (frozen.get("governed_dispatch") or {}).get("dispatched") is False,
                "Both distinct Cloud Run gateways must acknowledge the freeze and the Lab must refuse dispatch.")
        print("PASS  Two distinct remote gateways acknowledged the freeze and dispatch was refused")
    finally:
        call("/api/killswitch/unfreeze", token=r, body={})

    required_backends = {"bucket", "evm"} if require_evm else {"bucket"}
    published_evidence(call, p, wait_seconds=wait_seconds, required_backends=required_backends)


def main():
    base = os.environ.get("LAB_URL", "").rstrip("/")
    try:
        require(base.startswith(("http://", "https://")), "Set LAB_URL to the deployed Lab's HTTP(S) URL.")
        run(lambda path, **kwargs: request(base, path, **kwargs),
            wait_seconds=float(os.environ.get("SMOKE_ANCHOR_TIMEOUT_S", "60")),
            require_evm=os.environ.get("SMOKE_REQUIRE_EVM") == "true")
    except (SmokeFailure, KeyError, TypeError, ValueError) as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        return 1
    print("All cloud smoke checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
