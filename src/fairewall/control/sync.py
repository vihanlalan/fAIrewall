"""Gateway side of the control plane: pull policy, push health and decisions.

One background thread per gateway. Each tick is a single HTTPS POST:

  gateway -> control plane : health report + audit records since the last ack
  control plane -> gateway : assigned policy, shadow flag, fleet freezes, ack

If the control plane is unreachable the gateway keeps enforcing the last
policy it received ("fail static"): losing the control plane must never turn
enforcement off, and must never block traffic on its own either.
"""

from __future__ import annotations

import json
import secrets
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from ..firewall import Firewall
from ..policy import Policy

# Events forwarded to the control plane. Everything else stays local.
FORWARDED_EVENTS = {
    "tool_call_inspected", "input_inspected", "tool_output_inspected",
    "kill_switch_engaged", "kill_switch_released",
    "approval_requested", "approval_approved", "approval_rejected", "approval_expired",
}
CONTROL_PLANE_BY = "control plane"


def _event_view(record: Dict[str, Any]) -> Dict[str, Any]:
    """The part of an audit record the control plane needs. Arguments are the
    already-redacted copy the firewall logged, never the raw values."""
    return {
        "seq": record.get("seq"), "event": record.get("event"), "tool": record.get("tool"),
        "action": record.get("action") or record.get("status"),
        "session_id": record.get("session_id"), "principal": record.get("principal"),
        "timestamp": record.get("timestamp"),
        "findings": [{"rule_id": f.get("rule_id"), "action": f.get("action"),
                      "message": str(f.get("message") or "")[:300]}
                     for f in (record.get("findings") or [])][:10],
        "arguments": record.get("arguments") or {},
    }


class ControlPlaneSync:
    """Keeps one gateway's firewall in step with the control plane."""

    def __init__(self, firewall: Firewall, url: str, token: str, *,
                 interval: float = 10.0, auth_required: bool = False,
                 separate_reviewer_key: bool = False, timeout: float = 5.0,
                 batch: int = 500) -> None:
        if not url or not token:
            raise ValueError("Control plane URL and gateway token are both required.")
        self.firewall = firewall
        self.url = url.rstrip("/") + "/cp/v1/agent/sync"
        self.token = token
        self.interval = max(1.0, float(interval))
        self.timeout = timeout
        self.batch = batch
        self.auth_required = auth_required
        self.separate_reviewer_key = separate_reviewer_key
        self.boot_id = secrets.token_hex(4)
        self.started_at = time.time()
        # Audit records up to this sequence number are acknowledged. None until
        # the control plane tells us where it stands for this log.
        self._acked: Optional[int] = None
        self._log_id = ""
        self._applied_fingerprint: Optional[str] = None
        self._chain: Tuple[float, bool, int] = (0.0, True, 0)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.status: Dict[str, Any] = {"managed": True, "ok": False, "last_sync": None,
                                       "last_error": None, "policy": None}
        firewall.control_status = self.status  # read by the gateway's /health

    # ---------------------------------------------------------------- loop

    def start(self) -> "ControlPlaneSync":
        self._thread = threading.Thread(target=self._run, name="fairewall-control-sync",
                                        daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=self.timeout + 1)

    def _run(self) -> None:
        while not self._stop.is_set():
            self.sync_once()
            self._stop.wait(self.interval)

    # ---------------------------------------------------------------- tick

    def sync_once(self) -> bool:
        """One round trip. Returns True on success. Never raises."""
        try:
            log_id = self.firewall.audit.first_hash()
            if log_id != self._log_id:
                self._log_id, self._acked = log_id, None
            events: List[Dict[str, Any]] = []
            acked = -1 if self._acked is None else self._acked
            if log_id:
                records = self.firewall.audit.records_after(acked, self.batch)
                events = [_event_view(r) for r in records if r.get("event") in FORWARDED_EVENTS]
                sent_up_to = records[-1]["seq"] if records else acked
            else:
                sent_up_to = None
            reply = self._post({"report": self._report(), "log_id": log_id, "events": events,
                                "sent_up_to": sent_up_to})
            applied = self._apply(reply)
            if sent_up_to is not None:
                self._acked = sent_up_to
            elif log_id:
                self._acked = int(reply.get("acked_seq", -1))
            if applied:
                new_log_id = self.firewall.audit.first_hash()
                new_acked = -1 if self._acked is None else self._acked
                new_records = self.firewall.audit.records_after(new_acked, self.batch)
                new_events = [_event_view(r) for r in new_records if r.get("event") in FORWARDED_EVENTS]
                new_sent = new_records[-1]["seq"] if new_records else new_acked
                self._post({"report": self._report(), "log_id": new_log_id, "events": new_events,
                            "sent_up_to": new_sent})
                if new_sent is not None:
                    self._acked = new_sent
            self.status.update(ok=True, last_sync=time.time(), last_error=None)
            return True
        except Exception as exc:  # network, auth, bad reply: keep enforcing what we have
            self.status.update(ok=False, last_error="%s: %s" % (type(exc).__name__, str(exc)[:200]))
            return False

    def _post(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        data = json.dumps(payload, default=str).encode("utf-8")
        req = urllib.request.Request(self.url, data=data, method="POST", headers={
            "Content-Type": "application/json", "Authorization": "Bearer " + self.token})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise RuntimeError("control plane answered HTTP %d" % exc.code)

    def _report(self) -> Dict[str, Any]:
        fw = self.firewall
        # Verifying the chain is O(log size); do it at most once a minute.
        checked_at, valid, count = self._chain
        if time.time() - checked_at > 60:
            v = fw.audit.verify()
            self._chain = (time.time(), bool(v.valid), int(v.checked))
            _, valid, count = self._chain
        return {
            "fingerprint": fw.policy.fingerprint(), "policy_version": fw.policy.version,
            "shadow": fw.shadow, "auth_required": self.auth_required,
            "separate_reviewer_key": self.separate_reviewer_key,
            "chain_valid": valid, "chain_checked": count, "audit_head": fw.audit.head,
            "freezes": fw.freezes(), "detectors": [d.name for d in fw.detectors],
            "boot_id": self.boot_id, "started_at": self.started_at,
        }

    # --------------------------------------------------------------- apply

    def _apply(self, reply: Dict[str, Any]) -> bool:
        fw = self.firewall
        assigned = reply.get("policy")
        applied = False
        if assigned and assigned.get("fingerprint") != self._applied_fingerprint:
            policy = Policy.from_dict(assigned["body"])
            if policy.fingerprint() != assigned["fingerprint"]:
                raise ValueError("Policy from control plane does not match its fingerprint; "
                                 "keeping the current policy.")
            fw.policy = policy
            self._applied_fingerprint = assigned["fingerprint"]
            fw.audit.append("policy_applied", {
                "tool": "control plane", "action": "allow", "status": "applied",
                "policy_name": assigned.get("name"), "policy_version": policy.version,
                "policy_fingerprint": policy.fingerprint(), "assigned_version": assigned.get("version"),
            })
            applied = True
        if assigned:
            fw.shadow = bool(assigned.get("shadow"))
            self.status["policy"] = {"name": assigned.get("name"), "version": assigned.get("version"),
                                     "fingerprint": assigned.get("fingerprint"),
                                     "shadow": fw.shadow}

        # Mirror fleet freezes, reconciling against what is actually frozen
        # on this gateway (so it also works after a restart, and a fleet
        # freeze released locally is put back). Only freezes the control plane
        # set are ever lifted here; one an operator set on the gateway stays.
        wanted = {(f["scope"], f["target"]): f for f in reply.get("freezes") or []}
        local = {(f["scope"], f["target"]): f for f in fw.freezes()}
        for key, f in wanted.items():
            if key not in local:
                fw.freeze(f["scope"], None if f["scope"] == "all" else f["target"],
                          reason=f.get("reason", ""),
                          by="%s (%s)" % (CONTROL_PLANE_BY, f.get("by", "admin")))
        for key, f in local.items():
            if key not in wanted and str(f.get("by", "")).startswith(CONTROL_PLANE_BY):
                fw.unfreeze(key[0], None if key[0] == "all" else key[1], by=CONTROL_PLANE_BY)
        return applied
