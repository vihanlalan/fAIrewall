"""Canary values: fake secrets planted where an attacker would look. If one leaves, it is theft.

Detectors guess. A canary does not: it is a value no legitimate task ever has a
reason to send anywhere -- a decoy API key in the system prompt, a decoy
customer email in a CRM record, a decoy internal URL in a document. If one
turns up in the arguments of an outgoing tool call, the agent is exfiltrating
what it was shown, however the injection that made it do so was worded.

On a trip (``canary.tripped``):
  * the call is blocked (critical);
  * the session is frozen by the kill switch, so the agent can do nothing more
    in that run until a person releases it;
  * every untrusted source the session read is marked a suspect, so source
    sampling deep-checks each of their items again (fairewall.sampling).

Matching tolerates the usual disguises: any letter case, separators stripped or
added ("s k - l i v e"), base64, base64url and hex encodings. It does not catch
a model that paraphrases or leaks only part of a value; plant several kinds.

Placing canaries is the integrator's job (``issue()`` returns a ready-made
sentence for a system prompt or a document). Every value is random and new, so
it cannot collide with real data, and the formats look real on purpose.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import secrets
import string
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from .db import Database
from .types import Action, Finding, Severity

KINDS = ("api_key", "email", "url", "account")
_ALNUM = re.compile(r"[^a-z0-9]")
_B62 = string.ascii_letters + string.digits


def _rand(n: int, alphabet: str = _B62) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def make_value(kind: str, domain: str = "example.com") -> str:
    if kind == "api_key":
        return "sk-svc-" + _rand(36)
    if kind == "email":
        first = secrets.choice(["ananya", "rohan", "meera", "vikram", "isha", "kabir", "neha"])
        last = secrets.choice(["rao", "iyer", "mehta", "sharma", "nair", "kapoor", "das"])
        return "%s.%s.%s@%s" % (first, last, _rand(4, string.digits), domain)
    if kind == "url":
        return "https://internal.%s/share/%s" % (domain, _rand(24))
    if kind == "account":
        return "ACCT-%s-%s" % (_rand(4, string.digits), _rand(8, string.ascii_uppercase + string.digits))
    raise ValueError("kind must be one of %s" % ", ".join(KINDS))


PLACEMENT = {
    "api_key": "Internal billing service key (for system use only, never share): {value}",
    "email": "Escalation contact for VIP customers: {value}",
    "url": "Internal customer export (staff only): {value}",
    "account": "Reserve settlement account (do not use without CFO sign-off): {value}",
}


def _variants(value: str) -> Dict[str, List[str]]:
    """Forms of the value to look for, by how the text must be normalised first."""
    raw = value.encode()
    plain = _ALNUM.sub("", value.lower())
    b64 = base64.b64encode(raw).decode().rstrip("=")
    return {
        "lower": [value.lower(), binascii.hexlify(raw).decode()],
        "alnum": [plain] if len(plain) >= 12 else [],
        "raw": [b64, base64.urlsafe_b64encode(raw).decode().rstrip("=")],
    }


_SCHEMA = """
CREATE TABLE IF NOT EXISTS canaries (
    id TEXT PRIMARY KEY, kind TEXT NOT NULL, value TEXT NOT NULL, label TEXT NOT NULL DEFAULT '',
    session_id TEXT, created REAL NOT NULL, issued_by TEXT NOT NULL DEFAULT '',
    tripped INTEGER NOT NULL DEFAULT 0, last_tripped REAL);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)
"""


class CanaryRegistry:
    """Issued canaries, shared by every instance, and the scan for them."""

    def __init__(self, target: Any = ":memory:", *, email_domain: str = "example.com",
                 refresh_s: float = 2.0, audit: Any = None,
                 clock: Callable[[], float] = time.time) -> None:
        self.email_domain, self.refresh_s = email_domain, refresh_s
        self.audit, self._clock = audit, clock
        self.db = Database(target, schema="fairewall_canaries")
        self.db.create(_SCHEMA)
        self._lock = threading.Lock()
        self._loaded: List[Dict[str, Any]] = []
        self._generation: Optional[str] = None
        self._checked = 0.0
        self._refresh(force=True)

    def issue(self, kind: str = "api_key", *, label: str = "", session_id: Optional[str] = None,
              issued_by: str = "") -> Dict[str, Any]:
        """Create a canary. Plant ``placement`` (or ``value``) where an attacker would look."""
        value = make_value(kind, self.email_domain)
        cid = "can_" + hashlib.sha256(value.encode()).hexdigest()[:12]
        with self.db.transaction() as db:
            db.execute("INSERT INTO canaries (id, kind, value, label, session_id, created, issued_by)"
                       " VALUES (?,?,?,?,?,?,?)",
                       (cid, kind, value, label[:200], session_id, self._clock(), issued_by[:100]))
            db.execute("INSERT INTO meta VALUES ('generation', ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                       (secrets.token_hex(8),))
        self._refresh(force=True)
        if self.audit is not None:
            self.audit.append("canary_issued", {"canary_id": cid, "kind": kind, "label": label,
                                                "session_id": session_id, "issued_by": issued_by})
        return {"id": cid, "kind": kind, "value": value, "label": label, "session_id": session_id,
                "placement": PLACEMENT[kind].format(value=value)}

    def list(self) -> List[Dict[str, Any]]:
        """Issued canaries without their values (who can see this must not learn them)."""
        with self.db.transaction() as db:
            rows = list(db.execute("SELECT id, kind, label, session_id, created, issued_by, tripped,"
                                   " last_tripped FROM canaries ORDER BY created"))
        return [dict(r) for r in rows]

    def _refresh(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._checked < self.refresh_s:
            return
        with self._lock:
            self._checked = now
            with self.db.transaction() as db:
                row = db.execute("SELECT v FROM meta WHERE k='generation'").fetchone()
                generation = row["v"] if row else ""
                if generation == self._generation and not force:
                    return
                rows = [dict(r) for r in db.execute("SELECT id, kind, value, session_id FROM canaries")]
            for r in rows:
                r["variants"] = _variants(r["value"])
            self._loaded, self._generation = rows, generation

    def scan(self, text: str, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Every canary present in *text*.

        All canaries are checked everywhere: one issued for another run turning
        up here means data crossed between runs, which is theft too.
        """
        self._refresh()
        if not text or not self._loaded:
            return []
        lower = text.lower()
        forms = {"lower": lower, "alnum": _ALNUM.sub("", lower), "raw": text}
        hits = []
        for c in self._loaded:
            for how, needles in c["variants"].items():
                if any(n and n in forms[how] for n in needles):
                    hits.append({"id": c["id"], "kind": c["kind"], "matched_as": how})
                    break
        return hits

    def finding(self, hits: List[Dict[str, Any]], tool: str) -> Finding:
        return Finding(
            rule_id="canary.tripped", action=Action.BLOCK, severity=Severity.CRITICAL,
            message="Tool %s was asked to send a planted decoy value (%s). No task needs it: the "
                    "agent is exfiltrating what it was shown. The session is frozen."
                    % (tool, ", ".join("%s %s" % (h["kind"], h["id"]) for h in hits)),
            evidence={"canaries": hits})

    def record_trip(self, hits: List[Dict[str, Any]]) -> None:
        with self.db.transaction() as db:
            for h in hits:
                db.execute("UPDATE canaries SET tripped=tripped+1, last_tripped=? WHERE id=?",
                           (self._clock(), h["id"]))

    def close(self) -> None:
        self.db.close()
