"""Action baseline: hold an agent's first-ever action of a kind when its session read untrusted content.

Text detection cannot reliably tell an injected instruction from a legitimate
request: "Please transfer $3,000 to account 123-1234-1234" is the same sentence
either way. What an injection cannot avoid is making the agent *do* something,
and an agent's actions are few and repetitive. So this layer learns, per agent
(principal), what it normally does:

  * which tools it calls;
  * where it sends things: email and web domains, payees, accounts, phone
    numbers, webhooks (``destinations()``);
  * how much money a tool usually moves (the largest amount seen).

In a tainted session -- the agent has read a web page, an email, a tool's
output -- an action with anything new is held for a person
(``baseline.novel_action``): a tool this agent never used, a destination it
never sent to, or an amount more than ``amount_factor`` times its largest. No
detector has to notice the attack; the attack has to look exactly like
something the agent already does.

The baseline learns from two trusted signals only:

  * actions **committed in clean sessions** (nothing untrusted was read), which
    is the agent doing its normal job on its operator's instructions;
  * **reviewer approvals** of held actions. A rejection is remembered too, and
    shown to the next reviewer.

Nothing learned in a tainted session counts, so an injection cannot teach the
baseline its own destination. ``hold_when="always"`` holds new actions even in
clean sessions (strict onboarding); ``"off"`` only observes.
"""

from __future__ import annotations

import re
import threading
import time
from typing import Any, Callable, Dict, List, Sequence
from urllib.parse import urlparse

from .db import Database
from .rules.egress import _EMAIL, _URL, _strings
from .types import Action, Finding, Severity

# Argument names whose value *is* a destination even when it is not a URL or email.
DESTINATION_ARGS = {
    "to", "recipient", "recipients", "cc", "bcc", "payee", "payee_id", "beneficiary",
    "account", "account_number", "account_id", "iban", "swift", "upi", "upi_id", "vpa",
    "destination", "dest", "webhook", "webhook_url", "url", "endpoint", "channel",
    "phone", "phone_number", "mobile", "wallet", "address", "email",
}
_INDEX = re.compile(r"\[\d+\]")


def destinations(arguments: Any) -> List[str]:
    """Where a call sends things, as stable feature strings.

    ``domain:example.com`` for any URL or email address anywhere in the
    arguments, and ``to:<arg>=<value>`` for destination-named arguments that are
    neither (account numbers, payee ids, phone numbers, UPI ids).
    """
    out = set()
    for path, text in _strings(arguments):
        found = False
        for m in _URL.finditer(text):
            host = urlparse("http://" + m.group(1)).hostname
            if host:
                out.add("domain:" + host.lower().strip("."))
                found = True
        for m in _EMAIL.finditer(text):
            out.add("domain:" + m.group(1).lower().strip("."))
            found = True
        key = _INDEX.sub("", path.split(".")[-1]).lower() if path else ""
        if not found and key in DESTINATION_ARGS and text.strip():
            value = re.sub(r"[\s-]+", "", text.strip().lower())[:120]
            out.add("to:%s=%s" % (key, value))
    return sorted(out)


def describe(feature: str) -> str:
    if feature.startswith("domain:"):
        return "sends to %s" % feature[7:]
    if feature.startswith("to:"):
        key, _, value = feature[3:].partition("=")
        return "%s %s" % (key, value)
    return feature


_SCHEMA = """
CREATE TABLE IF NOT EXISTS baseline (
    principal TEXT NOT NULL, tool TEXT NOT NULL, feature TEXT NOT NULL,
    clean INTEGER NOT NULL DEFAULT 0, approved INTEGER NOT NULL DEFAULT 0,
    rejected INTEGER NOT NULL DEFAULT 0, last_reviewer TEXT NOT NULL DEFAULT '',
    first_seen REAL NOT NULL, last_seen REAL NOT NULL,
    PRIMARY KEY (principal, tool, feature));
CREATE TABLE IF NOT EXISTS baseline_amounts (
    principal TEXT NOT NULL, tool TEXT NOT NULL, max_amount REAL NOT NULL,
    PRIMARY KEY (principal, tool))
"""

HOLD_MODES = ("tainted", "always", "off")


class ActionBaseline:
    """What each agent normally does, and the check against it. Shared by every instance."""

    def __init__(self, target: Any = ":memory:", *, hold_when: str = "tainted",
                 min_approvals: int = 1, amount_factor: float = 2.0, audit: Any = None,
                 clock: Callable[[], float] = time.time) -> None:
        if hold_when not in HOLD_MODES:
            raise ValueError("hold_when must be one of %s" % ", ".join(HOLD_MODES))
        self.hold_when, self.min_approvals, self.amount_factor = hold_when, min_approvals, amount_factor
        self.audit, self._clock = audit, clock
        self.db = Database(target, schema="fairewall_baseline")
        self.db.create(_SCHEMA)
        self._lock = threading.Lock()

    @staticmethod
    def features(tool: str, arguments: Any) -> List[str]:
        return ["tool"] + destinations(arguments)

    # ----------------------------------------------------------------- check

    def assess(self, principal: str, tool: str, arguments: Any, amount: float,
               tainted: bool) -> List[Finding]:
        """A held finding when this action is new for this agent, else nothing."""
        if self.hold_when == "off" or (self.hold_when == "tainted" and not tainted):
            return []
        feats = self.features(tool, arguments)
        with self.db.transaction(lock="p:" + principal) as db:
            rows = {r["feature"]: r for r in db.execute(
                "SELECT * FROM baseline WHERE principal=? AND tool=?", (principal, tool))}
            row = db.execute("SELECT max_amount FROM baseline_amounts WHERE principal=? AND tool=?",
                             (principal, tool)).fetchone()
        known_max = row["max_amount"] if row else None
        new, rejected = [], []
        for f in feats:
            r = rows.get(f)
            if r is None or not (r["clean"] >= 1 or r["approved"] >= self.min_approvals):
                new.append(f)
                if r is not None and r["rejected"]:
                    rejected.append({"feature": f, "by": r["last_reviewer"]})
        big = amount > 0 and known_max is not None and amount > known_max * self.amount_factor
        if "tool" in new:
            new = ["tool"]  # a never-used tool says it all; its destinations are new by definition
        if not new and not big:
            return []
        parts = []
        if "tool" in new:
            parts.append("first time %s uses %s" % (principal, tool))
        else:
            parts.extend("first time it %s" % describe(f) for f in new)
        if big:
            parts.append("amount %.2f is over %gx the largest it has moved with %s (%.2f)"
                         % (amount, self.amount_factor, tool, known_max))
        where = "in a session that has read untrusted content" if tainted else "(strict mode)"
        return [Finding(
            rule_id="baseline.novel_action", action=Action.FLAG, severity=Severity.HIGH,
            message="New action for this agent %s: %s. A person must approve it." % (where, "; ".join(parts)),
            evidence={"principal": principal, "tool": tool, "new": new,
                      "amount": amount if big else None, "largest_before": known_max if big else None,
                      "rejected_before": rejected, "tainted": tainted})]

    # ----------------------------------------------------------------- learn

    def observe(self, principal: str, tool: str, arguments: Any, amount: float, kind: str,
                reviewer: str = "") -> None:
        """Record one trusted observation. ``kind``: clean, approved or rejected."""
        if kind not in ("clean", "approved", "rejected"):
            raise ValueError("kind must be clean, approved or rejected")
        now = self._clock()
        column = {"clean": "clean", "approved": "approved", "rejected": "rejected"}[kind]
        with self.db.transaction(lock="p:" + principal) as db:
            for f in self.features(tool, arguments):
                db.execute(
                    "INSERT INTO baseline (principal, tool, feature, %s, last_reviewer, first_seen, last_seen)"
                    " VALUES (?,?,?,1,?,?,?) ON CONFLICT(principal, tool, feature) DO UPDATE SET"
                    " %s=baseline.%s+1, last_seen=excluded.last_seen,"
                    " last_reviewer=CASE WHEN excluded.last_reviewer='' THEN baseline.last_reviewer"
                    " ELSE excluded.last_reviewer END" % (column, column, column),
                    (principal, tool, f, reviewer[:100], now, now))
            if amount > 0 and kind != "rejected":
                db.execute("INSERT INTO baseline_amounts VALUES (?,?,?) ON CONFLICT(principal, tool)"
                           " DO UPDATE SET max_amount=CASE WHEN excluded.max_amount > baseline_amounts.max_amount"
                           " THEN excluded.max_amount ELSE baseline_amounts.max_amount END",
                           (principal, tool, float(amount)))
        if kind != "clean" and self.audit is not None:
            self.audit.append("baseline_" + kind, {"principal": principal, "tool": tool,
                                                   "features": self.features(tool, arguments),
                                                   "reviewer": reviewer})

    @staticmethod
    def feature_for(destination: str) -> str:
        """A destination as an operator writes it -> a feature string.

        "priya@acme.in" or "https://acme.in/x" or "acme.in" -> "domain:acme.in";
        a feature string ("domain:..." or "to:payee=...") is kept as is.
        """
        d = destination.strip()
        if d.startswith(("domain:", "to:")):
            return d
        if "@" in d:
            return "domain:" + d.rsplit("@", 1)[1].lower()
        if "://" in d:
            return "domain:" + (urlparse(d).hostname or "").lower()
        return "domain:" + d.lower().strip(".")

    def allow(self, principal: str, tool: str, destinations_: Sequence[str] = (),
              max_amount: float = 0.0, by: str = "") -> List[str]:
        """Seed the baseline by hand (onboarding): this agent may use this tool and destinations."""
        if not (by or "").strip():
            raise ValueError("A reviewer name is required to seed the baseline.")
        feats = ["tool"] + [self.feature_for(d) for d in destinations_]
        now = self._clock()
        with self.db.transaction(lock="p:" + principal) as db:
            for f in feats:
                db.execute(
                    "INSERT INTO baseline (principal, tool, feature, approved, last_reviewer, first_seen,"
                    " last_seen) VALUES (?,?,?,?,?,?,?) ON CONFLICT(principal, tool, feature) DO UPDATE SET"
                    " approved=baseline.approved+excluded.approved, last_reviewer=excluded.last_reviewer",
                    (principal, tool, f, self.min_approvals, by.strip()[:100], now, now))
            if max_amount > 0:
                db.execute("INSERT INTO baseline_amounts VALUES (?,?,?) ON CONFLICT(principal, tool)"
                           " DO UPDATE SET max_amount=excluded.max_amount", (principal, tool, float(max_amount)))
        if self.audit is not None:
            self.audit.append("baseline_seeded", {"principal": principal, "tool": tool, "features": feats,
                                                  "max_amount": max_amount, "reviewer": by})
        return feats

    def profile(self, principal: str) -> Dict[str, Any]:
        with self.db.transaction(lock="p:" + principal) as db:
            rows = [dict(r) for r in db.execute(
                "SELECT tool, feature, clean, approved, rejected, last_reviewer FROM baseline"
                " WHERE principal=? ORDER BY tool, feature", (principal,))]
            amounts = {r["tool"]: r["max_amount"] for r in db.execute(
                "SELECT tool, max_amount FROM baseline_amounts WHERE principal=?", (principal,))}
        tools: Dict[str, Any] = {}
        for r in rows:
            t = tools.setdefault(r["tool"], {"features": [], "largest_amount": amounts.get(r["tool"])})
            t["features"].append({k: r[k] for k in ("feature", "clean", "approved", "rejected", "last_reviewer")})
        return {"principal": principal, "tools": tools}

    def close(self) -> None:
        self.db.close()
