"""Proof of Sampling for content sources: verify every item from a newcomer, a sample once trusted.

Adapted from Zhang et al., "Proof of Sampling: A Nash Equilibrium-Based
Verification Protocol for Decentralized Systems" (arXiv:2405.00295). In PoSP an
asserter's work is re-checked by a validator with probability p; a mismatch goes
to arbitration and the cheater loses its stake S. The paper shows honesty is the
unique Nash equilibrium when (Proposition 1, one validator):

    p > C / ((1 - r) * S + (1 - 2r) * R)

with C the cost of a check, R the reward for an accepted honest result, and r
the share of dishonest validators.

Mapping to fAIrewall:

  * asserter    -> a content source (a tool, an MCP server, a web domain, an inbox);
  * validator   -> the deep check: the expensive detectors (Google Model Armor);
  * arbitration -> a person, through the adaptive threat memory's review queue;
  * stake S     -> the trust a source has earned: the number of its items that
                   passed a deep check. A confirmed injection slashes it to zero
                   and puts the source in quarantine;
  * reward R    -> being accepted without a deep check (normalised to 1, as is C).

A source seen for the first time has no stake, so the inequality cannot hold
for any p < 1: every item it sends is deep-checked until it has passed
``probation`` checks. As stake grows, p falls toward ``p_floor``. The choice to
check is a keyed PRF (HMAC-SHA256) over a fresh request id, made after the
content arrived, so a source cannot predict which items will be checked.

What sampling does and does not change, on purpose:

  * It only decides whether the *expensive* deep detectors run. The
    deterministic rules, the cheap local detector, the threat memory and taint
    tracking run on every item, always. Content from any untrusted source still
    taints the session, however trusted the source.
  * The equilibrium argument assumes a rational source with something to lose.
    A one-shot attacker with nothing to lose is caught with probability p per
    attempt, not deterred, which is why sampling is a cost control on the deep
    check and never a reason to skip the deterministic floor.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .db import Database

STATUSES = ("probation", "trusted", "suspect", "quarantined")


@dataclass
class SamplingConfig:
    r: float = 0.10            # assumed share of dishonest validators (paper's r)
    cost: float = 1.0          # C: cost of one deep check
    reward: float = 1.0        # R: value to a source of an item accepted unchecked
    stake_per_check: float = 1.0
    max_stake: float = 1000.0
    probation: int = 20        # clean deep checks before a new source can be sampled
    p_floor: float = 0.02      # never check less often than this


def required_probability(stake: float, cfg: SamplingConfig) -> float:
    """Smallest p for which honesty is the equilibrium (Proposition 1), clamped to [p_floor, 1]."""
    denom = (1 - cfg.r) * stake + (1 - 2 * cfg.r) * cfg.reward
    if denom <= 0:
        return 1.0
    return max(cfg.p_floor, min(1.0, cfg.cost / denom))


@dataclass
class SamplePlan:
    source: str
    probability: float
    sampled: bool
    status: str
    request_id: str

    def view(self) -> Dict[str, Any]:
        return {"source": self.source, "probability": round(self.probability, 4),
                "deep_check": self.sampled, "status": self.status}


_SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    source TEXT PRIMARY KEY, first_seen REAL NOT NULL, last_seen REAL NOT NULL,
    items INTEGER NOT NULL DEFAULT 0, checked INTEGER NOT NULL DEFAULT 0,
    clean INTEGER NOT NULL DEFAULT 0, flagged INTEGER NOT NULL DEFAULT 0,
    slashes INTEGER NOT NULL DEFAULT 0, stake REAL NOT NULL DEFAULT 0,
    clean_since_slash INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL, resume_status TEXT NOT NULL DEFAULT 'probation')
"""


class SourceSampler:
    """Per-source trust, sampling decisions, rewards and slashing. Persistent and shareable."""

    def __init__(self, target: Any, *, config: Optional[SamplingConfig] = None,
                 secret: Optional[bytes] = None, audit: Any = None,
                 clock: Callable[[], float] = time.time) -> None:
        self.config = config or SamplingConfig()
        env = os.environ.get("FAIREWALL_SAMPLING_SECRET")
        self._secret = secret or (env.encode() if env else secrets.token_bytes(32))
        self.audit = audit
        self._clock = clock
        self.db = Database(target, schema="fairewall_sources")
        self.db.create(_SCHEMA)
        self._lock = threading.Lock()

    @staticmethod
    def key(source: str) -> str:
        return (source or "unknown").strip()[:200] or "unknown"

    def _sampled(self, source: str, request_id: str, p: float) -> bool:
        if p >= 1.0:
            return True
        mac = hmac.new(self._secret, (source + "\x00" + request_id).encode("utf-8", "surrogatepass"),
                       hashlib.sha256).digest()
        return int.from_bytes(mac, "big") < int(p * (1 << 256))

    def plan(self, source: str) -> SamplePlan:
        """Count one item from *source* and decide whether it gets the deep check."""
        source, now, cfg = self.key(source), self._clock(), self.config
        with self.db.transaction() as db:
            row = db.execute("SELECT * FROM sources WHERE source=?", (source,)).fetchone()
            if row is None:
                db.execute("INSERT INTO sources (source, first_seen, last_seen, items, status)"
                           " VALUES (?,?,?,1,'probation')", (source, now, now))
                status, stake = "probation", 0.0
                first = True
            else:
                db.execute("UPDATE sources SET items=items+1, last_seen=? WHERE source=?", (now, source))
                status, stake = row["status"], row["stake"]
                first = False
        p = 1.0 if status != "trusted" else required_probability(stake, cfg)
        request_id = uuid.uuid4().hex
        plan = SamplePlan(source, p, self._sampled(source, request_id, p), status, request_id)
        if first:
            self._audit("source_first_seen", {"source": source})
        return plan

    def record(self, plan: SamplePlan, flagged: bool) -> None:
        """The deep check's result: a clean check earns stake, a hit makes the source a suspect."""
        if not plan.sampled:
            return
        cfg = self.config
        with self.db.transaction() as db:
            row = db.execute("SELECT * FROM sources WHERE source=?", (plan.source,)).fetchone()
            if row is None:
                return
            if flagged:
                resume = row["status"] if row["status"] != "suspect" else row["resume_status"]
                db.execute("UPDATE sources SET checked=checked+1, flagged=flagged+1, status='suspect',"
                           " resume_status=? WHERE source=?", (resume, plan.source))
                event = ("source_suspect", {"source": plan.source, "was": row["status"]})
            else:
                status = row["status"]
                clean_since = row["clean_since_slash"] + 1
                stake = row["stake"]
                if status in ("probation", "trusted", "quarantined"):
                    stake = min(cfg.max_stake, stake + cfg.stake_per_check)
                needed = cfg.probation * (1 + row["slashes"])
                if status in ("probation", "quarantined") and clean_since >= needed:
                    status = "trusted"
                db.execute("UPDATE sources SET checked=checked+1, clean=clean+1, stake=?,"
                           " clean_since_slash=?, status=? WHERE source=?",
                           (stake, clean_since, status, plan.source))
                event = (("source_trusted", {"source": plan.source, "stake": stake})
                         if status == "trusted" and row["status"] != "trusted" else None)
        if event:
            self._audit(*event)

    def arbitrate(self, source: str, malicious: bool, reviewer: str, case_id: str = "") -> None:
        """A person ruled on content from *source*. Malicious: slash. Benign: clear the suspicion."""
        source = self.key(source)
        with self.db.transaction() as db:
            row = db.execute("SELECT * FROM sources WHERE source=?", (source,)).fetchone()
            if row is None:
                return
            if malicious:
                db.execute("UPDATE sources SET stake=0, slashes=slashes+1, clean_since_slash=0,"
                           " status='quarantined', resume_status='quarantined' WHERE source=?", (source,))
            elif row["status"] == "suspect":
                db.execute("UPDATE sources SET status=resume_status WHERE source=?", (source,))
            else:
                return
        self._audit("source_slashed" if malicious else "source_cleared",
                    {"source": source, "reviewer": reviewer, "case_id": case_id,
                     "stake_lost": row["stake"] if malicious else 0})

    def mark_suspect(self, source: str, reason: str = "") -> bool:
        """Check every item from *source* again until a person clears it (e.g. after a canary trip)."""
        source = self.key(source)
        with self.db.transaction() as db:
            row = db.execute("SELECT status FROM sources WHERE source=?", (source,)).fetchone()
            if row is None:
                return False
            if row["status"] != "suspect":
                db.execute("UPDATE sources SET resume_status=status, status='suspect' WHERE source=?", (source,))
        self._audit("source_suspect", {"source": source, "reason": reason})
        return True

    def get(self, source: str) -> Optional[Dict[str, Any]]:
        with self.db.transaction() as db:
            row = db.execute("SELECT * FROM sources WHERE source=?", (self.key(source),)).fetchone()
        return self._view(row) if row else None

    def list(self, limit: int = 200) -> List[Dict[str, Any]]:
        with self.db.transaction() as db:
            rows = list(db.execute("SELECT * FROM sources ORDER BY last_seen DESC LIMIT ?",
                                   (max(1, min(int(limit), 1000)),)))
        return [self._view(r) for r in rows]

    def _view(self, row: Any) -> Dict[str, Any]:
        out = dict(row)
        out.pop("resume_status", None)
        out["check_probability"] = round(
            1.0 if row["status"] != "trusted" else required_probability(row["stake"], self.config), 4)
        return out

    def _audit(self, event: str, data: Dict[str, Any]) -> None:
        if self.audit is not None:
            self.audit.append(event, data)

    def close(self) -> None:
        self.db.close()
