"""Adaptive threat memory: unseen threats go to a person, and fAIrewall learns the answer.

The rules and detectors are fixed; attacks are not. This module closes the loop:

  1. **Notice.** Every escalated event that carries a threat signal (a content
     rule flagged it, a detector scored it, Model Armor caught it) is compared
     with every case a human has already judged. If nothing similar has been
     judged, it is a *novel* threat: the event is flagged ``adaptive.novel_threat``,
     a case is opened, and a person decides (a held tool call waits in the
     approval queue; inbound content is flagged and its case waits for a label).
  2. **Learn.** The person's decision becomes a labelled case. Approving or
     rejecting a held call labels its case automatically; inbound cases are
     labelled from the review endpoint. Each label updates two things: an
     exemplar memory (nearest-neighbour over hashed character and word n-grams,
     robust to typos and look-alike letters) and a small logistic-regression
     model trained on every label so far. Neither is an LLM: both are pure
     Python, deterministic and explainable (each verdict names the case and
     reviewer it came from).
  3. **Adapt.** Next time something similar arrives, the memory acts without
     waking anyone:
       * close to a case a person called malicious -> BLOCK
         (``adaptive.learned_threat``), even if no rule or detector fires;
       * the model is confident it is malicious -> FLAG or BLOCK (``adaptive.model``);
       * close to several cases people approved, for the same reasons -> the
         content-threat flags those people already overruled are lifted
         (``adaptive.learned_allow``), so reviewers stop seeing repeats.

Safety, because a system that learns can be taught the wrong thing:

  * Learning tightens freely but loosens almost never. A learned block needs
    one human "malicious". A learned allow needs ``min_allow_votes`` human
    approvals of near-identical content (similarity >= ``allow_similarity``),
    no malicious case nearby, and covers only the exact content-threat rules
    those people saw and overruled.
  * A learned allow never lifts a BLOCK, never touches business rules (spend
    caps, rate limits, schemas, egress, required approvals, the kill switch),
    never touches a fail-closed detector error, and by default never applies
    to high-risk tools. Taint is untouched: a tainted session still cannot
    reach tools fenced off from untrusted content.
  * Only an authenticated reviewer can label. A principal cannot label its own
    request. Every case, label and revocation is written to the hash-chained
    audit log with the reviewer's name, and any label can be revoked, which
    retrains from the remaining labels. Learned allows expire (``allow_ttl_s``).
  * Labels live in a database (SQLite or Postgres), so every gateway instance
    sharing it learns from every reviewer, and a restart forgets nothing.

Honest limits: similarity over n-grams recognises variants of what a person
has seen (rewording, typos, homoglyphs, padding), not an attack of a wholly
new kind; that is still the job of the detectors, which is why their weak
signals feed novelty detection. And a learning system is only as good as its
reviewers' labels; revocation exists for when they are wrong.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import threading
import time
import unicodedata
import uuid
import zlib
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .db import Database
from .rules.injection import _normalize as _strip_invisible
from .types import Action, Finding, Severity

Vector = Dict[int, float]

# Signals this module may learn from (and, for FLAGs only, learn to lift).
# Everything else -- money, rate, schema, egress, approvals, kill switch -- is
# policy, not threat detection, and is never learned away.
LEARNABLE_PREFIXES = ("injection.", "output.", "detector.", "payload.", "adaptive.", "sampling.")
NOT_LEARNABLE = {"output.secret_redacted", "output.pii_redacted", "output.bulk_pii",
                 "injection.oversize_input", "adaptive.learned_allow"}

# Flags that count as signals but that a learned allow may never lift: the
# quarantine penalty, and the memory's own warnings.
NOT_LIFTABLE = {"sampling.quarantined_source", "adaptive.near_known_threat", "adaptive.model",
                "adaptive.novel_threat"}

VERDICTS = ("malicious", "benign")
_DIM_BITS = 20
_MASK = (1 << _DIM_BITS) - 1
_MAX_TEXT = 20_000
_LEET = str.maketrans("0134578@$|!", "oieastbasii")
_WORD = re.compile(r"\w+", re.UNICODE)


def learnable(finding: Finding) -> bool:
    rid = finding.rule_id
    return (rid.startswith(LEARNABLE_PREFIXES) and rid not in NOT_LEARNABLE
            and not rid.endswith(".error"))


# ------------------------------------------------------------------ features

def _h(token: str) -> int:
    # crc32 is stable across processes (Python's hash() is salted per run).
    return zlib.crc32(token.encode("utf-8", "surrogatepass")) & _MASK


def normalize_text(text: str) -> str:
    """Fold the disguises attackers use: width/compat forms, invisibles, case, spacing."""
    text = unicodedata.normalize("NFKC", text or "")[:_MAX_TEXT]
    text, _ = _strip_invisible(text)
    return re.sub(r"\s+", " ", text.casefold()).strip()


def featurize(text: str = "", *, tool: Optional[str] = None, arg_keys: Iterable[str] = (),
              rule_ids: Iterable[str] = (), kind: str = "") -> Vector:
    """A unit-length sparse vector for one event.

    Character 4-grams over a leetspeak-folded copy (so "1gn0re" ~ "ignore"),
    word unigrams and bigrams, plus structural tokens: the kind of event, the
    tool, argument names and which content rules fired.
    """
    norm = normalize_text(text)
    counts: Dict[int, float] = {}

    def add(token: str, weight: float = 1.0) -> None:
        k = _h(token)
        counts[k] = counts.get(k, 0.0) + weight

    folded = " " + norm.translate(_LEET) + " "
    for i in range(len(folded) - 3):
        add("c:" + folded[i:i + 4])
    words = _WORD.findall(norm)
    for i, w in enumerate(words):
        add("w:" + w)
        if i:
            add("b:" + words[i - 1] + " " + w)
    if kind:
        add("kind:" + kind, 2.0)
    if tool:
        add("tool:" + tool, 3.0)
    for key in arg_keys:
        add("arg:" + str(key), 2.0)
    for rid in rule_ids:
        add("rule:" + rid, 2.0)
    if not counts:
        return {}
    vec = {k: 1.0 + math.log(v) if v >= 1 else v for k, v in counts.items()}
    norm2 = math.sqrt(sum(v * v for v in vec.values()))
    return {k: v / norm2 for k, v in vec.items()}


def cosine(a: Vector, b: Vector) -> float:
    if len(a) > len(b):
        a, b = b, a
    return sum(v * b.get(k, 0.0) for k, v in a.items())


def _top(vec: Vector, n: int) -> Vector:
    if len(vec) <= n:
        return vec
    keep = sorted(vec.items(), key=lambda kv: -abs(kv[1]))[:n]
    return dict(keep)


# --------------------------------------------------------------------- model

class LinearModel:
    """Logistic regression over the hashed features, refit from every label.

    Class-weighted, L2-regularised, trained by a fixed number of passes in a
    fixed order, so the same labels always give the same model.
    """

    def __init__(self) -> None:
        self.w: Dict[int, float] = {}
        self.b = 0.0
        self.n_pos = self.n_neg = 0

    def score(self, x: Vector) -> float:
        z = self.b + sum(v * self.w.get(k, 0.0) for k, v in x.items())
        return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))

    def fit(self, examples: Sequence[Tuple[Vector, int]], epochs: int = 12,
            lr: float = 0.5, l2: float = 1e-3) -> "LinearModel":
        self.w, self.b = {}, 0.0
        self.n_pos = sum(1 for _, y in examples if y == 1)
        self.n_neg = len(examples) - self.n_pos
        if not examples or not self.n_pos or not self.n_neg:
            return self
        weight = {1: len(examples) / (2.0 * self.n_pos), 0: len(examples) / (2.0 * self.n_neg)}
        for epoch in range(epochs):
            rate = lr / (1.0 + epoch)
            for x, y in examples:
                g = (self.score(x) - y) * weight[y]
                self.b -= rate * g
                for k, v in x.items():
                    w = self.w.get(k, 0.0)
                    self.w[k] = w - rate * (g * v + l2 * w)
        return self


# --------------------------------------------------------------------- types

@dataclass
class LearningConfig:
    known_similarity: float = 0.60     # below this to every judged case -> "never seen"
    block_similarity: float = 0.80     # this close to a malicious case -> BLOCK
    conflict_similarity: float = 0.60  # a malicious case this close vetoes any learned allow
    allow_similarity: float = 0.92     # approvals must be this close to lift a flag
    min_allow_votes: int = 2           # human approvals needed before flags are lifted
    distinct_reviewers: bool = False   # require those approvals from different people
    allow_high_risk: bool = False      # may learned allows apply to high-risk tools?
    auto_allow: bool = True
    allow_ttl_s: float = 30 * 86400.0  # approvals older than this stop counting
    weak_signal: float = 0.30          # detector score that counts as a (weak) signal
    model_min_examples: int = 8
    model_min_per_class: int = 3
    model_flag: float = 0.70
    model_block: float = 0.90
    max_cases: int = 5000              # judged cases kept in the live index
    pending_ttl_s: float = 7 * 86400.0
    max_pending: int = 10_000
    refresh_s: float = 2.0             # how often to pick up labels from other instances
    excerpt_chars: int = 400


@dataclass
class Case:
    id: str
    kind: str
    status: str                 # pending | labeled | revoked | expired
    created: float
    vector: Vector
    rule_ids: List[str]
    source: str = ""
    tool: str = ""
    principal: str = ""
    session: str = ""
    excerpt: str = ""
    signals: Dict[str, Any] = field(default_factory=dict)
    label: Optional[str] = None
    reviewer: Optional[str] = None
    note: str = ""
    labeled_at: Optional[float] = None
    via: str = ""

    def view(self) -> Dict[str, Any]:
        return {"case_id": self.id, "kind": self.kind, "status": self.status,
                "created_at": self.created, "source": self.source, "tool": self.tool,
                "principal": self.principal, "session_id": self.session,
                "excerpt": self.excerpt, "rule_ids": list(self.rule_ids),
                "signals": self.signals, "label": self.label, "reviewer": self.reviewer,
                "note": self.note, "labeled_at": self.labeled_at, "via": self.via}


@dataclass
class Assessment:
    """What the memory adds to a decision."""

    findings: List[Finding] = field(default_factory=list)
    lift: Set[str] = field(default_factory=set)   # FLAG rule_ids a learned allow lifts
    case_id: Optional[str] = None
    novel: bool = False

    def apply(self, findings: List[Finding]) -> List[Finding]:
        """The decision's findings after learning: lifted flags become ALLOW, never BLOCKs."""
        out = []
        for f in findings:
            if (f.rule_id in self.lift and f.action is Action.FLAG and learnable(f)
                    and f.rule_id not in NOT_LIFTABLE):
                out.append(Finding(f.rule_id, Action.ALLOW, f.severity,
                                   f.message + " [cleared: people approved this before]",
                                   dict(f.evidence, learned_allow=True)))
            else:
                out.append(f)
        return out + self.findings


class LearningError(ValueError):
    """A label or revocation the memory refuses."""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY, kind TEXT NOT NULL, status TEXT NOT NULL, created REAL NOT NULL,
    digest TEXT NOT NULL, vector TEXT NOT NULL, rule_ids TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '', tool TEXT NOT NULL DEFAULT '',
    principal TEXT NOT NULL DEFAULT '', session TEXT NOT NULL DEFAULT '',
    excerpt TEXT NOT NULL DEFAULT '', signals TEXT NOT NULL DEFAULT '{}',
    label TEXT, reviewer TEXT, note TEXT NOT NULL DEFAULT '', labeled_at REAL,
    via TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS cases_by_status ON cases (status, created);
CREATE INDEX IF NOT EXISTS cases_by_digest ON cases (digest, status);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)
"""


class _Index:
    """Judged cases with an inverted index for nearest-neighbour search."""

    def __init__(self, cases: List[Case]) -> None:
        self.cases = cases
        self.postings: Dict[int, List[int]] = {}
        for i, c in enumerate(cases):
            for k in c.vector:
                self.postings.setdefault(k, []).append(i)
        self.has_malicious = any(c.label == "malicious" for c in cases)

    def search(self, vec: Vector, k: int = 12, candidates: int = 64) -> List[Tuple[float, Case]]:
        if not self.cases or not vec:
            return []
        if len(self.cases) <= 256:
            pool = range(len(self.cases))
        else:
            # Shortlist by the rarest shared features, then score exactly.
            rare_cut = max(32, len(self.cases) // 10)
            partial: Dict[int, float] = {}
            for f, v in vec.items():
                post = self.postings.get(f)
                if post and len(post) <= rare_cut:
                    for i in post:
                        partial[i] = partial.get(i, 0.0) + v * self.cases[i].vector[f]
            pool = [i for i, _ in sorted(partial.items(), key=lambda kv: -kv[1])[:candidates]]
        scored = [(cosine(vec, self.cases[i].vector), self.cases[i]) for i in pool]
        scored.sort(key=lambda sc: -sc[0])
        return scored[:k]


def build_adaptive(target: Any, source_sampling: bool = False):
    """(memory, sampler) on one database target, for a gateway. Either may be None."""
    if not target:
        return None, None
    memory = ThreatMemory(target)
    sampler = None
    if source_sampling:
        from .sampling import SourceSampler
        sampler = SourceSampler(target)
    return memory, sampler


class ThreatMemory:
    """Cases, labels, the exemplar index and the model. Thread-safe; shareable across instances."""

    def __init__(self, target: Any, *, config: Optional[LearningConfig] = None,
                 audit: Any = None, clock: Callable[[], float] = time.time) -> None:
        self.config = config or LearningConfig()
        self.audit = audit
        self._clock = clock
        self.db = Database(target, schema="fairewall_learning")
        self.db.create(_SCHEMA)
        self._lock = threading.RLock()
        self._index = _Index([])
        self._model = LinearModel()
        self._model_ready = False
        self._generation: Optional[str] = None
        self._checked = 0.0
        # Called as hook(case, verdict) after a label is recorded (e.g. source sampling).
        self.on_label: List[Callable[[Case, str], None]] = []
        self._refresh(force=True)

    # ------------------------------------------------------------- assessing

    def assess(self, *, kind: str, text: str = "", findings: Sequence[Finding] = (),
               scores: Sequence[Tuple[str, float]] = (), tool: str = "",
               arg_keys: Iterable[str] = (), source: str = "", high_risk: bool = False,
               session: str = "", principal: str = "", excerpt: str = "") -> Assessment:
        cfg = self.config
        signals = [f for f in findings if learnable(f) and f.action in (Action.FLAG, Action.BLOCK)]
        weak = [(n, s) for n, s in scores if s >= cfg.weak_signal]
        self._refresh()
        index, model, model_ready = self._index, self._model, self._model_ready
        if not signals and not weak and not index.has_malicious and not model_ready:
            return Assessment()

        rule_ids = sorted({f.rule_id for f in signals})
        vec = featurize(text, tool=tool or None, arg_keys=arg_keys, kind=kind)
        neighbours = index.search(vec)
        live = [(s, c) for s, c in neighbours if self._counts(c)]
        best_any = max((s for s, _ in live), default=0.0)
        malicious = [(s, c) for s, c in live if c.label == "malicious"]
        best_mal, mal_case = max(malicious, key=lambda sc: sc[0], default=(0.0, None))
        out: List[Finding] = []

        # 1. Seen before and judged malicious: block, no matter what else fired.
        if mal_case is not None and best_mal >= cfg.block_similarity:
            out.append(Finding(
                "adaptive.learned_threat", Action.BLOCK, Severity.HIGH,
                "Matches a threat a reviewer confirmed (case %s, %.0f%% similar)."
                % (mal_case.id, best_mal * 100),
                {"case_id": mal_case.id, "similarity": round(best_mal, 3),
                 "confirmed_by": mal_case.reviewer, "confirmed_at": mal_case.labeled_at}))

        # 2. The model, trained on every label so far. It can only add friction.
        model_p = None
        if model_ready and vec:
            model_p = model.score(vec)
            if model_p >= cfg.model_block:
                out.append(Finding("adaptive.model", Action.BLOCK, Severity.HIGH,
                                   "The learned threat model scores this %.2f." % model_p,
                                   {"probability": round(model_p, 3)}))
            elif model_p >= cfg.model_flag:
                out.append(Finding("adaptive.model", Action.FLAG, Severity.MEDIUM,
                                   "The learned threat model scores this %.2f; a person should look."
                                   % model_p, {"probability": round(model_p, 3)}))

        if not signals and not weak and not out:
            return Assessment()
        if any(f.action is Action.BLOCK for f in list(findings) + out):
            # Already blocked by policy or by memory: nothing for a person to decide.
            return Assessment(findings=out)

        flags = [f for f in signals if f.action is Action.FLAG]
        model_flagged = any(f.rule_id == "adaptive.model" for f in out)

        # 3. Learned allow: people approved near-identical content for the same reasons.
        if (flags and cfg.auto_allow and not model_flagged
                and not any(f.rule_id in NOT_LIFTABLE for f in flags)
                and (cfg.allow_high_risk or not high_risk)
                and best_mal < cfg.conflict_similarity):
            support = [c for s, c in live if c.label == "benign" and s >= cfg.allow_similarity
                       and (self._clock() - (c.labeled_at or 0)) <= cfg.allow_ttl_s]
            votes = len({c.reviewer for c in support}) if cfg.distinct_reviewers else len(support)
            overruled = set().union(*(set(c.rule_ids) for c in support)) if support else set()
            if votes >= cfg.min_allow_votes and all(f.rule_id in overruled for f in flags):
                out.append(Finding(
                    "adaptive.learned_allow", Action.ALLOW, Severity.INFO,
                    "Reviewers approved this %d time(s) before (cases %s); flags %s cleared."
                    % (votes, ", ".join(c.id for c in support[:5]),
                       ", ".join(sorted(f.rule_id for f in flags))),
                    {"cases": [c.id for c in support[:10]], "votes": votes,
                     "lifted": sorted({f.rule_id for f in flags})}))
                return Assessment(findings=out, lift={f.rule_id for f in flags})

        # 4. Never seen anything like it: a person decides, and we learn.
        novel = best_any < cfg.known_similarity
        if novel:
            out.append(Finding(
                "adaptive.novel_threat", Action.FLAG, Severity.MEDIUM,
                "A possible threat unlike anything reviewed before; a person must decide, "
                "and fAIrewall will learn from the decision.",
                {"nearest_similarity": round(best_any, 3),
                 "signals": rule_ids + ["%s:%.2f" % w for w in weak]}))
        elif mal_case is not None and best_mal >= cfg.conflict_similarity:
            out.append(Finding(
                "adaptive.near_known_threat", Action.FLAG, Severity.MEDIUM,
                "Resembles a confirmed threat (case %s, %.0f%% similar); a person should look."
                % (mal_case.id, best_mal * 100),
                {"case_id": mal_case.id, "similarity": round(best_mal, 3)}))

        needs_person = flags or any(f.action is Action.FLAG for f in out)
        if not needs_person:
            return Assessment(findings=out)
        all_rules = sorted(set(rule_ids) | {f.rule_id for f in out if f.action is Action.FLAG})
        case_id = self._open_case(
            kind=kind, text=text, vec=vec, rule_ids=all_rules, source=source, tool=tool,
            principal=principal, session=session, excerpt=excerpt, arg_keys=arg_keys,
            signals={"weak": [[n, round(s, 3)] for n, s in weak],
                     "nearest_similarity": round(best_any, 3), "novel": novel,
                     "model_probability": None if model_p is None else round(model_p, 3)})
        for f in out:
            if f.action is Action.FLAG:
                f.evidence["case_id"] = case_id
        return Assessment(findings=out, case_id=case_id, novel=novel)

    def _counts(self, case: Case) -> bool:
        return case.status == "labeled" and case.label in VERDICTS

    # ----------------------------------------------------------------- cases

    @staticmethod
    def _digest(kind: str, text: str, tool: str, source: str, arg_keys: Iterable[str]) -> str:
        raw = json.dumps([kind, normalize_text(text), tool, source, sorted(map(str, arg_keys))])
        return hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()

    def _open_case(self, *, kind, text, vec, rule_ids, source, tool, principal, session,
                   excerpt, arg_keys, signals) -> str:
        """Open a pending case, or return the pending one for the same event."""
        digest = self._digest(kind, text, tool, source, arg_keys)
        now = self._clock()
        with self.db.transaction() as db:
            row = db.execute("SELECT id FROM cases WHERE digest=? AND status='pending'",
                             (digest,)).fetchone()
            if row:
                return row["id"]
            case_id = "case_" + uuid.uuid4().hex[:16]
            db.execute(
                "INSERT INTO cases (id, kind, status, created, digest, vector, rule_ids, source, tool,"
                " principal, session, excerpt, signals) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (case_id, kind, "pending", now, digest,
                 json.dumps({str(k): round(v, 6) for k, v in vec.items()}),
                 json.dumps(rule_ids), source[:200], tool[:200], principal[:200], session[:200],
                 excerpt[: self.config.excerpt_chars], json.dumps(signals)))
            self._prune(db, now)
        self._audit("learning_case_opened", {"case_id": case_id, "kind": kind, "tool": tool,
                                             "source": source, "rule_ids": rule_ids,
                                             "novel": signals.get("novel")})
        return case_id

    def _prune(self, db: Any, now: float) -> None:
        db.execute("UPDATE cases SET status='expired' WHERE status='pending' AND created<?",
                   (now - self.config.pending_ttl_s,))
        n = db.execute("SELECT COUNT(*) FROM cases WHERE status='pending'").fetchone()[0]
        if n > self.config.max_pending:
            db.execute("UPDATE cases SET status='expired' WHERE id IN (SELECT id FROM cases"
                       " WHERE status='pending' ORDER BY created LIMIT ?)", (n - self.config.max_pending,))

    def label(self, case_id: str, verdict: str, reviewer: str, note: str = "",
              via: str = "review") -> Dict[str, Any]:
        """Record a person's verdict and learn from it. ``verdict``: malicious or benign."""
        verdict = (verdict or "").strip().lower()
        reviewer = (reviewer or "").strip()
        if verdict not in VERDICTS:
            raise LearningError("verdict must be 'malicious' or 'benign'.")
        if not reviewer:
            raise LearningError("A reviewer is required, so the audit log shows who taught fAIrewall.")
        now = self._clock()
        with self.db.transaction() as db:
            row = db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
            if row is None:
                raise LearningError("No case %s." % case_id)
            if row["status"] != "pending":
                raise LearningError("Case %s is %s; revoke a label before relabelling."
                                    % (case_id, row["status"]))
            if row["principal"] and reviewer == row["principal"]:
                raise LearningError("A principal cannot label its own case.")
            db.execute("UPDATE cases SET status='labeled', label=?, reviewer=?, note=?, labeled_at=?,"
                       " via=? WHERE id=? AND status='pending'",
                       (verdict, reviewer[:100], (note or "")[:500], now, via[:100], case_id))
            self._bump(db)
        case = self.get(case_id)
        self._refresh(force=True)
        self._audit("learning_case_labeled", {"case_id": case_id, "verdict": verdict,
                                              "reviewer": reviewer, "via": via,
                                              "rule_ids": case.rule_ids, "source": case.source})
        for hook in list(self.on_label):
            try:
                hook(case, verdict)
            except Exception:  # a broken hook must not undo a recorded label
                pass
        return case.view()

    def revoke(self, case_id: str, reviewer: str, reason: str = "") -> Dict[str, Any]:
        """Withdraw a label (it was wrong). The memory and model retrain without it."""
        reviewer = (reviewer or "").strip()
        if not reviewer:
            raise LearningError("A reviewer is required.")
        with self.db.transaction() as db:
            row = db.execute("SELECT status FROM cases WHERE id=?", (case_id,)).fetchone()
            if row is None or row["status"] != "labeled":
                raise LearningError("Only a labelled case can be revoked.")
            db.execute("UPDATE cases SET status='revoked', note=? WHERE id=?",
                       (("Revoked by %s: %s" % (reviewer, reason or ""))[:500], case_id))
            self._bump(db)
        self._refresh(force=True)
        self._audit("learning_label_revoked", {"case_id": case_id, "reviewer": reviewer,
                                               "reason": (reason or "")[:500]})
        return self.get(case_id).view()

    def get(self, case_id: str) -> Case:
        with self.db.transaction() as db:
            row = db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if row is None:
            raise LearningError("No case %s." % case_id)
        return self._case(row)

    def cases(self, status: Optional[str] = "pending", limit: int = 100) -> List[Dict[str, Any]]:
        sql, args = "SELECT * FROM cases", []
        if status:
            sql += " WHERE status=?"
            args.append(status)
        sql += " ORDER BY created DESC LIMIT ?"
        args.append(max(1, min(int(limit), 1000)))
        with self.db.transaction() as db:
            rows = list(db.execute(sql, args))
        return [self._case(r).view() for r in rows]

    def stats(self) -> Dict[str, Any]:
        with self.db.transaction() as db:
            rows = list(db.execute("SELECT status, label, COUNT(*) AS n FROM cases GROUP BY status, label"))
        counts: Dict[str, int] = {}
        for r in rows:
            key = r["status"] + (":" + r["label"] if r["label"] else "")
            counts[key] = r["n"]
        cfg = self.config
        return {"cases": counts, "judged_in_memory": len(self._index.cases),
                "model": {"trained": self._model_ready, "malicious_examples": self._model.n_pos,
                          "benign_examples": self._model.n_neg},
                "thresholds": {"novel_below": cfg.known_similarity, "block_at": cfg.block_similarity,
                               "allow_at": cfg.allow_similarity, "allow_votes": cfg.min_allow_votes,
                               "allow_high_risk": cfg.allow_high_risk}}

    # --------------------------------------------------------------- internals

    @staticmethod
    def _case(row: Any) -> Case:
        return Case(id=row["id"], kind=row["kind"], status=row["status"], created=row["created"],
                    vector={int(k): float(v) for k, v in json.loads(row["vector"]).items()},
                    rule_ids=json.loads(row["rule_ids"]), source=row["source"], tool=row["tool"],
                    principal=row["principal"], session=row["session"], excerpt=row["excerpt"],
                    signals=json.loads(row["signals"] or "{}"), label=row["label"],
                    reviewer=row["reviewer"], note=row["note"] or "", labeled_at=row["labeled_at"],
                    via=row["via"] or "")

    @staticmethod
    def _bump(db: Any) -> None:
        db.execute("INSERT INTO meta VALUES ('generation', ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                   (uuid.uuid4().hex,))

    def _refresh(self, force: bool = False) -> None:
        """Reload judged cases when any instance has labelled or revoked since we last looked."""
        now = time.monotonic()
        if not force and now - self._checked < self.config.refresh_s:
            return
        with self._lock:
            if not force and now - self._checked < self.config.refresh_s:
                return
            self._checked = now
            with self.db.transaction() as db:
                row = db.execute("SELECT v FROM meta WHERE k='generation'").fetchone()
                generation = row["v"] if row else ""
                if generation == self._generation and not force:
                    return
                rows = list(db.execute(
                    "SELECT * FROM cases WHERE status='labeled' ORDER BY labeled_at DESC LIMIT ?",
                    (self.config.max_cases,)))
            cases = [self._case(r) for r in rows]
            model = LinearModel().fit([(_top(c.vector, 400), 1 if c.label == "malicious" else 0)
                                       for c in sorted(cases, key=lambda c: c.id)])
            cfg = self.config
            self._index = _Index(cases)
            self._model = model
            self._model_ready = (model.n_pos + model.n_neg >= cfg.model_min_examples
                                 and min(model.n_pos, model.n_neg) >= cfg.model_min_per_class)
            self._generation = generation

    def _audit(self, event: str, data: Dict[str, Any]) -> None:
        if self.audit is not None:
            self.audit.append(event, data)

    def close(self) -> None:
        self.db.close()
