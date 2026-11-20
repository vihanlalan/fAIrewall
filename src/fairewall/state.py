"""Shared gateway state: sessions, kill-switch freezes and held approvals in the database.

Without this, each gateway process keeps its own copy: on Cloud Run, a session
tainted on one instance is clean on the next, a budget spent on one is fresh on
another, a freeze reaches one instance only, and pending approvals vanish on a
restart. With ``Firewall(state=GatewayState(url))`` every instance reads and
writes the same rows:

  * **Sessions.** Each request loads the session (taint, principal, spend,
    rate windows) fresh. Writes happen under a per-session lock, read-modify-
    write in one short transaction, so two instances can neither lose an update
    nor un-taint a session: taint is a union, budgets and rate windows are
    recomputed from the stored state plus this call.
  * **Freezes.** Stored once, read by every instance (cached for at most
    ``freeze_cache_s``, one second by default). If the database cannot be
    read, every call is treated as frozen: the kill switch fails closed.
  * **Approvals.** Held calls are rows. Approving is an atomic claim
    (``pending -> approved`` only if still pending and unexpired), so two
    reviewers on two instances get one decision.

No network call happens while a lock is held: detectors (Model Armor) run on a
snapshot, and only the short write afterwards takes the lock.
"""

from __future__ import annotations

import json
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict
from typing import Any, Callable, Dict, Iterator, List, Optional

from .approvals import (
    APPROVAL_ONLY_RULE, ApprovalError, ApprovalQueue, ApprovalRequest, ApprovalStatus, needs_human,
)
from .db import Database
from .firewall import redact
from .types import Action, Context, Decision, FirewallBlock, Principal

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY, principal TEXT NOT NULL DEFAULT '{}', taint TEXT NOT NULL DEFAULT '[]',
    rules TEXT NOT NULL DEFAULT '{}', updated REAL NOT NULL);
CREATE INDEX IF NOT EXISTS sessions_by_updated ON sessions (updated);
CREATE TABLE IF NOT EXISTS freezes (
    scope TEXT NOT NULL, target TEXT NOT NULL, reason TEXT NOT NULL, "by" TEXT NOT NULL,
    at REAL NOT NULL, PRIMARY KEY (scope, target));
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY, tool TEXT NOT NULL, arguments TEXT NOT NULL, session_id TEXT NOT NULL,
    principal_id TEXT NOT NULL, principal TEXT NOT NULL, reason TEXT NOT NULL,
    rule_ids TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL, status TEXT NOT NULL,
    decided_by TEXT, decided_at REAL, note TEXT NOT NULL DEFAULT '', executed INTEGER NOT NULL DEFAULT 0,
    case_id TEXT);
CREATE INDEX IF NOT EXISTS approvals_by_status ON approvals (status, created_at)
"""


class GatewayState:
    """The database tables every gateway instance shares."""

    def __init__(self, target: Any, *, session_ttl: float = 86400.0, freeze_cache_s: float = 1.0,
                 clock: Callable[[], float] = time.time) -> None:
        self.db = Database(target, schema="fairewall_gateway")
        self.db.create(_SCHEMA)
        self.session_ttl = session_ttl
        self.freeze_cache_s = freeze_cache_s
        self._clock = clock
        self._freeze_cache: Optional[List[Dict[str, Any]]] = None
        self._freeze_read = 0.0

    # --------------------------------------------------------------- sessions

    def load(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self.db.transaction(lock="session:" + session_id) as db:
            row = db.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
        return self._session_view(row) if row else None

    @contextmanager
    def edit(self, session_id: str) -> Iterator[Dict[str, Any]]:
        """Read-modify-write one session under its lock. Yields a dict to change in place."""
        with self.db.transaction(lock="session:" + session_id) as db:
            row = db.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
            state = self._session_view(row) if row else {"principal": None, "taint": [], "rules": {}}
            yield state
            db.execute(
                "INSERT INTO sessions (id, principal, taint, rules, updated) VALUES (?,?,?,?,?)"
                " ON CONFLICT(id) DO UPDATE SET principal=excluded.principal, taint=excluded.taint,"
                " rules=excluded.rules, updated=excluded.updated",
                (session_id, json.dumps(state.get("principal") or {}), json.dumps(state["taint"]),
                 json.dumps(state["rules"]), self._clock()))

    def forget(self, session_id: Optional[str] = None) -> None:
        with self.db.transaction() as db:
            if session_id is None:
                db.execute("DELETE FROM sessions")
            else:
                db.execute("DELETE FROM sessions WHERE id=?", (session_id,))

    def prune(self) -> int:
        with self.db.transaction() as db:
            cur = db.execute("DELETE FROM sessions WHERE updated < ?", (self._clock() - self.session_ttl,))
            return cur.rowcount or 0

    @staticmethod
    def _session_view(row: Any) -> Dict[str, Any]:
        principal = json.loads(row["principal"] or "{}")
        return {"principal": principal or None, "taint": json.loads(row["taint"]),
                "rules": json.loads(row["rules"])}

    # ---------------------------------------------------------------- freezes

    def freezes(self, fresh: bool = False) -> List[Dict[str, Any]]:
        now = time.monotonic()
        if not fresh and self._freeze_cache is not None and now - self._freeze_read < self.freeze_cache_s:
            return self._freeze_cache
        with self.db.transaction(lock="freezes") as db:
            rows = [dict(r) for r in db.execute("SELECT * FROM freezes ORDER BY at")]
        self._freeze_cache, self._freeze_read = rows, now
        return rows

    def put_freeze(self, record: Dict[str, Any]) -> Dict[str, Any]:
        with self.db.transaction(lock="freezes") as db:
            prior = db.execute("SELECT at FROM freezes WHERE scope=? AND target=?",
                               (record["scope"], record["target"])).fetchone()
            if prior:
                record = dict(record, at=prior["at"])
            db.execute('INSERT INTO freezes (scope, target, reason, "by", at) VALUES (?,?,?,?,?)'
                       ' ON CONFLICT(scope, target) DO UPDATE SET reason=excluded.reason, "by"=excluded."by"',
                       (record["scope"], record["target"], record["reason"], record["by"], record["at"]))
        self._freeze_cache = None
        return record

    def drop_freeze(self, scope: str, target: str) -> Optional[Dict[str, Any]]:
        with self.db.transaction(lock="freezes") as db:
            row = db.execute("SELECT * FROM freezes WHERE scope=? AND target=?", (scope, target)).fetchone()
            if row:
                db.execute("DELETE FROM freezes WHERE scope=? AND target=?", (scope, target))
        self._freeze_cache = None
        return dict(row) if row else None

    def close(self) -> None:
        self.db.close()


# ----------------------------------------------------------------- approvals

def _request(row: Any) -> ApprovalRequest:
    return ApprovalRequest(
        id=row["id"], tool=row["tool"], arguments=json.loads(row["arguments"]),
        session_id=row["session_id"], principal_id=row["principal_id"], reason=row["reason"],
        rule_ids=json.loads(row["rule_ids"]), created_at=row["created_at"],
        expires_at=row["expires_at"], status=ApprovalStatus(row["status"]),
        decided_by=row["decided_by"], decided_at=row["decided_at"], note=row["note"] or "",
        executed=bool(row["executed"]), case_id=row["case_id"])


class DurableApprovalQueue(ApprovalQueue):
    """The approval queue, kept in the gateway database.

    Same behaviour and API as ``ApprovalQueue``: what is held, the re-check on
    approval, no self-approval, audit records and learning labels. The
    difference is that requests survive restarts and every instance sees them.
    A held Python function (``run``) can only be executed by the process that
    holds it; the HTTP flow never holds one.
    """

    def __init__(self, firewall: Any, state: GatewayState, ttl_seconds: Optional[float] = 3600.0,
                 max_requests: int = 10_000, clock: Callable[[], float] = time.time) -> None:
        super().__init__(firewall, ttl_seconds=ttl_seconds, max_requests=max_requests, clock=clock)
        self.state = state
        self._functions: Dict[str, Callable[..., Any]] = {}

    @property
    def db(self) -> Database:
        return self.state.db

    def submit(self, tool: str, arguments: Dict[str, Any], ctx: Context, decision: Decision,
               fn: Optional[Callable[..., Any]] = None) -> ApprovalRequest:
        if not needs_human(decision):
            raise ValueError("Only calls that need a person can be queued; this one is %s"
                             % decision.action.value)
        now = self._clock()
        req = ApprovalRequest(
            id=uuid.uuid4().hex[:16], tool=tool, arguments=dict(arguments),
            session_id=ctx.session_id, principal_id=ctx.principal.id, reason=decision.reason,
            rule_ids=sorted({f.rule_id for f in decision.findings}), created_at=now,
            expires_at=(now + self.ttl_seconds) if self.ttl_seconds is not None else None,
            case_id=decision.case_id)
        self._expire()
        with self.db.transaction(lock="approvals") as db:
            pending = db.execute("SELECT COUNT(*) FROM approvals WHERE status='pending'").fetchone()[0]
            if pending >= self.max_requests:
                raise ApprovalError("Approval queue is full of pending requests; refusing to hold more.")
            db.execute(
                "INSERT INTO approvals (id, tool, arguments, session_id, principal_id, principal, reason,"
                " rule_ids, created_at, expires_at, status, case_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (req.id, tool, json.dumps(req.arguments, default=str), req.session_id,
                 req.principal_id, json.dumps(asdict(ctx.principal)), req.reason,
                 json.dumps(req.rule_ids), req.created_at, req.expires_at, "pending", req.case_id))
        if fn is not None:
            self._functions[req.id] = fn
        self._audit("approval_requested", req, {"arguments": redact(req.arguments)})
        return req

    def get(self, request_id: str) -> Optional[ApprovalRequest]:
        self._expire()
        with self.db.transaction(lock="approvals") as db:
            row = db.execute("SELECT * FROM approvals WHERE id=?", (request_id,)).fetchone()
        return _request(row) if row else None

    def list(self, status: Optional[ApprovalStatus] = None) -> List[ApprovalRequest]:
        self._expire()
        sql, args = "SELECT * FROM approvals", []
        if status is not None:
            sql += " WHERE status=?"
            args.append(status.value)
        with self.db.transaction(lock="approvals") as db:
            rows = list(db.execute(sql + " ORDER BY created_at", args))
        return [_request(r) for r in rows]

    def reject(self, request_id: str, reviewer: str, note: str = "") -> ApprovalRequest:
        reviewer = self._check_reviewer(reviewer)
        req = self._claim(request_id, ApprovalStatus.REJECTED, reviewer, note)
        self._functions.pop(req.id, None)
        self._audit("approval_rejected", req, {})
        self._teach(req, "malicious", reviewer, note)
        return req

    def _approve(self, request_id: str, reviewer: str, note: str):
        reviewer = self._check_reviewer(reviewer)
        current = self.get(request_id)
        if current is None:
            raise ApprovalError("No approval request with id %r." % request_id)
        if reviewer == current.principal_id:
            raise ApprovalError("A principal cannot approve its own request.")
        req = self._claim(request_id, ApprovalStatus.APPROVED, reviewer, note)

        fw = self.firewall
        with self.db.transaction(lock="approvals") as db:
            principal = json.loads(db.execute("SELECT principal FROM approvals WHERE id=?",
                                              (req.id,)).fetchone()[0])
        ctx = fw.session(req.session_id, Principal(**principal))
        with fw.session_lock(ctx.session_id):
            recheck = fw.inspect(req.tool, req.arguments, ctx=ctx)
            if recheck.blocked and not needs_human(recheck):
                hard = [f for f in recheck.findings
                        if f.action is Action.BLOCK and f.rule_id != APPROVAL_ONLY_RULE]
                why = "; ".join("[%s] %s" % (f.rule_id, f.message) for f in hard)
                req.status, req.decided_by = ApprovalStatus.REJECTED, "fairewall"
                req.note = "Approved by %s, but the policy now blocks it: %s" % (reviewer, why)
                with self.db.transaction(lock="approvals") as db:
                    db.execute("UPDATE approvals SET status='rejected', decided_by='fairewall', note=?"
                               " WHERE id=?", (req.note, req.id))
                self._functions.pop(req.id, None)
                self._audit("approval_rejected", req, {"recheck_reason": why, "approved_by": reviewer})
                self._teach(req, "benign", reviewer, note)
                return req, None

            self._audit("approval_granted", req, {})
            self._teach(req, "benign", reviewer, note)
            fn = self._functions.pop(req.id, None)
            if fn is None:
                return req, None
            result = fw._perform(req.tool, fn, req.arguments, ctx, recheck,
                                 extra={"approval_id": req.id, "approved_by": reviewer})
            req.executed = True
            with self.db.transaction(lock="approvals") as db:
                db.execute("UPDATE approvals SET executed=1 WHERE id=?", (req.id,))
            return req, result

    def _claim(self, request_id: str, status: ApprovalStatus, reviewer: str,
               note: str) -> ApprovalRequest:
        """pending -> decided, atomically. Exactly one caller wins, on any instance."""
        self._expire()
        now = self._clock()
        with self.db.transaction(lock="approvals") as db:
            cur = db.execute(
                "UPDATE approvals SET status=?, decided_by=?, decided_at=?, note=? WHERE id=?"
                " AND status='pending' AND (expires_at IS NULL OR expires_at > ?)",
                (status.value, reviewer, now, note, request_id, now))
            row = db.execute("SELECT * FROM approvals WHERE id=?", (request_id,)).fetchone()
        if row is None:
            raise ApprovalError("No approval request with id %r." % request_id)
        if cur.rowcount != 1:
            raise ApprovalError("Request %s is already %s." % (request_id, row["status"]))
        return _request(row)

    def _expire(self) -> None:
        now = self._clock()
        with self.db.transaction(lock="approvals") as db:
            rows = list(db.execute("SELECT * FROM approvals WHERE status='pending' AND expires_at IS NOT NULL"
                                   " AND expires_at <= ?", (now,)))
            for r in rows:
                db.execute("UPDATE approvals SET status='expired', decided_at=? WHERE id=? AND status='pending'",
                           (now, r["id"]))
        for r in rows:
            req = _request(r)
            req.status, req.decided_at = ApprovalStatus.EXPIRED, now
            self._functions.pop(req.id, None)
            self._audit("approval_expired", req, {})


def build_gateway_firewall(*, policy: Any, database: Optional[str] = None,
                           audit_path: Optional[str] = None, learning: Optional[str] = None,
                           source_sampling: bool = False, shadow: bool = False,
                           detectors: Any = None, kill_switch_path: Optional[str] = None,
                           action_baseline: Optional[str] = None,
                           canaries: Optional[bool] = None) -> Any:
    """The firewall a gateway runs, from flags or environment.

    ``database`` (FAIREWALL_DATABASE_URL): a SQLite file or postgresql:// URL.
    With it, sessions, freezes, held approvals and the audit chain are shared by
    every instance, and learning uses it too unless ``learning`` names another.
    Without it, everything stays in this process, as before.
    """
    import os

    from .audit import AuditLog
    from .firewall import Firewall
    from .learning import build_adaptive

    database = database or os.environ.get("FAIREWALL_DATABASE_URL") or None
    learning = learning or os.environ.get("FAIREWALL_LEARNING_DB") or database
    source_sampling = source_sampling or os.environ.get(
        "FAIREWALL_SOURCE_SAMPLING", "").lower() in ("1", "true")
    if source_sampling and not learning:
        raise ValueError("Source sampling needs a database (--database or --learning-db) "
                         "to keep source trust in.")
    if database:
        audit = AuditLog(store=database, log_id=os.environ.get("FAIREWALL_AUDIT_LOG_ID") or None)
    else:
        audit = AuditLog(path=audit_path) if audit_path else AuditLog()
    memory, sampler = build_adaptive(learning, source_sampling)

    # Defences against attacks no detector recognises. Stored with the shared
    # state when there is one; otherwise in memory for this process.
    mode = action_baseline or os.environ.get("FAIREWALL_ACTION_BASELINE") or ""
    baseline = None
    if mode:
        from .baseline import ActionBaseline
        baseline = ActionBaseline(database or ":memory:", hold_when=mode)
    if canaries is None:
        canaries = os.environ.get("FAIREWALL_CANARIES", "").lower() in ("1", "true")
    registry = None
    if canaries:
        from .canary import CanaryRegistry
        registry = CanaryRegistry(database or ":memory:",
                                  email_domain=os.environ.get("FAIREWALL_CANARY_DOMAIN", "example.com"))
    return Firewall(policy=policy, audit=audit, shadow=shadow, detectors=detectors,
                    kill_switch_path=None if database else (
                        kill_switch_path or os.environ.get("FAIREWALL_KILL_SWITCH_FILE")),
                    memory=memory, sampler=sampler, baseline=baseline, canaries=registry,
                    state=GatewayState(database) if database else None)


def queue_for(firewall: Any) -> ApprovalQueue:
    """The approval queue that matches the firewall: durable when its state is shared."""
    state = getattr(firewall, "state", None)
    return DurableApprovalQueue(firewall, state) if state is not None else ApprovalQueue(firewall)


__all__ = ["GatewayState", "DurableApprovalQueue", "build_gateway_firewall", "queue_for"]
