"""Durable dispatch for registered business actions. The database is the release authority.

SQLite (a file path) or Postgres (a postgresql:// URL, e.g. Cloud SQL); see fairewall.db.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from types import MappingProxyType
from typing import Any, Callable

from jsonschema import Draft202012Validator
from referencing import Registry

from .approvals import ApprovalError, needs_human
from .db import Database
from .firewall import Firewall
from .rules import FinancialRule, VelocityRule
from .types import Context, Principal, Trust


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


# On Postgres a trailing BIGSERIAL "seq" column orders rows by insertion
# (SQLite uses its rowid).
_SCHEMA = """
CREATE TABLE IF NOT EXISTS actions (
    id TEXT PRIMARY KEY, principal TEXT, session TEXT, token TEXT,
    tool TEXT, args TEXT, fingerprint TEXT, status TEXT, rules TEXT,
    expires REAL, reviewer TEXT, result TEXT, policy_hash TEXT, definition TEXT, generation INTEGER,
    UNIQUE(principal, token));
CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pins (server TEXT, tool TEXT, fingerprint TEXT, PRIMARY KEY(server, tool));
CREATE TABLE IF NOT EXISTS reconciliations (
    action_id TEXT PRIMARY KEY, operator TEXT NOT NULL, reference TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS action_events
    (action_id TEXT, status TEXT, reviewer TEXT, policy_hash TEXT, at TEXT);
CREATE TABLE IF NOT EXISTS definition_reviews
    (tool TEXT, server TEXT, fingerprint TEXT, reviewer TEXT, at TEXT);
CREATE TABLE IF NOT EXISTS registry
    (tool TEXT PRIMARY KEY, fingerprint TEXT, generation INTEGER NOT NULL)
"""

# Every status change is recorded by the database itself, so no code path can
# change a status without leaving an event.
_SQLITE_TRIGGERS = ";;".join(
    f"""CREATE TRIGGER IF NOT EXISTS action_event_{name}
        AFTER {operation} ON actions {clause} BEGIN
        INSERT INTO action_events VALUES (NEW.id, NEW.status, NEW.reviewer,
            NEW.policy_hash, strftime('%Y-%m-%dT%H:%M:%fZ','now')); END"""
    for name, operation, clause in (("insert", "INSERT", ""),
                                    ("update", "UPDATE OF status", "WHEN NEW.status != OLD.status")))

_PG_TRIGGER = """
ALTER TABLE actions ADD COLUMN IF NOT EXISTS seq BIGSERIAL;
ALTER TABLE action_events ADD COLUMN IF NOT EXISTS seq BIGSERIAL;
CREATE OR REPLACE FUNCTION action_event() RETURNS trigger AS $fw$
BEGIN
    IF TG_OP = 'INSERT' OR NEW.status IS DISTINCT FROM OLD.status THEN
        INSERT INTO action_events (action_id, status, reviewer, policy_hash, at)
        VALUES (NEW.id, NEW.status, NEW.reviewer, NEW.policy_hash,
                to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'));
    END IF;
    RETURN NULL;
END $fw$ LANGUAGE plpgsql;
CREATE OR REPLACE TRIGGER action_event AFTER INSERT OR UPDATE OF status ON actions
    FOR EACH ROW EXECUTE FUNCTION action_event();
"""

_UPSERT_PIN = ("INSERT INTO pins VALUES (?,?,?) ON CONFLICT(server, tool) "
               "DO UPDATE SET fingerprint=excluded.fingerprint")


def _utc_now():
    now = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + ".%03dZ" % (int(now * 1000) % 1000)


@dataclass(frozen=True)
class RegisteredAction:
    """Trusted application binding. Handler receives (arguments, idempotency_key)."""
    server: str
    _definition: str
    revision: str
    handler: Callable[[dict, str], Any]

    def __init__(self, server, definition, revision, handler):
        object.__setattr__(self, "server", server)
        object.__setattr__(self, "_definition", canonical(definition))
        object.__setattr__(self, "revision", revision)
        object.__setattr__(self, "handler", handler)

    @property
    def definition(self):
        return json.loads(self._definition)

    def fingerprint(self):
        data = canonical([self.server, self.definition, self.revision])
        return hashlib.sha256(data.encode()).hexdigest()


class ActionStore:
    """One SQLite database per application/policy domain, shared by its workers."""

    def __init__(self, path, policy, actions, *, audit=None, detectors=(), ttl=3600,
                 firewall_factory=None, on_decision=None):
        """``firewall_factory(principal)`` builds the Firewall each decision runs on, so a host
        can attach the full control set (memory, baseline, canaries, sampler, shared freezes).
        ``on_decision(phase, decision, request_id, session, principal)`` sees every decision
        where it is made: "screen", "submit", "review" (the re-check) and "output"."""
        if str(path) == ":memory:" or ttl <= 0:
            raise ValueError("Use a database file and positive approval TTL")
        self.path, self.policy, self.ttl = path, policy, ttl
        self.actions = {}
        self._validators = {}
        for action in actions:
            name = action.definition["name"]
            if not name or not action.server or not action.revision or name in self.actions:
                raise ValueError("Each action needs a unique tool name, server and revision")
            schema = action.definition["inputSchema"]
            Draft202012Validator.check_schema(schema)
            self.actions[name] = action
            # Resolve local schema references only.
            self._validators[name] = Draft202012Validator(schema, registry=Registry())
        self.actions = MappingProxyType(self.actions)
        self.audit, self.detectors = audit, detectors
        self.firewall_factory, self.on_decision = firewall_factory, on_decision
        # Per-thread timing of the last handler call, so callers can separate
        # fAIrewall's own overhead from the time the business system took.
        self._timing = threading.local()
        self.db = Database(path, schema="fairewall_actions")
        self.db.create(_SCHEMA, postgres_extra=_PG_TRIGGER, sqlite_extra=_SQLITE_TRIGGERS)
        with self.transaction() as db:
            previous = {r["tool"]: r["fingerprint"] for r in db.execute("SELECT * FROM registry")}
            for tool in set(previous) | set(self.actions):
                binding = self.actions.get(tool)
                digest = binding.fingerprint() if binding else None
                if digest != previous.get(tool):
                    db.execute("""INSERT INTO registry VALUES (?,?,1) ON CONFLICT(tool)
                        DO UPDATE SET fingerprint=excluded.fingerprint, generation=registry.generation+1""",
                               (tool, digest))
                    db.execute("DELETE FROM pins WHERE tool=?", (tool,))

    def transaction(self):
        """One write-locked transaction (see fairewall.db: serialized per store)."""
        return self.db.transaction()

    def close(self):
        """Close every connection this store opened (needed before deleting its files)."""
        self.db.close()

    def _runtime(self, db, session, principal):
        scope = canonical([principal.id, session])
        row = db.execute("SELECT state FROM sessions WHERE id=?", (scope,)).fetchone()
        state = json.loads(row[0]) if row else {}
        fw = (self.firewall_factory(principal) if self.firewall_factory is not None
              else Firewall(self.policy, audit=self.audit, detectors=self.detectors))
        ctx = Context(scope, principal)
        ctx.taint_sources = state.get("taint", [])
        ctx.tainted = bool(ctx.taint_sources)
        for rule in fw.rules:
            if isinstance(rule, (FinancialRule, VelocityRule)) or hasattr(rule, "snapshot_session"):
                rule.reset(scope)
                rule.restore_session(scope, state.get(rule.id))
        return fw, ctx

    def _notify(self, phase, decision, request_id, session, principal):
        if self.on_decision is not None:
            try:
                self.on_decision(phase, decision, request_id, session, principal)
            except Exception:  # a trace hook must never change an enforcement outcome
                pass

    def _save(self, db, fw, ctx):
        state = {"taint": ctx.taint_sources}
        for rule in fw.rules:
            if isinstance(rule, (FinancialRule, VelocityRule)) or hasattr(rule, "snapshot_session"):
                snap = rule.snapshot_session(ctx.session_id)
                if snap is not None:
                    state[rule.id] = snap
        db.execute("INSERT INTO sessions VALUES (?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state",
                   (ctx.session_id, canonical(state)))

    def screen(self, session, principal, text, source="intake", trust=Trust.UNTRUSTED):
        """Screen text entering the session. Untrusted text (the default) taints it."""
        with self.transaction() as db:
            fw, ctx = self._runtime(db, session, principal)
            decision = fw.inspect_input(text, trust=trust, ctx=ctx, source=source)
            self._save(db, fw, ctx)
        self._notify("screen", decision, None, session, principal)
        return decision

    def set_scope(self, session, principal, scope, *, widen=False, by=""):
        """Declare a run's scope (see fairewall.rules.scope) in this store's session state."""
        with self.transaction() as db:
            fw, ctx = self._runtime(db, session, principal)
            result = fw._scope_rule().set(ctx.session_id, scope, widen=widen, by=by)
            self._save(db, fw, ctx)
        return result

    def session_state(self, session, principal):
        """Taint and rule state of one session, as stored."""
        with self.transaction() as db:
            row = db.execute("SELECT state FROM sessions WHERE id=?",
                             (canonical([principal.id, session]),)).fetchone()
        return json.loads(row[0]) if row else {}

    @staticmethod
    def _view(row):
        data = dict(row)
        data.pop("seq", None)
        data["definition"] = json.loads(data["definition"])
        data["arguments"] = json.loads(data.pop("args"))
        data["principal"] = json.loads(data["principal"])
        data["rules"] = json.loads(data["rules"])
        data["result"] = json.loads(data["result"]) if data["result"] else None
        return data

    def get(self, request_id):
        with self.transaction() as db:
            db.execute("UPDATE actions SET status='expired' WHERE id=? AND status='pending' AND expires<=?",
                       (request_id, time.time()))
            row = db.execute("SELECT * FROM actions WHERE id=?", (request_id,)).fetchone()
            if not row:
                raise ApprovalError("Unknown action request")
            view = self._view(row)
            view["events"] = [dict(event) for event in db.execute(
                "SELECT status,reviewer,policy_hash,at FROM action_events WHERE action_id=? ORDER BY "
                + self.db.rowid,
                (request_id,))]
            receipt = db.execute("SELECT operator,reference FROM reconciliations WHERE action_id=?",
                                 (request_id,)).fetchone()
            if receipt:
                view["reconciliation"] = dict(receipt)
            return view

    def pending(self):
        with self.transaction() as db:
            rows = db.execute("SELECT * FROM actions WHERE status='pending' AND expires>? ORDER BY " + self.db.rowid,
                              (time.time(),))
            return [self._view(row) for row in rows]

    def find(self, principal_id, token):
        """The action bound to (principal, idempotency key), or None.

        Lets a caller recover the action after a handler raised mid-dispatch,
        when ``submit`` or ``review`` could not return the record.
        """
        with self.transaction() as db:
            row = db.execute("SELECT id FROM actions WHERE %s=? AND token=?" % self.db.json_text("principal", "id"),
                             (principal_id, token)).fetchone()
        return self.get(row["id"]) if row else None

    @property
    def last_handler_ms(self):
        """Milliseconds the last handler call on this thread took (0 if none ran)."""
        return getattr(self._timing, "handler_ms", 0.0)

    def pending_definitions(self):
        """Registered tool definitions not yet reviewed in their current form."""
        with self.transaction() as db:
            pins = {(r["server"], r["tool"]): r["fingerprint"] for r in db.execute("SELECT * FROM pins")}
        out = []
        for name, action in self.actions.items():
            if pins.get((action.server, name)) != action.fingerprint():
                out.append({"tool": name, "server": action.server, "revision": action.revision,
                            "fingerprint": action.fingerprint(), "definition": action.definition})
        return out

    def review_definition(self, tool, reviewer):
        """Approve a tool definition on its own, before any call uses it.

        Separate from approving a call: reviewing what a tool *is* must never
        be mistaken for approving what one call *does*. A definition that
        changes later is unpinned again by the registry and needs a new review.
        """
        if not reviewer or not reviewer.strip():
            raise ApprovalError("A reviewer is required")
        action = self.actions.get(tool)
        if action is None:
            raise ApprovalError("Unknown tool")
        with self.transaction() as db:
            current = db.execute("SELECT * FROM registry WHERE tool=?", (tool,)).fetchone()
            if not current or current["fingerprint"] != action.fingerprint():
                raise ApprovalError("Worker has an outdated tool definition")
            db.execute(_UPSERT_PIN, (action.server, tool, action.fingerprint()))
            db.execute("INSERT INTO definition_reviews VALUES (?,?,?,?,?)",
                       (tool, action.server, action.fingerprint(), reviewer.strip(), _utc_now()))
        return {"tool": tool, "fingerprint": action.fingerprint(), "reviewer": reviewer.strip()}

    def submit(self, tool, arguments, session, principal, token):
        if not session or not token or not principal.id or tool not in self.actions:
            raise ApprovalError("A registered action, session, principal and idempotency key are required")
        key = canonical(asdict(principal))
        args = canonical(arguments)
        action = self.actions[tool]
        with self.transaction() as db:
            prior = db.execute("SELECT * FROM actions WHERE %s=? AND token=?" % self.db.json_text("principal", "id"),
                               (principal.id, token)).fetchone()
            if prior:
                if (prior["args"], prior["tool"], prior["session"], prior["principal"]) != (args, tool, session, key):
                    raise ApprovalError("Idempotency key already bound to another action")
                request_id = prior["id"]
                dispatch = False
            else:
                binding = db.execute("SELECT * FROM registry WHERE tool=?", (tool,)).fetchone()
                if not binding or binding["fingerprint"] != action.fingerprint():
                    raise ApprovalError("Worker has an outdated tool definition")
                request_id = uuid.uuid4().hex
                db.execute("INSERT INTO actions (id, principal, session, token, tool, args, fingerprint,"
                           " status, rules, expires, reviewer, result, policy_hash, definition, generation)"
                           " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           (request_id, key, session, token, tool, args, action.fingerprint(),
                            "pending", "[]", time.time()+self.ttl, None, None, self.policy.fingerprint(),
                            canonical(dict(server=action.server, tool=action.definition, revision=action.revision)),
                            binding["generation"]))
                dispatch = self._evaluate(db, request_id, action, None)
        if dispatch:
            self._dispatch(request_id, action)
        return self.get(request_id)

    def review(self, request_id, reviewer, approve=True, *, current_principal=None):
        with self.transaction() as db:
            row = db.execute("SELECT * FROM actions WHERE id=?", (request_id,)).fetchone()
            if not row or row["status"] != "pending":
                raise ApprovalError("Action is unknown or already decided")
            if not reviewer.strip() or reviewer == json.loads(row["principal"])["id"]:
                raise ApprovalError("An independent reviewer is required")
            action = self.actions.get(row["tool"])
            dispatch = False
            if current_principal is not None and canonical(asdict(current_principal)) != row["principal"]:
                approve = False
            current = db.execute("SELECT * FROM registry WHERE tool=?", (row["tool"],)).fetchone()
            if row["expires"] <= time.time():
                status = "expired"
            elif not approve or current["generation"] != row["generation"]:
                status = "rejected"
            elif not action or action.fingerprint() != current["fingerprint"]:
                raise ApprovalError("Worker has an outdated tool definition")
            else:
                status = None
                dispatch = self._evaluate(db, request_id, action, reviewer)
            if status:
                db.execute("UPDATE actions SET status=?, reviewer=? WHERE id=?", (status, reviewer, request_id))
        if dispatch:
            self._dispatch(request_id, action)
        return self.get(request_id)

    def _evaluate(self, db, request_id, action, reviewer):
        row = db.execute("SELECT * FROM actions WHERE id=?", (request_id,)).fetchone()
        tool, args = row["tool"], json.loads(row["args"])
        principal = Principal(**json.loads(row["principal"]))
        fw, ctx = self._runtime(db, row["session"], principal)
        decision = fw.inspect(tool, args, ctx=ctx)
        self._notify("review" if reviewer else "submit", decision, request_id, row["session"], principal)
        rules = [f.rule_id for f in decision.findings]
        pin = db.execute("SELECT fingerprint FROM pins WHERE server=? AND tool=?",
                         (action.server, tool)).fetchone()
        changed = not pin or pin[0] != row["fingerprint"]
        if changed:
            rules.append("registry.definition_review")
        if not self._validators[tool].is_valid(args):
            rules.append("registry.invalid_arguments")
            status = "blocked"
        elif decision.blocked and not needs_human(decision):
            status = "blocked"
        elif not reviewer and (changed or needs_human(decision)):
            status = "pending"
        else:
            # Hold reservations through uncertain delivery. Serialize calls until the
            # previous result has been screened and any taint written back.
            busy = db.execute("""SELECT 1 FROM actions WHERE session=?
                AND %s=? AND status IN ('dispatching','uncertain')""" % self.db.json_text("principal", "id"),
                              (row["session"], principal.id)).fetchone()
            if busy:
                raise ApprovalError("Previous dispatch in this session awaits reconciliation")
            db.execute(_UPSERT_PIN, (action.server, tool, row["fingerprint"]))
            fw.commit(tool, args, ctx)
            self._save(db, fw, ctx)
            status = "dispatching"
        db.execute("UPDATE actions SET status=?,rules=?,reviewer=?,policy_hash=? WHERE id=?",
                   (status, canonical(rules), reviewer, self.policy.fingerprint(), request_id))
        return status == "dispatching"

    def _dispatch(self, request_id, action):
        row = self.get(request_id)
        started = time.perf_counter()
        self._timing.handler_ms = 0.0
        try:
            try:
                result = action.handler(row["arguments"], request_id)
            finally:
                self._timing.handler_ms = (time.perf_counter() - started) * 1000
            with self.transaction() as db:
                self._finish(db, row, result)
        except Exception:
            with self.transaction() as db:
                db.execute("UPDATE actions SET status='uncertain' WHERE id=? AND status='dispatching'",
                           (request_id,))
            raise

    def reconcile(self, request_id, operator, reference, *, executed, result=None):
        """Record the verified downstream outcome after the dispatch worker has stopped.

        A confirmed non-execution retains the conservative budget reservation.
        This operator API never calls the downstream handler.
        """
        if not operator.strip() or not reference.strip() or not isinstance(executed, bool):
            raise ApprovalError("Reconciliation needs an operator, external receipt and outcome")
        with self.transaction() as db:
            record = db.execute("SELECT * FROM actions WHERE id=?", (request_id,)).fetchone()
            if not record or record["status"] not in ("uncertain", "dispatching"):
                raise ApprovalError("Only unresolved dispatches can be reconciled")
            if executed:
                self._finish(db, self._view(record), result)
            else:
                db.execute("UPDATE actions SET status='cancelled' WHERE id=?", (request_id,))
            db.execute("INSERT INTO reconciliations VALUES (?,?,?)", (request_id, operator, reference))
        return self.get(request_id)

    def _finish(self, db, row, result):
        fw, ctx = self._runtime(db, row["session"], Principal(**row["principal"]))
        tool = row["tool"]
        definition_policy = fw.policy.tool(tool)
        if definition_policy and definition_policy.produces_untrusted_output:
            ctx.taint(tool)
        structured = not isinstance(result, str)
        raw = canonical(result) if structured else result
        out_decision, screened = fw.inspect_output(tool, raw, ctx=ctx)
        self._notify("output", out_decision, row["id"], row["session"], Principal(**row["principal"]))
        result = json.loads(screened) if structured else screened
        self._save(db, fw, ctx)
        db.execute("UPDATE actions SET status='executed',result=? WHERE id=?",
                   (canonical(result), row["id"]))
