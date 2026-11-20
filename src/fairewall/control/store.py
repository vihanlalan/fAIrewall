"""Control-plane storage: policy versions, environments, gateways, events.

SQLite (a file, or ":memory:") for a single node, or Postgres (a
postgresql:// URL, e.g. Cloud SQL) so several control-plane instances share one
state. Every transaction is serialized (see fairewall.db); the control plane is
write-light (a sync every few seconds per gateway), so this is not the limit.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..db import Database, Row
from ..policy import Policy

# Rows kept in the central event table. Older rows are pruned on insert.
MAX_EVENTS = 50_000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS policy_versions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    version     INTEGER NOT NULL,
    body        TEXT    NOT NULL,
    fingerprint TEXT    NOT NULL,
    note        TEXT    NOT NULL DEFAULT '',
    created_by  TEXT    NOT NULL,
    created_at  REAL    NOT NULL,
    UNIQUE (name, version)
);
CREATE TABLE IF NOT EXISTS environments (
    name        TEXT PRIMARY KEY,
    policy_name TEXT,
    version     INTEGER,
    shadow      INTEGER NOT NULL DEFAULT 0,
    updated_by  TEXT,
    updated_at  REAL
);
CREATE TABLE IF NOT EXISTS gateways (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    environment   TEXT NOT NULL,
    token_hash    TEXT NOT NULL UNIQUE,
    created_at    REAL NOT NULL,
    last_seen     REAL,
    report        TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    gateway_id  TEXT    NOT NULL,
    log_id      TEXT    NOT NULL,
    seq         INTEGER NOT NULL,
    received_at REAL    NOT NULL,
    ts          REAL,
    event       TEXT,
    tool        TEXT,
    action      TEXT,
    session_id  TEXT,
    principal   TEXT,
    findings    TEXT NOT NULL DEFAULT '[]',
    arguments   TEXT NOT NULL DEFAULT '{}',
    UNIQUE (gateway_id, log_id, seq)
);
CREATE INDEX IF NOT EXISTS events_by_time ON events (received_at);
CREATE TABLE IF NOT EXISTS fleet_freezes (
    scope  TEXT NOT NULL,
    target TEXT NOT NULL,
    reason TEXT NOT NULL,
    "by"   TEXT NOT NULL,
    at     REAL NOT NULL,
    PRIMARY KEY (scope, target)
);
CREATE TABLE IF NOT EXISTS changes (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    at     REAL NOT NULL,
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '{}'
)
"""


class ControlError(ValueError):
    """A request the control plane refuses (bad input, unknown object)."""


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _clean_name(value: str, what: str, limit: int = 64) -> str:
    value = (value or "").strip()
    if not value:
        raise ControlError("%s is required." % what)
    if len(value) > limit:
        raise ControlError("%s must be at most %d characters." % (what, limit))
    if not all(c.isalnum() or c in "-_." for c in value):
        raise ControlError("%s may contain only letters, digits, '-', '_' and '.'." % what)
    return value


class ControlStore:
    """All control-plane state. Thread-safe: every call is one serialized transaction."""

    def __init__(self, path: str = ":memory:") -> None:
        self.path = path
        self.db = Database(path, schema="fairewall_control")
        self.db.create(_SCHEMA)

    def close(self) -> None:
        self.db.close()

    # ------------------------------------------------------------ helpers

    def _rows(self, sql: str, args: Iterable[Any] = ()) -> List[Row]:
        with self.db.transaction() as db:
            return list(db.execute(sql, tuple(args)))

    def _one(self, sql: str, args: Iterable[Any] = ()) -> Optional[Row]:
        rows = self._rows(sql, args)
        return rows[0] if rows else None

    @staticmethod
    def _record_change(db: Any, actor: str, action: str, detail: Dict[str, Any]) -> None:
        db.execute("INSERT INTO changes (at, actor, action, detail) VALUES (?, ?, ?, ?)",
                   (time.time(), (actor or "admin")[:100], action, json.dumps(detail)))

    # ------------------------------------------------------------ policies

    def create_version(self, name: str, body: Dict[str, Any], created_by: str,
                       note: str = "") -> Dict[str, Any]:
        """Validate *body* as a policy and store it as the next version of *name*."""
        name = _clean_name(name, "Policy name")
        if not isinstance(body, dict):
            raise ControlError("Policy body must be a JSON object.")
        try:
            policy = Policy.from_dict(body)
        except (ValueError, TypeError, KeyError) as exc:
            raise ControlError("Invalid policy: %s" % exc)
        normalized = policy.to_dict()
        fingerprint = policy.fingerprint()
        with self.db.transaction() as db:
            row = db.execute("SELECT MAX(version) FROM policy_versions WHERE name = ?",
                             (name,)).fetchone()
            version = (row[0] or 0) + 1
            db.execute(
                "INSERT INTO policy_versions (name, version, body, fingerprint, note, created_by,"
                " created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (name, version, json.dumps(normalized), fingerprint, (note or "")[:500],
                 (created_by or "admin")[:100], time.time()))
            self._record_change(db, created_by, "policy_version_created",
                                {"policy": name, "version": version, "fingerprint": fingerprint,
                                 "note": (note or "")[:500]})
        return self.get_version(name, version)

    def get_version(self, name: str, version: int) -> Dict[str, Any]:
        row = self._one("SELECT * FROM policy_versions WHERE name = ? AND version = ?",
                        (name, int(version)))
        if row is None:
            raise ControlError("No policy %s version %s." % (name, version))
        return self._version_dict(row, with_body=True)

    def list_versions(self, name: Optional[str] = None) -> List[Dict[str, Any]]:
        rows = (self._rows("SELECT * FROM policy_versions WHERE name = ? ORDER BY version DESC",
                           (name,)) if name else
                self._rows("SELECT * FROM policy_versions ORDER BY name, version DESC"))
        return [self._version_dict(r, with_body=False) for r in rows]

    @staticmethod
    def _version_dict(row: Row, with_body: bool) -> Dict[str, Any]:
        out = {"name": row["name"], "version": row["version"], "fingerprint": row["fingerprint"],
               "note": row["note"], "created_by": row["created_by"],
               "created_at": row["created_at"]}
        if with_body:
            out["body"] = json.loads(row["body"])
        return out

    # -------------------------------------------------------- environments

    def deploy(self, environment: str, name: str, version: int, shadow: bool,
               actor: str) -> Dict[str, Any]:
        """Assign a policy version to an environment. Gateways pick it up on their next sync."""
        environment = _clean_name(environment, "Environment")
        self.get_version(name, version)  # must exist
        with self.db.transaction() as db:
            previous = db.execute("SELECT * FROM environments WHERE name = ?",
                                  (environment,)).fetchone()
            db.execute(
                "INSERT INTO environments (name, policy_name, version, shadow, updated_by, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET"
                " policy_name = excluded.policy_name, version = excluded.version,"
                " shadow = excluded.shadow, updated_by = excluded.updated_by,"
                " updated_at = excluded.updated_at",
                (environment, name, int(version), int(bool(shadow)), (actor or "admin")[:100],
                 time.time()))
            self._record_change(db, actor, "deployed", {
                "environment": environment, "policy": name, "version": int(version),
                "shadow": bool(shadow),
                "previous": ({"policy": previous["policy_name"], "version": previous["version"],
                              "shadow": bool(previous["shadow"])}
                             if previous and previous["policy_name"] else None)})
        return self.get_environment(environment)

    def promote(self, source: str, target: str, actor: str, shadow: bool = False) -> Dict[str, Any]:
        """Copy *source*'s assignment to *target* (e.g. staging -> production)."""
        env = self.get_environment(source)
        if not env.get("policy"):
            raise ControlError("Environment %s has no policy deployed to promote." % source)
        return self.deploy(target, env["policy"], env["version"], shadow, actor)

    def get_environment(self, name: str) -> Dict[str, Any]:
        row = self._one("SELECT * FROM environments WHERE name = ?", (name,))
        if row is None:
            return {"name": name, "policy": None, "version": None, "shadow": False,
                    "fingerprint": None, "updated_by": None, "updated_at": None}
        fingerprint = None
        if row["policy_name"]:
            fingerprint = self.get_version(row["policy_name"], row["version"])["fingerprint"]
        return {"name": row["name"], "policy": row["policy_name"], "version": row["version"],
                "shadow": bool(row["shadow"]), "fingerprint": fingerprint,
                "updated_by": row["updated_by"], "updated_at": row["updated_at"]}

    def list_environments(self) -> List[Dict[str, Any]]:
        names = {r["name"] for r in self._rows("SELECT name FROM environments")}
        names |= {r["environment"] for r in self._rows("SELECT DISTINCT environment FROM gateways")}
        return [self.get_environment(n) for n in sorted(names)]

    # ------------------------------------------------------------ gateways

    def register_gateway(self, name: str, environment: str, actor: str) -> Tuple[Dict[str, Any], str]:
        """Create a gateway identity. Returns (gateway, token); the token is shown only once."""
        name = _clean_name(name, "Gateway name")
        environment = _clean_name(environment, "Environment")
        gateway_id = "gw_" + secrets.token_hex(6)
        token = "fwgw_" + secrets.token_urlsafe(32)
        with self.db.transaction() as db:
            db.execute(
                "INSERT INTO gateways (id, name, environment, token_hash, created_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (gateway_id, name, environment, _hash_token(token), time.time()))
            self._record_change(db, actor, "gateway_registered",
                                {"gateway": gateway_id, "name": name, "environment": environment})
        return self.get_gateway(gateway_id), token

    def remove_gateway(self, gateway_id: str, actor: str) -> None:
        with self.db.transaction() as db:
            cur = db.execute("DELETE FROM gateways WHERE id = ?", (gateway_id,))
            if cur.rowcount == 0:
                raise ControlError("No gateway %s." % gateway_id)
            self._record_change(db, actor, "gateway_removed", {"gateway": gateway_id})

    def gateway_for_token(self, token: str) -> Optional[Dict[str, Any]]:
        if not token:
            return None
        row = self._one("SELECT * FROM gateways WHERE token_hash = ?", (_hash_token(token),))
        return self._gateway_dict(row) if row else None

    def get_gateway(self, gateway_id: str) -> Dict[str, Any]:
        row = self._one("SELECT * FROM gateways WHERE id = ?", (gateway_id,))
        if row is None:
            raise ControlError("No gateway %s." % gateway_id)
        return self._gateway_dict(row)

    def list_gateways(self) -> List[Dict[str, Any]]:
        return [self._gateway_dict(r) for r in self._rows("SELECT * FROM gateways ORDER BY name")]

    @staticmethod
    def _gateway_dict(row: Row) -> Dict[str, Any]:
        return {"id": row["id"], "name": row["name"], "environment": row["environment"],
                "created_at": row["created_at"], "last_seen": row["last_seen"],
                "report": json.loads(row["report"] or "{}")}

    def record_sync(self, gateway_id: str, report: Dict[str, Any],
                    events: List[Dict[str, Any]], log_id: str = "") -> int:
        """Store a gateway's heartbeat and its new events. Returns events stored.

        *log_id* identifies the gateway's audit log (the hash of its first
        record), so a gateway restarted with a fresh in-memory log, whose
        sequence numbers start again at 0, is not mistaken for a replay.
        """
        now = time.time()
        stored = 0
        with self.db.transaction() as db:
            db.execute("UPDATE gateways SET last_seen = ?, report = ? WHERE id = ?",
                       (now, json.dumps(report), gateway_id))
            for ev in events:
                try:
                    cur = db.execute(
                        "INSERT INTO events (gateway_id, log_id, seq, received_at, ts,"
                        " event, tool, action, session_id, principal, findings, arguments)"
                        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
                        (gateway_id, (log_id or "")[:64], int(ev["seq"]), now, ev.get("timestamp"),
                         str(ev.get("event") or "")[:64], str(ev.get("tool") or "")[:200],
                         str(ev.get("action") or "")[:16], str(ev.get("session_id") or "")[:200],
                         str(ev.get("principal") or "")[:200],
                         json.dumps(ev.get("findings") or [])[:8000],
                         json.dumps(ev.get("arguments") or {})[:8000]))
                    stored += cur.rowcount
                except (KeyError, TypeError, ValueError):
                    continue  # one malformed event must not drop the rest
            total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            if total > MAX_EVENTS:
                db.execute(
                    "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id LIMIT ?)",
                    (total - MAX_EVENTS,))
        return stored

    def last_seq(self, gateway_id: str, log_id: str) -> int:
        """Highest sequence number stored for this gateway's log, or -1."""
        row = self._one("SELECT MAX(seq) FROM events WHERE gateway_id = ? AND log_id = ?",
                        (gateway_id, (log_id or "")[:64]))
        return row[0] if row and row[0] is not None else -1

    # -------------------------------------------------------------- events

    def events(self, limit: int = 100, gateway_id: Optional[str] = None,
               actions: Optional[List[str]] = None, environment: Optional[str] = None,
               event: Optional[str] = None, since: Optional[float] = None) -> List[Dict[str, Any]]:
        sql = ("SELECT e.*, g.name AS gateway_name, g.environment AS environment FROM events e"
               " LEFT JOIN gateways g ON g.id = e.gateway_id WHERE 1 = 1")
        args: List[Any] = []
        if gateway_id:
            sql += " AND e.gateway_id = ?"
            args.append(gateway_id)
        if environment:
            sql += " AND g.environment = ?"
            args.append(environment)
        if actions:
            sql += " AND e.action IN (%s)" % ",".join("?" * len(actions))
            args.extend(actions)
        if event:
            sql += " AND e.event = ?"
            args.append(event)
        if since is not None:
            sql += " AND e.received_at >= ?"
            args.append(since)
        sql += " ORDER BY e.id DESC LIMIT ?"
        args.append(max(1, min(int(limit), 5000)))
        out = []
        for r in self._rows(sql, args):
            out.append({"id": r["id"], "gateway_id": r["gateway_id"],
                        "gateway": r["gateway_name"], "environment": r["environment"],
                        "seq": r["seq"], "timestamp": r["ts"], "received_at": r["received_at"],
                        "event": r["event"], "tool": r["tool"], "action": r["action"],
                        "session_id": r["session_id"], "principal": r["principal"],
                        "findings": json.loads(r["findings"]),
                        "arguments": json.loads(r["arguments"])})
        return out

    def action_counts(self, gateway_id: str, since: float) -> Dict[str, int]:
        rows = self._rows("SELECT action, COUNT(*) AS n FROM events WHERE gateway_id = ?"
                          " AND received_at >= ? AND event = 'tool_call_inspected' GROUP BY action",
                          (gateway_id, since))
        return {r["action"]: r["n"] for r in rows}

    # --------------------------------------------------------- kill switch

    def fleet_freeze(self, scope: str, target: Optional[str], reason: str, actor: str) -> Dict[str, Any]:
        scope = (scope or "all").strip().lower()
        if scope not in ("all", "session", "principal"):
            raise ControlError("scope must be all, session or principal.")
        target = "*" if scope == "all" else (target or "").strip()[:200]
        if not target:
            raise ControlError("A %s freeze needs a target." % scope)
        record = {"scope": scope, "target": target,
                  "reason": (reason or "").strip()[:500] or "Stopped from the control plane.",
                  "by": (actor or "admin")[:100], "at": time.time()}
        with self.db.transaction() as db:
            db.execute(
                "INSERT INTO fleet_freezes (scope, target, reason, \"by\", at) VALUES (?, ?, ?, ?, ?)"
                " ON CONFLICT(scope, target) DO UPDATE SET reason = excluded.reason,"
                " \"by\" = excluded.\"by\"",
                (record["scope"], record["target"], record["reason"], record["by"], record["at"]))
            self._record_change(db, actor, "fleet_freeze", record)
        return record

    def fleet_unfreeze(self, scope: str, target: Optional[str], actor: str) -> bool:
        scope = (scope or "all").strip().lower()
        target = "*" if scope == "all" else (target or "").strip()[:200]
        with self.db.transaction() as db:
            cur = db.execute("DELETE FROM fleet_freezes WHERE scope = ? AND target = ?",
                             (scope, target))
            if cur.rowcount:
                self._record_change(db, actor, "fleet_unfreeze", {"scope": scope, "target": target})
            return bool(cur.rowcount)

    def fleet_freezes(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._rows("SELECT * FROM fleet_freezes ORDER BY at")]

    # ------------------------------------------------------------- history

    def changes(self, limit: int = 100) -> List[Dict[str, Any]]:
        rows = self._rows("SELECT * FROM changes ORDER BY id DESC LIMIT ?",
                          (max(1, min(int(limit), 1000)),))
        return [{"id": r["id"], "at": r["at"], "actor": r["actor"], "action": r["action"],
                 "detail": json.loads(r["detail"])} for r in rows]
