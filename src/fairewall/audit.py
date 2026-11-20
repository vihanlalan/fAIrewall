"""Tamper-evident audit log.

This is the commercial center of gravity, not the detection. A CTO in a
regulated space cannot ship an autonomous agent without being able to answer,
months later and under oath: what did the agent try to do, what was allowed,
under which version of which policy, and can you prove the record was not
edited afterwards?

Each record carries the SHA-256 of the previous record. Altering or deleting
any entry breaks the chain from that point on, which `verify_chain` detects.
That is tamper-*evidence*, not tamper-proofing: an attacker with write access
to the storage can rewrite the whole chain. fairewall.anchor closes that gap:
it seals batches of records into a Merkle tree and publishes the root to a
locked bucket and a public blockchain.

Storage: in memory, a JSONL file (``path``), or a database (``store``, SQLite
or Postgres). In a database each process writes its own chain (``log_id``), so
gateway instances never contend, and every chain survives the instance.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional, Tuple

GENESIS = "0" * 64


def _canonical(record: Dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def record_hash(record: Dict[str, Any]) -> str:
    """Hash of a record excluding its own hash field."""
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()


class AuditLog:
    """Append-only JSONL log with a hash chain. Thread-safe."""

    def __init__(self, path: Optional[str] = None, echo: bool = False, *,
                 store: Any = None, log_id: Optional[str] = None) -> None:
        self.path = path
        self.echo = echo
        self._lock = threading.Lock()
        self._head = GENESIS
        self._sequence = 0
        self._memory: List[Dict[str, Any]] = []
        self.db = None
        self.log_id = log_id
        if store is not None:
            from .db import Database
            self.db = Database(store, schema="fairewall_audit")
            self.db.create(AUDIT_SCHEMA)
            self.log_id = log_id or "log_" + uuid.uuid4().hex[:16]
            self._resume_db()
        elif path:
            os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
            self._resume()

    def _resume_db(self) -> None:
        with self.db.transaction(lock="log:" + self.log_id) as db:
            row = db.execute("SELECT seq, hash FROM audit_records WHERE log_id=? ORDER BY seq DESC LIMIT 1",
                             (self.log_id,)).fetchone()
            if row is None:
                db.execute("INSERT INTO audit_logs (log_id, created) VALUES (?,?) ON CONFLICT DO NOTHING",
                           (self.log_id, time.time()))
        if row is not None:
            self._sequence, self._head = row["seq"] + 1, row["hash"]

    def _resume(self) -> None:
        """Continue an existing chain rather than starting a second one."""
        if not self.path or not os.path.exists(self.path):
            return
        last = None
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = line
                    self._sequence += 1
        if last:
            entry = json.loads(last)
            self._head = entry.get("hash", GENESIS)

    def append(self, event: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            record = {
                "seq": self._sequence,
                "event": event,
                "prev_hash": self._head,
                **payload,
            }
            record["hash"] = record_hash(record)
            self._head = record["hash"]
            self._sequence += 1

            if self.db is not None:
                with self.db.transaction(lock="log:" + self.log_id) as db:
                    db.execute("INSERT INTO audit_records (log_id, seq, hash, prev_hash, event, body, at)"
                               " VALUES (?,?,?,?,?,?,?)",
                               (self.log_id, record["seq"], record["hash"], record["prev_hash"], event,
                                _canonical(record), time.time()))
            elif self.path:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(_canonical(record) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
            else:
                self._memory.append(record)
            if self.echo:
                print("[fairewall audit] " + _canonical(record))
            return record

    @property
    def head(self) -> str:
        """Current chain head. Publish this externally to anchor the log."""
        return self._head

    def __iter__(self) -> Iterator[Dict[str, Any]]:
        if self.db is not None:
            return iter(self.records_after(-1, limit=10 ** 9))
        if self.path:
            if not os.path.exists(self.path):
                return iter(())
            with open(self.path, "r", encoding="utf-8") as fh:
                return iter([json.loads(line) for line in fh if line.strip()])
        return iter(list(self._memory))

    def records(self) -> List[Dict[str, Any]]:
        return list(self)

    def records_after(self, seq: int, limit: int = 500) -> List[Dict[str, Any]]:
        """Up to *limit* records with a sequence number greater than *seq*, oldest first."""
        if self.db is not None:
            with self.db.transaction(lock="log:" + self.log_id) as db:
                rows = list(db.execute("SELECT body FROM audit_records WHERE log_id=? AND seq>?"
                                       " ORDER BY seq LIMIT ?", (self.log_id, seq, limit)))
            return [json.loads(r["body"]) for r in rows]
        if not self.path:
            with self._lock:
                start = max(0, seq + 1)
                return [dict(r) for r in self._memory[start:start + limit]]
        out: List[Dict[str, Any]] = []
        for record in self:
            if record.get("seq", -1) > seq:
                out.append(record)
                if len(out) >= limit:
                    break
        return out

    def first_hash(self) -> str:
        """Hash of the first record: a stable identity for this log, or '' if empty."""
        if self.db is not None:
            first = self.records_after(-1, limit=1)
            return str(first[0]["hash"]) if first else ""
        if not self.path:
            with self._lock:
                return self._memory[0]["hash"] if self._memory else ""
        for record in self:
            return str(record.get("hash", ""))
        return ""

    def verify(self) -> "ChainVerification":
        return verify_chain(self.records())


AUDIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_logs (log_id TEXT PRIMARY KEY, created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS audit_records (
    log_id TEXT NOT NULL, seq INTEGER NOT NULL, hash TEXT NOT NULL, prev_hash TEXT NOT NULL,
    event TEXT NOT NULL, body TEXT NOT NULL, at REAL NOT NULL, PRIMARY KEY (log_id, seq))
"""


@dataclass
class ChainVerification:
    valid: bool
    checked: int
    broken_at: Optional[int] = None
    reason: Optional[str] = None

    def __bool__(self) -> bool:
        return self.valid


def verify_chain(records: List[Dict[str, Any]]) -> ChainVerification:
    """Confirm every record hashes to its stored value and links to its predecessor."""
    previous = GENESIS
    for index, record in enumerate(records):
        expected = record_hash(record)
        if record.get("hash") != expected:
            return ChainVerification(False, index, index,
                                     "record %d content does not match its hash" % index)
        if record.get("prev_hash") != previous:
            return ChainVerification(False, index, index,
                                     "record %d does not link to its predecessor" % index)
        if record.get("seq") != index:
            return ChainVerification(False, index, index,
                                     "record %d has a gap in the sequence" % index)
        previous = record["hash"]
    return ChainVerification(True, len(records))


def verify_file(path: str) -> ChainVerification:
    with open(path, "r", encoding="utf-8") as fh:
        records = [json.loads(line) for line in fh if line.strip()]
    return verify_chain(records)
