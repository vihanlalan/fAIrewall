"""Tamper-evident audit log.

This is the commercial center of gravity, not the detection. A CTO in a
regulated space cannot ship an autonomous agent without being able to answer,
months later and under oath: what did the agent try to do, what was allowed,
under which version of which policy, and can you prove the record was not
edited afterwards?

Each record carries the SHA-256 of the previous record. Altering or deleting
any entry breaks the chain from that point on, which `verify_chain` detects.
That is tamper-*evidence*, not tamper-proofing: an attacker with write access
to the file can rewrite the whole chain. Anchor it -- ship each record to
append-only storage (S3 Object Lock, CloudWatch, a WORM bucket) or publish the
head hash periodically -- before calling it an auditor-grade control.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
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

    def __init__(self, path: Optional[str] = None, echo: bool = False) -> None:
        self.path = path
        self.echo = echo
        self._lock = threading.Lock()
        self._head = GENESIS
        self._sequence = 0
        self._memory: List[Dict[str, Any]] = []
        if path:
            os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
            self._resume()

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

            if self.path:
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
        if self.path:
            if not os.path.exists(self.path):
                return iter(())
            with open(self.path, "r", encoding="utf-8") as fh:
                return iter([json.loads(line) for line in fh if line.strip()])
        return iter(list(self._memory))

    def records(self) -> List[Dict[str, Any]]:
        return list(self)

    def verify(self) -> "ChainVerification":
        return verify_chain(self.records())


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
