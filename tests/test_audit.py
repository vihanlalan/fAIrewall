import json
import os
import threading
import pytest
from fairewall.audit import AuditLog, GENESIS, record_hash, verify_chain, verify_file


def test_audit_in_memory():
    log = AuditLog()
    r1 = log.append("call_1", {"action": "allow", "tool": "search"})
    r2 = log.append("call_2", {"action": "block", "tool": "refund"})

    assert r1["seq"] == 0
    assert r1["prev_hash"] == GENESIS
    assert r2["seq"] == 1
    assert r2["prev_hash"] == r1["hash"]
    assert log.head == r2["hash"]

    records = log.records()
    assert len(records) == 2

    res = log.verify()
    assert res.valid is True
    assert res.checked == 2
    assert res.broken_at is None


def test_audit_file_backed(tmp_path):
    log_file = str(tmp_path / "test_audit.jsonl")
    log = AuditLog(path=log_file)
    log.append("ev1", {"data": 1})
    log.append("ev2", {"data": 2})
    log.append("ev3", {"data": 3})

    # Verify directly from file
    res = verify_file(log_file)
    assert res.valid is True
    assert res.checked == 3

    # Resuming an existing log continues the chain
    log2 = AuditLog(path=log_file)
    assert log2.head == log.head
    r4 = log2.append("ev4", {"data": 4})
    assert r4["seq"] == 3
    assert r4["prev_hash"] == log.head

    res2 = verify_file(log_file)
    assert res2.valid is True
    assert res2.checked == 4


def test_audit_tamper_detection(tmp_path):
    log_file = str(tmp_path / "tamper_audit.jsonl")
    log = AuditLog(path=log_file)
    log.append("ev0", {"amount": 100})
    log.append("ev1", {"amount": 200})
    log.append("ev2", {"amount": 300})

    # Read records
    with open(log_file, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    # Tamper with record 1's payload without updating hash
    records = [json.loads(l) for l in lines]
    records[1]["amount"] = 999999

    res = verify_chain(records)
    assert res.valid is False
    assert res.broken_at == 1
    assert "content does not match its hash" in res.reason

    # Tamper with record 1's hash (breaks link to record 2)
    records[1] = json.loads(lines[1])
    records[1]["hash"] = "0" * 64
    res = verify_chain(records)
    assert res.valid is False
    assert res.broken_at == 1

    # Delete record 1 (breaks sequence and chain)
    records = [json.loads(lines[0]), json.loads(lines[2])]
    res = verify_chain(records)
    assert res.valid is False
    assert res.broken_at == 1
    assert "does not link to its predecessor" in res.reason


def test_audit_thread_safety():
    log = AuditLog()
    num_threads = 10
    appends_per_thread = 20

    def worker(worker_id: int):
        for i in range(appends_per_thread):
            log.append(f"worker_{worker_id}", {"step": i})

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    records = log.records()
    assert len(records) == num_threads * appends_per_thread

    # Chain must be valid despite concurrent writes
    res = log.verify()
    assert res.valid is True
    assert res.checked == num_threads * appends_per_thread
