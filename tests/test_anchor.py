"""Audit anchoring: Merkle batches, chained commitments, proofs, tamper detection, backends."""
import hashlib
import json

import pytest

from fairewall.anchor import (
    AnchorError, Anchorer, BucketBackend, EvmBackend, FileBackend, check_proof, commitment,
    leaf_data, leaf_hash, merkle_path, merkle_root, root_from_path, tx_data,
)
from fairewall.audit import AuditLog
from fairewall.db import Database

KEY = "0x" + "11" * 32  # test-only key; never funded anywhere


def rfc6962(leaves):
    """MTH straight from RFC 6962 section 2.1, as the reference."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    k = 1
    while k * 2 < n:
        k *= 2
    return hashlib.sha256(b"\x01" + rfc6962(leaves[:k]) + rfc6962(leaves[k:])).digest()


# --------------------------------------------------------------------- Merkle

def test_root_matches_rfc6962_for_every_size():
    for n in range(0, 41):
        leaves = [leaf_hash(b"rec-%d" % i) for i in range(n)]
        assert merkle_root(leaves) == rfc6962(leaves), n


def test_every_path_verifies_and_a_wrong_leaf_does_not():
    for n in (1, 2, 3, 7, 8, 13, 32):
        leaves = [leaf_hash(b"rec-%d" % i) for i in range(n)]
        root = merkle_root(leaves)
        for i in range(n):
            path = merkle_path(leaves, i)
            assert root_from_path(leaves[i], path) == root
            assert root_from_path(leaf_hash(b"forged"), path) != root
            assert len(path) <= max(1, n).bit_length()


def test_a_leaf_cannot_pose_as_an_internal_node():
    a, b = leaf_hash(b"a"), leaf_hash(b"b")
    node_bytes = a + b  # the bytes an internal node is built from
    assert leaf_hash(node_bytes) != merkle_root([a, b])


# ---------------------------------------------------------- sealing batches

def logs(tmp_path, n_a=5, n_b=3):
    db = str(tmp_path / "audit.sqlite")
    a, b = AuditLog(store=db, log_id="gw-a"), AuditLog(store=db, log_id="gw-b")
    for i in range(n_a):
        a.append("tool_call_inspected", {"tool": "refund", "i": i})
    for i in range(n_b):
        b.append("input_inspected", {"source": "email", "i": i})
    return db, a, b


def test_one_batch_covers_every_instance_and_proofs_check_offline(tmp_path):
    db, a, b = logs(tmp_path)
    anchorer = Anchorer(db)
    batch = anchorer.seal()
    assert batch["batch"] == 0 and batch["size"] == 8 and batch["prev"] == "00" * 32
    assert batch["ranges"] == {"gw-a": [0, 4], "gw-b": [0, 2]}
    assert anchorer.seal() is None  # nothing new

    proof = anchorer.proof("gw-a", 3)
    assert proof["record"]["i"] == 3
    proof = json.loads(json.dumps(proof))  # survives a trip through a file
    assert check_proof(proof)["valid"]
    proof["record"]["i"] = 99
    assert not check_proof(proof)["valid"]


def test_batches_chain_and_only_new_records_are_sealed(tmp_path):
    db, a, b = logs(tmp_path)
    anchorer = Anchorer(db)
    first = anchorer.seal()
    a.append("tool_call_inspected", {"tool": "refund", "i": 5})
    second = anchorer.seal()
    assert second["batch"] == 1 and second["size"] == 1 and second["ranges"] == {"gw-a": [5, 5]}
    assert second["prev"] == first["commitment"]
    assert second["commitment"] == commitment(1, first["commitment"], second["root"], 1)
    assert anchorer.verify()["valid"]


def _sql(db_path, sql, args=()):
    d = Database(db_path, schema="fairewall_audit")
    with d.transaction() as tx:
        tx.execute(sql, args)
    d.close()


def test_editing_an_anchored_record_is_caught(tmp_path):
    db, a, _ = logs(tmp_path)
    anchorer = Anchorer(db)
    anchorer.seal()
    body = dict(a.records()[2])
    body["tool"] = "harmless"
    _sql(db, "UPDATE audit_records SET body=? WHERE log_id='gw-a' AND seq=2", (json.dumps(body),))
    report = anchorer.verify()
    assert not report["valid"] and "edited" in report["problems"][0]


def test_rewriting_the_whole_chain_is_still_caught(tmp_path):
    """The attack a hash chain alone cannot stop: recompute every hash after an edit."""
    db, a, _ = logs(tmp_path)
    anchorer = Anchorer(db)
    anchorer.seal()
    from fairewall.audit import GENESIS, record_hash
    prev = GENESIS
    for rec in a.records():
        rec = dict(rec, prev_hash=prev)
        if rec["seq"] == 1:
            rec["tool"] = "harmless"
        rec["hash"] = record_hash(rec)
        _sql(db, "UPDATE audit_records SET body=?, hash=?, prev_hash=? WHERE log_id='gw-a' AND seq=?",
             (json.dumps(rec, sort_keys=True), rec["hash"], prev, rec["seq"]))
        prev = rec["hash"]
    assert AuditLog(store=db, log_id="gw-a").verify().valid  # the chain itself looks fine
    report = anchorer.verify()
    assert not report["valid"] and "anchored root" in " ".join(report["problems"])


def test_deleting_records_or_batches_is_caught(tmp_path):
    db, a, _ = logs(tmp_path)
    anchorer = Anchorer(db)
    anchorer.seal()
    a.append("x", {})
    anchorer.seal()
    _sql(db, "DELETE FROM anchors WHERE batch=0")
    assert any("does not link" in p for p in anchorer.verify()["problems"])

    (tmp_path / "two").mkdir()
    db2, a2, _ = logs(tmp_path / "two")
    anchorer2 = Anchorer(db2)
    anchorer2.seal()
    _sql(db2, "DELETE FROM audit_records WHERE log_id='gw-b' AND seq=1")
    assert any("deleted" in p for p in anchorer2.verify()["problems"])


def test_a_chain_broken_before_sealing_is_refused(tmp_path):
    db, a, _ = logs(tmp_path)
    _sql(db, "UPDATE audit_records SET hash=? WHERE log_id='gw-a' AND seq=3", ("ab" * 32,))
    with pytest.raises(AnchorError, match="broken at record 3"):
        Anchorer(db).seal()


# -------------------------------------------------------------- publishing

def test_file_backend_never_overwrites(tmp_path):
    db, _, _ = logs(tmp_path)
    backend = FileBackend(str(tmp_path / "anchors"))
    anchorer = Anchorer(db, [backend])
    out = anchorer.run_once()
    assert out["published"][0]["status"] == "anchored"
    doc = json.loads(open(out["published"][0]["receipts"]["file"]["path"]).read())
    assert doc["commitment"] == out["sealed"]["commitment"] and len(doc["leaves"]) == 8
    assert "refund" not in json.dumps(doc)  # hashes only, no record content
    with pytest.raises(FileExistsError):
        backend.publish(out["sealed"], [])
    assert anchorer.verify(online=True)["valid"]


class FakeChain:
    """Answers the JSON-RPC calls EvmBackend makes, and keeps what it was sent."""

    def __init__(self):
        self.sent, self.txs = [], {}

    def __call__(self, method, params):
        if method == "eth_chainId":
            return hex(84532)
        if method == "eth_getTransactionCount":
            return hex(len(self.sent))
        if method == "eth_getBlockByNumber":
            return {"baseFeePerGas": hex(1_000_000), "timestamp": hex(1_795_000_000)}
        if method == "eth_maxPriorityFeePerGas":
            return hex(1_000)
        if method == "eth_estimateGas":
            return hex(21_800)
        if method == "eth_sendRawTransaction":
            from eth_account import Account
            from eth_account.typed_transactions import TypedTransaction
            from hexbytes import HexBytes
            raw = HexBytes(params[0])
            tx = TypedTransaction.from_bytes(raw).as_dict()
            sender = Account.recover_transaction(raw)
            h = "0x" + hashlib.sha256(raw).hexdigest()
            self.sent.append({"tx": tx, "from": sender})
            self.txs[h] = {"input": "0x" + bytes(tx["data"]).hex(), "blockNumber": hex(1234)}
            return h
        if method == "eth_getTransactionByHash":
            return self.txs.get(params[0])
        raise AssertionError(method)


def test_evm_backend_signs_a_self_transaction_carrying_only_the_commitment(tmp_path):
    from eth_account import Account
    db, _, _ = logs(tmp_path)
    chain = FakeChain()
    anchorer = Anchorer(db, [EvmBackend(private_key=KEY, transport=chain)])
    out = anchorer.run_once()
    receipt = out["published"][0]["receipts"]["evm"]
    me = Account.from_key(KEY).address
    sent = chain.sent[0]
    assert sent["from"] == me and "0x" + bytes(sent["tx"]["to"]).hex() == me.lower() and sent["tx"]["value"] == 0
    assert bytes(sent["tx"]["data"]) == tx_data(0, out["sealed"]["commitment"])
    assert len(bytes(sent["tx"]["data"])) == 44
    assert receipt["explorer"].startswith("https://sepolia.basescan.org/tx/")
    assert anchorer.verify(online=True)["valid"]
    # A proof can be confirmed against the chain with no database at all.
    result = check_proof(anchorer.proof("gw-b", 2), backend=EvmBackend(transport=chain))
    assert result["valid"] and "block 1234" in result["published"]["detail"]
    # If the chain held something else, verification says so.
    chain.txs[receipt["tx"]]["input"] = "0x" + tx_data(0, "ff" * 32).hex()
    assert not anchorer.verify(online=True)["valid"]


def test_a_failed_publish_is_retried_and_does_not_lose_the_batch(tmp_path):
    db, _, _ = logs(tmp_path)
    calls = []

    def down(method, url, body, headers):
        calls.append(url)
        raise AnchorError("storage unreachable")

    bucket = BucketBackend("fw-audit", token="t", transport=down)
    anchorer = Anchorer(db, [bucket])
    out = anchorer.run_once()
    assert out["published"][0]["status"] == "sealed" and "unreachable" in out["published"][0]["error"]
    assert "ifGenerationMatch=0" in calls[0]  # create-only: never replaces an object

    bucket._http = lambda method, url, body, headers: {"generation": "17"}
    again = anchorer.publish()
    assert again[0]["status"] == "anchored" and again[0]["receipts"]["bucket"]["generation"] == "17"
    assert anchorer.anchors()[0]["status"] == "anchored"


def test_no_signing_key_is_a_clear_error_not_a_crash(tmp_path, monkeypatch):
    monkeypatch.delenv("FAIREWALL_ANCHOR_KEY", raising=False)
    db, _, _ = logs(tmp_path)
    out = Anchorer(db, [EvmBackend(transport=FakeChain())]).run_once()
    assert out["published"][0]["status"] == "sealed"
    assert "FAIREWALL_ANCHOR_KEY" in out["published"][0]["error"]


def test_leaf_encoding_is_unambiguous():
    assert leaf_data("a", 1, "b" * 64) != leaf_data("a1", 1, "b" * 64)
