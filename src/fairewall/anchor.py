"""Anchoring the audit trail: Merkle batches, published to a locked bucket and a public chain.

The audit log is a hash chain, which shows tampering *inside* the log. It
cannot stop someone with database access from rewriting a whole chain. This
module closes that gap without putting records on a blockchain:

  1. **Seal.** Every interval, all audit records written since the last batch,
     across every gateway instance's chain, become the leaves of one Merkle tree
     (RFC 6962 layout, as in Certificate Transparency: leaves and nodes are
     hashed with different prefixes, so a leaf can never pass as a node).
     Sealing first re-checks each record's hash and its link to the previous
     record, so a chain already tampered with is refused, not anchored.
  2. **Link.** Each batch's commitment hashes in the previous batch's, so a
     deleted or reordered batch is detectable too:
         commitment_n = SHA-256("fairewall-anchor-v1" || n || commitment_(n-1) || root_n || size_n)
  3. **Publish.** Only the 32-byte commitment leaves the system: as a
     transaction on an EVM chain (Base), and as a batch file in a Cloud
     Storage bucket with a locked retention policy. One transaction per
     interval, whatever the traffic. No record content goes on chain.
  4. **Prove.** For any one record, ``proof()`` gives a short Merkle path to
     its batch root. Anyone can check it offline against the published
     commitment, without seeing any other record.

What an anchor proves: the record existed, unchanged, when its batch was
published. It does not prove the record was true when written, and records
newer than the last anchor are only as safe as the database until the next one.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .audit import AUDIT_SCHEMA, GENESIS, record_hash
from .db import Database

DOMAIN = b"fairewall-anchor-v1"
ZERO = "00" * 32
MARKER = b"FWA1"  # prefixes the transaction data, so anchors are easy to find on chain

_SCHEMA = AUDIT_SCHEMA + """;
CREATE TABLE IF NOT EXISTS anchors (
    batch INTEGER PRIMARY KEY, created REAL NOT NULL, root TEXT NOT NULL, prev TEXT NOT NULL,
    commitment TEXT NOT NULL, size INTEGER NOT NULL, ranges TEXT NOT NULL,
    status TEXT NOT NULL, receipts TEXT NOT NULL DEFAULT '{}', error TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS anchor_progress (
    log_id TEXT PRIMARY KEY, last_seq INTEGER NOT NULL, last_hash TEXT NOT NULL)
"""


class AnchorError(RuntimeError):
    """Sealing or verification found something wrong (or a backend failed)."""


# ------------------------------------------------------------- Merkle (RFC 6962)

def _sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_data(log_id: str, seq: int, record_hash_hex: str) -> bytes:
    return json.dumps([log_id, seq, record_hash_hex], separators=(",", ":")).encode()


def leaf_hash(data: bytes) -> bytes:
    return _sha(b"\x00" + data)


def _node(left: bytes, right: bytes) -> bytes:
    return _sha(b"\x01" + left + right)


def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    """MTH(D) from RFC 6962 over already-hashed leaves."""
    if not leaves:
        return _sha(b"")
    level = list(leaves)
    # Bottom-up pairing gives the same tree as RFC 6962's left-balanced split.
    while len(level) > 1:
        nxt = [_node(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])  # promoted, never duplicated
        level = nxt
    return level[0]


def merkle_path(leaves: Sequence[bytes], index: int) -> List[Tuple[str, str]]:
    """Audit path for leaf *index*: [(side, sibling_hex)], side 'L' or 'R' of the sibling."""
    if not 0 <= index < len(leaves):
        raise IndexError("leaf index out of range")
    path: List[Tuple[str, str]] = []

    def walk(lo: int, hi: int) -> None:
        n = hi - lo
        if n == 1:
            return
        k = _split(n)
        if index < lo + k:
            walk(lo, lo + k)
            path.append(("R", merkle_root(leaves[lo + k:hi]).hex()))
        else:
            walk(lo + k, hi)
            path.append(("L", merkle_root(leaves[lo:lo + k]).hex()))

    walk(0, len(leaves))
    return path


def root_from_path(leaf: bytes, path: Sequence[Sequence[str]]) -> bytes:
    h = leaf
    for side, sibling in path:
        h = _node(bytes.fromhex(sibling), h) if side == "L" else _node(h, bytes.fromhex(sibling))
    return h


def commitment(batch: int, prev_hex: str, root_hex: str, size: int) -> str:
    return _sha(DOMAIN + batch.to_bytes(8, "big") + bytes.fromhex(prev_hex)
                + bytes.fromhex(root_hex) + size.to_bytes(8, "big")).hex()


def tx_data(batch: int, commitment_hex: str) -> bytes:
    return MARKER + batch.to_bytes(8, "big") + bytes.fromhex(commitment_hex)


# ---------------------------------------------------------------------- backends

class FileBackend:
    """Writes each batch to a directory, never overwriting. For local runs and tests."""

    name = "file"

    def __init__(self, directory: str) -> None:
        self.directory = directory
        os.makedirs(directory, exist_ok=True)

    def publish(self, anchor: Dict[str, Any], leaves: List[Dict[str, Any]]) -> Dict[str, Any]:
        path = os.path.join(self.directory, "anchor-%08d.json" % anchor["batch"])
        with open(path, "x", encoding="utf-8") as fh:  # "x": refuse to overwrite
            json.dump(_batch_document(anchor, leaves), fh, indent=1)
        return {"path": path}

    def check(self, anchor: Dict[str, Any], receipt: Dict[str, Any]) -> Dict[str, Any]:
        with open(receipt["path"], encoding="utf-8") as fh:
            doc = json.load(fh)
        ok = doc["commitment"] == anchor["commitment"] and doc["root"] == anchor["root"]
        return {"ok": ok, "detail": "file copy matches" if ok else "file copy differs"}


class BucketBackend:
    """Cloud Storage with a locked retention policy (WORM). Objects are created, never replaced.

    Create the bucket once, in the region you keep logs in, and lock it:
        gcloud storage buckets create gs://BUCKET --location=asia-south1 --retention-period=400d
        gcloud storage buckets update gs://BUCKET --lock-retention-period
    Locking is permanent: nobody, including you, can then shorten or remove it.
    """

    name = "bucket"

    def __init__(self, bucket: str, prefix: str = "fairewall-anchors/", token: Optional[str] = None,
                 transport: Optional[Callable[..., Dict[str, Any]]] = None) -> None:
        from .integrations.model_armor import TokenSource  # same Google auth (ADC or token)
        self.bucket, self.prefix = bucket, prefix
        self._token = TokenSource(token or os.environ.get("FAIREWALL_ANCHOR_GCS_TOKEN"))
        self._http = transport or _http

    def _object(self, batch: int) -> str:
        return "%sanchor-%08d.json" % (self.prefix, batch)

    def publish(self, anchor: Dict[str, Any], leaves: List[Dict[str, Any]]) -> Dict[str, Any]:
        name = self._object(anchor["batch"])
        url = ("https://storage.googleapis.com/upload/storage/v1/b/%s/o?uploadType=media&name=%s"
               "&ifGenerationMatch=0" % (urllib.parse.quote(self.bucket, safe=""),
                                         urllib.parse.quote(name, safe="")))
        body = json.dumps(_batch_document(anchor, leaves)).encode()
        out = self._http("POST", url, body, {"Authorization": "Bearer " + self._token(),
                                             "Content-Type": "application/json"})
        return {"bucket": self.bucket, "object": name, "generation": out.get("generation")}

    def check(self, anchor: Dict[str, Any], receipt: Dict[str, Any]) -> Dict[str, Any]:
        url = "https://storage.googleapis.com/storage/v1/b/%s/o/%s?alt=media" % (
            urllib.parse.quote(receipt["bucket"], safe=""), urllib.parse.quote(receipt["object"], safe=""))
        doc = self._http("GET", url, None, {"Authorization": "Bearer " + self._token()})
        ok = doc.get("commitment") == anchor["commitment"]
        return {"ok": ok, "detail": "bucket copy matches" if ok else "bucket copy differs"}


EXPLORERS = {8453: "https://basescan.org/tx/", 84532: "https://sepolia.basescan.org/tx/",
             1: "https://etherscan.io/tx/", 11155111: "https://sepolia.etherscan.io/tx/"}


class EvmBackend:
    """Posts the commitment to an EVM chain as the data of a zero-value transaction to itself.

    No contract, so nothing to deploy or audit: the transaction's input is
    "FWA1" + batch number + commitment (44 bytes). On Base that costs a fraction
    of a cent to a few cents. Default RPC is Base Sepolia (free test network).
    The signing key comes from FAIREWALL_ANCHOR_KEY (keep it in Secret Manager);
    it only ever needs enough ETH for gas.
    """

    name = "evm"

    def __init__(self, rpc_url: Optional[str] = None, private_key: Optional[str] = None,
                 transport: Optional[Callable[..., Any]] = None) -> None:
        self.rpc_url = rpc_url or os.environ.get("FAIREWALL_ANCHOR_RPC", "https://sepolia.base.org")
        self._key = private_key or os.environ.get("FAIREWALL_ANCHOR_KEY")
        self._rpc_call = transport or self._post_rpc
        self._id = 0

    def _post_rpc(self, method: str, params: List[Any]) -> Any:
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}).encode()
        out = _http("POST", self.rpc_url, body, {"Content-Type": "application/json"})
        if out.get("error"):
            raise AnchorError("RPC %s failed: %s" % (method, out["error"].get("message", out["error"])))
        return out.get("result")

    def rpc(self, method: str, *params: Any) -> Any:
        return self._rpc_call(method, list(params))

    def publish(self, anchor: Dict[str, Any], leaves: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not self._key:
            raise AnchorError("No signing key: set FAIREWALL_ANCHOR_KEY to a funded account's key.")
        try:
            from eth_account import Account  # type: ignore
        except ImportError as exc:
            raise AnchorError("EVM anchoring needs `pip install 'fairewall[anchor]'` (eth-account)") from exc
        account = Account.from_key(self._key)
        data = "0x" + tx_data(anchor["batch"], anchor["commitment"]).hex()
        chain_id = int(self.rpc("eth_chainId"), 16)
        nonce = int(self.rpc("eth_getTransactionCount", account.address, "pending"), 16)
        base = int(self.rpc("eth_getBlockByNumber", "latest", False)["baseFeePerGas"], 16)
        tip = int(self.rpc("eth_maxPriorityFeePerGas"), 16)
        gas = int(self.rpc("eth_estimateGas", {"from": account.address, "to": account.address,
                                               "value": "0x0", "data": data}), 16)
        tx = {"type": 2, "chainId": chain_id, "nonce": nonce, "to": account.address, "value": 0,
              "data": data, "gas": gas + gas // 5, "maxPriorityFeePerGas": tip,
              "maxFeePerGas": base * 2 + tip}
        signed = Account.sign_transaction(tx, self._key)
        raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
        tx_hash = self.rpc("eth_sendRawTransaction", "0x" + bytes(raw).hex())
        return {"chain_id": chain_id, "tx": tx_hash, "from": account.address,
                "explorer": EXPLORERS.get(chain_id, "") + tx_hash if chain_id in EXPLORERS else ""}

    def check(self, anchor: Dict[str, Any], receipt: Dict[str, Any]) -> Dict[str, Any]:
        tx = self.rpc("eth_getTransactionByHash", receipt["tx"])
        if not tx:
            return {"ok": False, "detail": "transaction not found on chain %s" % receipt.get("chain_id")}
        expected = "0x" + tx_data(anchor["batch"], anchor["commitment"]).hex()
        if (tx.get("input") or tx.get("data") or "").lower() != expected:
            return {"ok": False, "detail": "transaction data does not match the commitment"}
        if not tx.get("blockNumber"):
            return {"ok": False, "pending": True, "detail": "transaction not mined yet"}
        block = self.rpc("eth_getBlockByNumber", tx["blockNumber"], False)
        when = int(block["timestamp"], 16)
        return {"ok": True, "block": int(tx["blockNumber"], 16), "block_time": when,
                "detail": "on chain in block %d at %s UTC" % (
                    int(tx["blockNumber"], 16), time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(when)))}


def _http(method: str, url: str, body: Optional[bytes], headers: Dict[str, str],
          timeout: float = 20.0) -> Dict[str, Any]:
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise AnchorError("%s %s returned HTTP %d: %s" % (method, url.split("?")[0], exc.code, detail)) from exc
    except (urllib.error.URLError, OSError) as exc:
        raise AnchorError("%s unreachable: %s" % (url.split("?")[0], exc)) from exc


def _batch_document(anchor: Dict[str, Any], leaves: List[Dict[str, Any]]) -> Dict[str, Any]:
    """What goes into the locked bucket: the batch and its leaves (hashes, not record content)."""
    return {"version": 1, "batch": anchor["batch"], "created": anchor["created"],
            "root": anchor["root"], "prev": anchor["prev"], "commitment": anchor["commitment"],
            "size": anchor["size"], "ranges": anchor["ranges"],
            "leaves": [[x["log_id"], x["seq"], x["hash"]] for x in leaves]}


# ---------------------------------------------------------------------- anchorer

class Anchorer:
    """Seals audit records into Merkle batches and publishes them. Run it on a schedule."""

    def __init__(self, target: Any, backends: Sequence[Any] = (), *, max_leaves: int = 200_000,
                 audit: Any = None, clock: Callable[[], float] = time.time) -> None:
        self.db = Database(target, schema="fairewall_audit")
        self.db.create(_SCHEMA)
        self.backends = list(backends)
        self.max_leaves = max_leaves
        self.audit = audit
        self._clock = clock

    # ------------------------------------------------------------------ seal

    def seal(self) -> Optional[Dict[str, Any]]:
        """Batch every unanchored record into one Merkle tree. None if there is nothing new."""
        with self.db.transaction() as db:
            progress = {r["log_id"]: (r["last_seq"], r["last_hash"])
                        for r in db.execute("SELECT * FROM anchor_progress")}
            logs = [r["log_id"] for r in db.execute("SELECT log_id FROM audit_logs ORDER BY log_id")]
            leaves: List[Dict[str, Any]] = []
            ranges: Dict[str, List[int]] = {}
            new_progress: Dict[str, Tuple[int, str]] = {}
            for log_id in logs:
                if len(leaves) >= self.max_leaves:
                    break
                last_seq, last_hash = progress.get(log_id, (-1, GENESIS))
                rows = list(db.execute(
                    "SELECT seq, hash, prev_hash, body FROM audit_records WHERE log_id=? AND seq>?"
                    " ORDER BY seq LIMIT ?", (log_id, last_seq, self.max_leaves - len(leaves))))
                expected_prev, expected_seq = last_hash, last_seq + 1
                for r in rows:
                    body = json.loads(r["body"])
                    if (r["seq"] != expected_seq or r["prev_hash"] != expected_prev
                            or record_hash(body) != r["hash"] or body.get("hash") != r["hash"]):
                        raise AnchorError(
                            "Audit log %s is broken at record %d (gap, bad link or edited content); "
                            "refusing to anchor it. Investigate before sealing." % (log_id, r["seq"]))
                    leaves.append({"log_id": log_id, "seq": r["seq"], "hash": r["hash"]})
                    expected_prev, expected_seq = r["hash"], r["seq"] + 1
                if rows:
                    ranges[log_id] = [rows[0]["seq"], rows[-1]["seq"]]
                    new_progress[log_id] = (rows[-1]["seq"], rows[-1]["hash"])
            if not leaves:
                return None
            last = db.execute("SELECT batch, commitment FROM anchors ORDER BY batch DESC LIMIT 1").fetchone()
            batch = (last["batch"] + 1) if last else 0
            prev = last["commitment"] if last else ZERO
            root = merkle_root([leaf_hash(leaf_data(x["log_id"], x["seq"], x["hash"])) for x in leaves]).hex()
            anchor = {"batch": batch, "created": self._clock(), "root": root, "prev": prev,
                      "commitment": commitment(batch, prev, root, len(leaves)), "size": len(leaves),
                      "ranges": ranges, "status": "sealed", "receipts": {}}
            db.execute("INSERT INTO anchors (batch, created, root, prev, commitment, size, ranges, status)"
                       " VALUES (?,?,?,?,?,?,?,?)",
                       (batch, anchor["created"], root, prev, anchor["commitment"], len(leaves),
                        json.dumps(ranges), "sealed"))
            for log_id, (seq, h) in new_progress.items():
                db.execute("INSERT INTO anchor_progress VALUES (?,?,?) ON CONFLICT(log_id) DO UPDATE"
                           " SET last_seq=excluded.last_seq, last_hash=excluded.last_hash", (log_id, seq, h))
        return anchor

    # --------------------------------------------------------------- publish

    def publish(self) -> List[Dict[str, Any]]:
        """Send every batch not yet on every backend. Failures are kept and retried next time."""
        done = []
        for anchor in self.anchors(status_not="anchored"):
            receipts, errors = dict(anchor["receipts"]), []
            leaves = None
            for backend in self.backends:
                if backend.name in receipts:
                    continue
                try:
                    leaves = leaves if leaves is not None else self._leaves(anchor)
                    receipts[backend.name] = backend.publish(anchor, leaves)
                except Exception as exc:
                    errors.append("%s: %s" % (backend.name, exc))
            status = "anchored" if all(b.name in receipts for b in self.backends) else "sealed"
            with self.db.transaction() as db:
                db.execute("UPDATE anchors SET receipts=?, status=?, error=? WHERE batch=?",
                           (json.dumps(receipts), status, "; ".join(errors)[:1000], anchor["batch"]))
            anchor.update(receipts=receipts, status=status, error="; ".join(errors))
            if self.audit is not None and status == "anchored":
                self.audit.append("audit_anchored", {"batch": anchor["batch"], "root": anchor["root"],
                                                     "commitment": anchor["commitment"],
                                                     "size": anchor["size"], "receipts": receipts})
            done.append(anchor)
        return done

    def run_once(self) -> Dict[str, Any]:
        sealed = self.seal()
        published = self.publish() if self.backends else []
        return {"sealed": sealed, "published": published}

    def run_forever(self, interval_s: float = 600.0, log: Callable[[str], None] = print) -> None:
        while True:
            try:
                out = self.run_once()
                if out["sealed"]:
                    log("[anchor] sealed batch %d: %d records, root %s"
                        % (out["sealed"]["batch"], out["sealed"]["size"], out["sealed"]["root"][:16]))
                for a in out["published"]:
                    log("[anchor] batch %d %s %s" % (a["batch"], a["status"], a.get("error") or
                                                      json.dumps(a["receipts"])))
            except Exception as exc:  # keep running; a missed interval is caught up next time
                log("[anchor] error: %s" % exc)
            time.sleep(interval_s)

    # ----------------------------------------------------------------- read

    def anchors(self, status_not: Optional[str] = None) -> List[Dict[str, Any]]:
        sql, args = "SELECT * FROM anchors", []
        if status_not:
            sql += " WHERE status != ?"
            args.append(status_not)
        with self.db.transaction() as db:
            rows = list(db.execute(sql + " ORDER BY batch", args))
        return [self._anchor(r) for r in rows]

    @staticmethod
    def _anchor(row: Any) -> Dict[str, Any]:
        out = dict(row)
        out["ranges"] = json.loads(out["ranges"])
        out["receipts"] = json.loads(out["receipts"] or "{}")
        return out

    def _leaves(self, anchor: Dict[str, Any], with_body: bool = False) -> List[Dict[str, Any]]:
        out = []
        with self.db.transaction() as db:
            for log_id in sorted(anchor["ranges"]):
                lo, hi = anchor["ranges"][log_id]
                for r in db.execute("SELECT seq, hash, body FROM audit_records WHERE log_id=? AND seq>=?"
                                    " AND seq<=? ORDER BY seq", (log_id, lo, hi)):
                    leaf = {"log_id": log_id, "seq": r["seq"], "hash": r["hash"]}
                    if with_body:
                        leaf["body"] = r["body"]
                    out.append(leaf)
        return out

    # --------------------------------------------------------------- verify

    def verify(self, online: bool = False) -> Dict[str, Any]:
        """Re-derive every batch from the records, check the links, and optionally the backends."""
        problems: List[str] = []
        prev = ZERO
        checked = 0
        backends = {b.name: b for b in self.backends}
        for anchor in self.anchors():
            leaves = self._leaves(anchor, with_body=True)
            for leaf in leaves:
                if record_hash(json.loads(leaf["body"])) != leaf["hash"]:
                    problems.append("batch %d: record %s#%d was edited after it was anchored"
                                    % (anchor["batch"], leaf["log_id"], leaf["seq"]))
            if len(leaves) != anchor["size"]:
                problems.append("batch %d: %d records anchored, %d found (records deleted?)"
                                % (anchor["batch"], anchor["size"], len(leaves)))
            root = merkle_root([leaf_hash(leaf_data(x["log_id"], x["seq"], x["hash"])) for x in leaves]).hex()
            if root != anchor["root"]:
                problems.append("batch %d: records no longer produce the anchored root" % anchor["batch"])
            if anchor["prev"] != prev:
                problems.append("batch %d: does not link to the batch before it" % anchor["batch"])
            if commitment(anchor["batch"], anchor["prev"], anchor["root"], anchor["size"]) != anchor["commitment"]:
                problems.append("batch %d: commitment does not match its contents" % anchor["batch"])
            if online:
                for name, receipt in anchor["receipts"].items():
                    backend = backends.get(name)
                    if backend is None:
                        continue
                    try:
                        result = backend.check(anchor, receipt)
                    except Exception as exc:
                        result = {"ok": False, "detail": str(exc)}
                    if not result.get("ok") and not result.get("pending"):
                        problems.append("batch %d: %s says %s" % (anchor["batch"], name, result["detail"]))
            prev = anchor["commitment"]
            checked += 1
        return {"valid": not problems, "batches": checked, "problems": problems}

    # ---------------------------------------------------------------- proof

    def proof(self, log_id: str, seq: int) -> Dict[str, Any]:
        """Everything needed to show one record was anchored, checkable offline."""
        for anchor in self.anchors():
            lo_hi = anchor["ranges"].get(log_id)
            if lo_hi and lo_hi[0] <= seq <= lo_hi[1]:
                leaves = self._leaves(anchor, with_body=True)
                index = next(i for i, x in enumerate(leaves) if x["log_id"] == log_id and x["seq"] == seq)
                hashed = [leaf_hash(leaf_data(x["log_id"], x["seq"], x["hash"])) for x in leaves]
                return {"version": 1, "log_id": log_id, "seq": seq,
                        "record": json.loads(leaves[index]["body"]), "batch": anchor["batch"],
                        "index": index, "size": anchor["size"], "path": merkle_path(hashed, index),
                        "root": anchor["root"], "prev": anchor["prev"],
                        "commitment": anchor["commitment"], "receipts": anchor["receipts"]}
        raise AnchorError("Record %s#%d is not in any sealed batch yet." % (log_id, seq))

    def close(self) -> None:
        self.db.close()


def check_proof(proof: Dict[str, Any], backend: Any = None) -> Dict[str, Any]:
    """Verify a proof from ``Anchorer.proof`` with no database. Optionally confirm it on chain."""
    record = proof["record"]
    h = record_hash(record)
    if h != record.get("hash"):
        return {"valid": False, "detail": "the record's content does not match its hash"}
    leaf = leaf_hash(leaf_data(proof["log_id"], proof["seq"], h))
    root = root_from_path(leaf, proof["path"]).hex()
    if root != proof["root"]:
        return {"valid": False, "detail": "the Merkle path does not lead to the anchored root"}
    if commitment(proof["batch"], proof["prev"], root, proof["size"]) != proof["commitment"]:
        return {"valid": False, "detail": "the commitment does not match the root"}
    out = {"valid": True, "detail": "record is in batch %d (root %s...)" % (proof["batch"], root[:16])}
    if backend is not None and backend.name in proof.get("receipts", {}):
        anchor = {"batch": proof["batch"], "commitment": proof["commitment"], "root": root}
        result = backend.check(anchor, proof["receipts"][backend.name])
        out["published"] = result
        out["valid"] = bool(result.get("ok"))
    return out
