"""The sandbox shop's own systems: an order ledger and an email outbox, per workspace.

This stands in for the business system fAIrewall protects. It is separate from
fAIrewall's records on purpose: the Lab shows both, so a judge can check that a
blocked action really wrote nothing, and an approved one wrote exactly once.
Every write is keyed by the action's idempotency key, so a retry is a lookup.
Money is integer paise.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from ..db import Database

_SCHEMA = """
CREATE TABLE IF NOT EXISTS orders (
    ws TEXT NOT NULL, order_id TEXT NOT NULL, item TEXT NOT NULL,
    paid INTEGER NOT NULL, refunded INTEGER NOT NULL DEFAULT 0, note TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (ws, order_id));
CREATE TABLE IF NOT EXISTS refunds (
    ws TEXT NOT NULL, receipt TEXT NOT NULL, idem_key TEXT NOT NULL UNIQUE, order_id TEXT NOT NULL,
    amount INTEGER NOT NULL, at REAL NOT NULL, PRIMARY KEY (ws, receipt));
CREATE TABLE IF NOT EXISTS outbox (
    ws TEXT NOT NULL, message_id TEXT NOT NULL, idem_key TEXT NOT NULL UNIQUE, recipient TEXT NOT NULL,
    subject TEXT NOT NULL, body TEXT NOT NULL, at REAL NOT NULL, PRIMARY KEY (ws, message_id))
"""


def rupees(paise: Optional[int]) -> str:
    if paise is None:
        return ""
    sign = "-" if paise < 0 else ""
    p = abs(int(paise))
    whole, frac = divmod(p, 100)
    s = str(whole)
    if len(s) > 3:  # Indian grouping: 12,34,567
        head, tail = s[:-3], s[-3:]
        groups = []
        while len(head) > 2:
            groups.insert(0, head[-2:])
            head = head[:-2]
        if head:
            groups.insert(0, head)
        s = ",".join(groups + [tail])
    return "%s₹%s.%02d" % (sign, s, frac)


class SandboxLedger:
    def __init__(self, target: Any) -> None:
        self.db = Database(target, schema="lab_shop")
        self.db.create(_SCHEMA)

    def seed(self, ws: str, orders, notes: Dict[str, str]) -> None:
        with self.db.transaction(lock="ws:" + ws) as db:
            for order_id, item, paid in orders:
                db.execute("INSERT INTO orders (ws, order_id, item, paid, note) VALUES (?,?,?,?,?)"
                           " ON CONFLICT DO NOTHING", (ws, order_id, item, paid, notes.get(order_id, "")))

    def order(self, ws: str, order_id: str) -> Optional[Dict[str, Any]]:
        with self.db.transaction(lock="ws:" + ws) as db:
            row = db.execute("SELECT * FROM orders WHERE ws=? AND order_id=?", (ws, order_id)).fetchone()
        if row is None:
            return None
        out = {"order_id": row["order_id"], "item": row["item"], "paid_paise": row["paid"],
               "refunded_paise": row["refunded"], "refundable_paise": row["paid"] - row["refunded"]}
        if row["note"]:
            out["note"] = row["note"]
        return out

    def refund(self, ws: str, order_id: str, amount: int, key: str) -> Dict[str, Any]:
        if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
            return {"outcome": "declined", "reason": "amount_not_positive_integer_paise"}
        with self.db.transaction(lock="ws:" + ws) as db:
            prior = db.execute("SELECT * FROM refunds WHERE idem_key=?", (key,)).fetchone()
            if prior:
                return {"outcome": "refunded", "receipt": prior["receipt"], "order_id": prior["order_id"],
                        "amount_paise": prior["amount"], "replayed": True}
            row = db.execute("SELECT * FROM orders WHERE ws=? AND order_id=?", (ws, order_id)).fetchone()
            if row is None:
                return {"outcome": "declined", "reason": "order_not_found", "order_id": order_id}
            if amount > row["paid"] - row["refunded"]:
                return {"outcome": "declined", "reason": "exceeds_refundable", "order_id": order_id,
                        "refundable_paise": row["paid"] - row["refunded"]}
            receipt = "rf_" + key[:12]
            db.execute("INSERT INTO refunds VALUES (?,?,?,?,?,?)", (ws, receipt, key, order_id, amount, time.time()))
            db.execute("UPDATE orders SET refunded=refunded+? WHERE ws=? AND order_id=?", (amount, ws, order_id))
        return {"outcome": "refunded", "receipt": receipt, "order_id": order_id, "amount_paise": amount,
                "replayed": False}

    def send(self, ws: str, to: str, subject: str, body: str, key: str) -> Dict[str, Any]:
        with self.db.transaction(lock="ws:" + ws) as db:
            prior = db.execute("SELECT message_id FROM outbox WHERE idem_key=?", (key,)).fetchone()
            if prior:
                return {"outcome": "delivered", "message_id": prior["message_id"], "replayed": True}
            message_id = "msg_" + key[:12]
            db.execute("INSERT INTO outbox VALUES (?,?,?,?,?,?,?)",
                       (ws, message_id, key, to[:200], subject[:200], body[:4000], time.time()))
        return {"outcome": "delivered", "message_id": message_id, "to": to, "replayed": False}

    def state(self, ws: str) -> Dict[str, Any]:
        with self.db.transaction(lock="ws:" + ws) as db:
            orders = [dict(r) for r in db.execute("SELECT order_id, item, paid, refunded FROM orders WHERE ws=?"
                                                  " ORDER BY order_id", (ws,))]
            refunds = [dict(r) for r in db.execute("SELECT receipt, idem_key, order_id, amount, at FROM refunds"
                                                   " WHERE ws=? ORDER BY at", (ws,))]
            outbox = [dict(r) for r in db.execute("SELECT message_id, idem_key, recipient, subject, body, at"
                                                  " FROM outbox WHERE ws=? ORDER BY at", (ws,))]
        for o in orders:
            o["paid_display"], o["refunded_display"] = rupees(o["paid"]), rupees(o["refunded"])
        for r in refunds:
            r["amount_display"] = rupees(r["amount"])
        return {"orders": orders, "refunds": refunds, "outbox": outbox}

    def close(self) -> None:
        self.db.close()


def dumps(value: Any) -> str:
    return json.dumps(value, default=str, separators=(",", ":"))
