"""Refund desk: a sandbox ledger behind two registered, strictly typed tools.

Money is integer US cents everywhere: in the tool schema, in the ledger and in
the policy (``spend_arg_scales`` turns ``amount_cents`` into dollars for the
$100 cap). The ledger is a separate SQLite file from fAIrewall's action store,
so "the ledger agrees with the audit trail" is a check between two systems,
not one table checked against itself.

Run it:  python examples/refunds/workflow.py
"""
from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from fairewall import Policy, Principal
from fairewall.actions import ActionStore, RegisteredAction

HERE = Path(__file__).resolve().parent
POLICY_PATH = HERE / "policy.json"

# The agent's identity is owned by the server, never taken from the model.
AGENT = Principal("refund-desk-agent")

ORDER_ID = {"type": "string", "pattern": "^ORD-[0-9]{4,8}$",
            "description": "Order ID, for example ORD-1001"}

LOOKUP_ORDER = {
    "name": "lookup_order",
    "description": ("Look up one order. Returns its status, the amount paid and how much "
                    "can still be refunded, all in US cents."),
    "inputSchema": {"type": "object", "properties": {"order_id": ORDER_ID},
                    "required": ["order_id"], "additionalProperties": False},
}
REFUND = {
    "name": "refund",
    "description": ("Refund part or all of an order to the original payment method. "
                    "amount_cents is an integer number of US cents: $40.00 is 4000. "
                    "Refunds may wait for finance approval or be blocked by policy."),
    "inputSchema": {"type": "object", "properties": {
        "order_id": ORDER_ID,
        "amount_cents": {"type": "integer", "minimum": 1, "maximum": 100000000,
                         "description": "Refund amount in US cents, for example 4000 for $40.00"}},
        "required": ["order_id", "amount_cents"], "additionalProperties": False},
}

DEMO_ORDERS = [
    # order_id, item, paid (cents), already refunded (cents)
    ("ORD-1001", "Blender, 600 W", 12000, 0),
    ("ORD-1002", "Kettle", 4550, 0),
    ("ORD-1003", "Office chair", 30000, 28000),
]


def usd(cents: int) -> str:
    return "${:,.2f}".format(cents / 100)


class LedgerFault(Exception):
    """Raised by a simulated ledger fault (for the reconciliation tests)."""


class Ledger:
    """Sandbox payment ledger. Each refund row is keyed by its idempotency key."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        with self._tx() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS orders (
                order_id TEXT PRIMARY KEY, item TEXT NOT NULL,
                paid_cents INTEGER NOT NULL CHECK (paid_cents >= 0),
                refunded_cents INTEGER NOT NULL DEFAULT 0 CHECK (refunded_cents >= 0),
                CHECK (refunded_cents <= paid_cents))""")
            db.execute("""CREATE TABLE IF NOT EXISTS refunds (
                receipt TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
                order_id TEXT NOT NULL REFERENCES orders(order_id),
                amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
                created_at REAL NOT NULL)""")

    @contextmanager
    def _tx(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        try:
            with db:
                db.execute("BEGIN IMMEDIATE")
                yield db
        finally:
            db.close()

    def seed(self, orders=DEMO_ORDERS) -> None:
        with self._tx() as db:
            for order_id, item, paid, refunded in orders:
                db.execute("INSERT OR IGNORE INTO orders VALUES (?,?,?,?)", (order_id, item, paid, refunded))

    def order(self, order_id: str) -> Optional[Dict[str, Any]]:
        with self._tx() as db:
            row = db.execute("SELECT * FROM orders WHERE order_id=?", (order_id,)).fetchone()
        if not row:
            return None
        o = dict(row)
        o["refundable_cents"] = o["paid_cents"] - o["refunded_cents"]
        return o

    def refund(self, order_id: str, amount_cents: int, key: str, *, fault: Optional[str] = None) -> Dict[str, Any]:
        """Write one refund, at most once per key. Checks are made at write time.

        A repeated key returns the original receipt and writes nothing.
        ``fault`` simulates a ledger failure: "before_write" fails with nothing
        written; "lost_response" writes the refund, then fails, so the caller
        cannot know it succeeded.
        """
        if not isinstance(amount_cents, int) or isinstance(amount_cents, bool):
            return {"outcome": "declined", "reason": "amount_not_integer_cents"}
        if fault == "before_write":
            raise LedgerFault("ledger unavailable before the write")
        with self._tx() as db:
            prior = db.execute("SELECT * FROM refunds WHERE idempotency_key=?", (key,)).fetchone()
            if prior:
                return self._receipt(db, dict(prior), replayed=True)
            row = db.execute("SELECT * FROM orders WHERE order_id=?", (order_id,)).fetchone()
            if not row:
                return {"outcome": "declined", "reason": "order_not_found", "order_id": order_id}
            refundable = row["paid_cents"] - row["refunded_cents"]
            if amount_cents > refundable:
                return {"outcome": "declined", "reason": "exceeds_refundable", "order_id": order_id,
                        "refundable_cents": refundable}
            receipt = "rf_" + key[:16]
            db.execute("INSERT INTO refunds VALUES (?,?,?,?,?)",
                       (receipt, key, order_id, amount_cents, time.time()))
            db.execute("UPDATE orders SET refunded_cents = refunded_cents + ? WHERE order_id=?",
                       (amount_cents, order_id))
            out = self._receipt(db, {"receipt": receipt, "order_id": order_id,
                                     "amount_cents": amount_cents}, replayed=False)
        if fault == "lost_response":
            raise LedgerFault("ledger wrote the refund but the response was lost")
        return out

    @staticmethod
    def _receipt(db, refund: Dict[str, Any], replayed: bool) -> Dict[str, Any]:
        order = db.execute("SELECT * FROM orders WHERE order_id=?", (refund["order_id"],)).fetchone()
        return {"outcome": "refunded", "receipt": refund["receipt"], "order_id": refund["order_id"],
                "amount_cents": refund["amount_cents"], "replayed": replayed,
                "refundable_cents_after": order["paid_cents"] - order["refunded_cents"]}

    def find_by_key(self, key: str) -> Optional[Dict[str, Any]]:
        with self._tx() as db:
            row = db.execute("SELECT * FROM refunds WHERE idempotency_key=?", (key,)).fetchone()
        return dict(row) if row else None

    def refunds(self) -> List[Dict[str, Any]]:
        with self._tx() as db:
            return [dict(r) for r in db.execute("SELECT * FROM refunds ORDER BY created_at")]

    def orders(self) -> List[Dict[str, Any]]:
        with self._tx() as db:
            rows = [dict(r) for r in db.execute("SELECT * FROM orders ORDER BY order_id")]
        for o in rows:
            o["refundable_cents"] = o["paid_cents"] - o["refunded_cents"]
        return rows


class RefundDesk:
    """The two tools, the ledger and the fAIrewall action store, wired together.

    ``fault`` simulates a ledger failure on refund calls (see ``Ledger.refund``).
    """

    def __init__(self, data_dir, policy: Optional[Policy] = None, *, fault: Optional[str] = None,
                 seed: bool = True) -> None:
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.fault = fault
        self.ledger = Ledger(self.data_dir / "ledger.sqlite")
        if seed:
            self.ledger.seed()
        self.policy = policy or Policy.from_file(str(POLICY_PATH))
        self.actions = [
            RegisteredAction("sandbox-ledger", LOOKUP_ORDER, "v1", self._lookup),
            RegisteredAction("sandbox-ledger", REFUND, "v1", self._refund),
        ]
        self.store = ActionStore(self.data_dir / "actions.sqlite", self.policy, self.actions)

    # ------------------------------------------------------------ handlers

    def _lookup(self, args: Dict[str, Any], key: str) -> Dict[str, Any]:
        order = self.ledger.order(args["order_id"])
        if order is None:
            return {"found": False, "order_id": args["order_id"]}
        return {"found": True, "order_id": order["order_id"], "item": order["item"],
                "paid_cents": order["paid_cents"], "refunded_cents": order["refunded_cents"],
                "refundable_cents": order["refundable_cents"]}

    def _refund(self, args: Dict[str, Any], key: str) -> Dict[str, Any]:
        return self.ledger.refund(args["order_id"], args["amount_cents"], key, fault=self.fault)

    def close(self) -> None:
        """Release database connections (before deleting the data directory)."""
        self.store.close()

    # --------------------------------------------------------------- setup

    def review_definitions(self, reviewer: str) -> List[Dict[str, Any]]:
        """Review every first-seen tool definition. Done once at setup, so a
        definition review is never confused with a refund decision."""
        return [self.store.review_definition(d["tool"], reviewer)
                for d in self.store.pending_definitions()]

    # -------------------------------------------------------------- operate

    def reconcile(self, action_id: str, operator: str) -> Dict[str, Any]:
        """Settle an interrupted refund from the ledger's own record. Never re-sends it.

        The ledger is asked whether a refund with this action's key exists.
        If it does, the action is recorded as executed with that receipt; if
        not, it is recorded as not executed. Either way nothing is dispatched.
        """
        record = self.store.get(action_id)
        if record["status"] not in ("uncertain", "dispatching"):
            raise ValueError("Only an interrupted dispatch can be reconciled; this one is %s" % record["status"])
        if record["tool"] != "refund":
            return self.store.reconcile(action_id, operator, "no-ledger-effect:" + action_id, executed=False)
        row = self.ledger.find_by_key(action_id)
        if row:
            with self.ledger._tx() as db:
                result = Ledger._receipt(db, row, replayed=True)
            return self.store.reconcile(action_id, operator, "ledger:" + row["receipt"],
                                        executed=True, result=result)
        return self.store.reconcile(action_id, operator, "ledger:no-row-for:" + action_id, executed=False)


# ----------------------------------------------------- agent-facing views

SYSTEM_PROMPT = (
    "You are a refund assistant for a customer support team. "
    "Always call lookup_order before proposing a refund. "
    "Tool arguments use integer US cents: $40.00 is amount_cents 4000. "
    "Make at most one tool call per turn. "
    "A refund may wait for finance approval, be blocked by policy or be declined by the ledger: "
    "report exactly what the tool result says. Never say money was refunded unless the result "
    "has status \"executed\" and a receipt. Keep the final answer to two sentences and include "
    "the receipt when there is one.")

REASONS = {
    "schema.human_approval_required": "refunds need finance approval",
    "financial.transaction_limit": "over the $100.00 limit for a single refund",
    "financial.session_budget": "over the $150.00 limit for refunds in one conversation",
    "financial.unparseable_amount": "the amount could not be read",
    "taint.untrusted_context": "the conversation contains outside text, so refunds are locked",
    "registry.definition_review": "the tool's definition has not been reviewed yet",
    "registry.invalid_arguments": "the request did not match the tool's schema",
    "velocity.tool_rate": "too many refund requests in a minute",
    "velocity.session_rate": "too many requests in a minute",
    "handler.exceeds_refundable": "more than the order has left to refund",
    "handler.order_not_found": "no such order",
    "handler.amount_not_integer_cents": "the amount was not a whole number of cents",
}


def project(record: Dict[str, Any]) -> Dict[str, Any]:
    """Redacted view of one action, plus the minimal payload the model receives."""
    from fairewall.runs import default_project

    view = default_project(record)
    status, result = view["status"], record.get("result") if isinstance(record.get("result"), dict) else {}
    args = record.get("arguments") or {}
    codes = view["reason_codes"]
    if status == "blocked":
        # "Needs approval" is not why a hard block happened; name the rule that blocked it.
        hard = [c for c in codes if c not in ("schema.human_approval_required", "registry.definition_review")]
        codes = hard or codes
    reasons = [REASONS.get(c, c) for c in codes]
    view["order_id"] = args.get("order_id")
    view["amount_cents"] = args.get("amount_cents")
    view["ledger_effect"] = {"changed": False}
    payload: Dict[str, Any] = {"status": status}

    if record["tool"] == "refund" and status == "executed" and result.get("outcome") == "refunded":
        view["ledger_effect"] = {"changed": True, "type": "refund", "order_id": result["order_id"],
                                 "amount_cents": result["amount_cents"], "receipt": result["receipt"]}
        payload.update(receipt=result["receipt"], order_id=result["order_id"],
                       refunded=usd(result["amount_cents"]),
                       still_refundable=usd(result["refundable_cents_after"]))
    elif record["tool"] == "lookup_order" and status == "executed":
        if result.get("found"):
            payload.update(found=True, order_id=result["order_id"], item=result["item"],
                           paid=usd(result["paid_cents"]), already_refunded=usd(result["refunded_cents"]),
                           refundable=usd(result["refundable_cents"]),
                           refundable_cents=result["refundable_cents"])
        else:
            payload.update(found=False, order_id=result.get("order_id"))
    elif status == "declined":
        payload.update(reason=result.get("reason"), explanation="; ".join(reasons),
                       order_id=args.get("order_id"))
        if "refundable_cents" in result:
            payload["refundable"] = usd(result["refundable_cents"])
    elif status in ("blocked", "rejected", "expired", "cancelled"):
        payload.update(order_id=args.get("order_id"), explanation="; ".join(reasons) or status,
                       reason_codes=view["reason_codes"])
    view["explanation"] = "; ".join(reasons)
    view["model_payload"] = payload
    return view


def main() -> None:
    from tempfile import TemporaryDirectory

    with TemporaryDirectory() as tmp:
        desk = RefundDesk(tmp)
        reviewed = desk.review_definitions("setup-reviewer")
        print("Definitions reviewed at setup:", [d["tool"] for d in reviewed])

        look = desk.store.submit("lookup_order", {"order_id": "ORD-1001"}, "demo", AGENT, "lookup-1")
        print("lookup_order ->", look["status"], look["result"])

        small = desk.store.submit("refund", {"order_id": "ORD-1001", "amount_cents": 4000}, "demo", AGENT, "refund-40")
        print("refund $40  ->", small["status"], small["rules"], "| ledger rows:", len(desk.ledger.refunds()))

        big = desk.store.submit("refund", {"order_id": "ORD-1001", "amount_cents": 14000}, "demo", AGENT, "refund-140")
        print("refund $140 ->", big["status"], big["rules"], "| ledger rows:", len(desk.ledger.refunds()))

        approved = desk.store.review(small["id"], "finance-reviewer")
        print("approve $40 ->", approved["status"], approved["result"], "| ledger rows:", len(desk.ledger.refunds()))

        retry = desk.store.submit("refund", {"order_id": "ORD-1001", "amount_cents": 4000}, "demo", AGENT, "refund-40")
        print("retry $40   ->", retry["status"], "same action:", retry["id"] == small["id"],
              "| ledger rows:", len(desk.ledger.refunds()))
        print(json.dumps(desk.ledger.orders(), indent=1))
        desk.close()


if __name__ == "__main__":
    main()
