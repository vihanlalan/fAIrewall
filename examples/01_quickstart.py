import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from fairewall import Firewall, Policy, ToolPolicy


def main():
    print("=== 1. Define Declarative Security Policy ===")
    policy = Policy(
        max_spend_per_transaction=500.0,
        tools={
            "process_refund": ToolPolicy(
                name="process_refund",
                required_args=["amount", "order_id"],
                max_values={"amount": 500.0},
                forbid_when_tainted=True,
            )
        },
    )
    fw = Firewall(policy=policy)
    print(f"Policy version: {policy.version} [Fingerprint: {policy.fingerprint()}]")

    print("\n=== 2. Guard Python Tool Functions ===")
    @fw.guard()
    def process_refund(amount: float, order_id: str) -> str:
        return f"Successfully processed refund of ${amount:.2f} for {order_id}."

    # Call 1: Normal, legitimate call within policy
    print("\nExecuting legitimate refund ($120.00)...")
    res1 = process_refund(amount=120.0, order_id="ord_101", _session_id="session_A")
    print(f"Result: {res1}")

    # Call 2: Attempted spend beyond policy limit ($1,500.00)
    print("\nExecuting excessive refund ($1,500.00)...")
    res2 = process_refund(amount=1500.0, order_id="ord_102", _session_id="session_A")
    print(f"Result: {res2}")

    print("\n=== 3. Inspect Tamper-Evident Audit Log ===")
    for record in fw.audit.records():
        print(f"Seq {record['seq']}: [{record['event']}] tool={record.get('tool')} action={record.get('action')} hash={record['hash'][:16]}...")

    print(f"\nVerification status: {fw.audit.verify().valid} (checked {len(fw.audit.records())} records)")


if __name__ == "__main__":
    main()
