"""03_audit_trail_verification.py

Demonstration of fAIrewall's tamper-evident audit logging:
1. Logs multiple agent actions with SHA-256 hash-chaining.
2. Cryptographically verifies the intact chain.
3. Simulates a malicious database/file modification and verifies that the tampered record is detected.
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from fairewall import AuditLog, Firewall, Policy, verify_file


def main():
    print("=== Tamper-Evident Audit Trail Demonstration ===")

    with tempfile.TemporaryDirectory() as tmpdir:
        audit_file = os.path.join(tmpdir, "production_audit.jsonl")
        audit = AuditLog(path=audit_file)
        fw = Firewall(policy=Policy(), audit=audit)

        print(f"\n[Step 1] Logging agent actions to {audit_file}...")
        fw.inspect_input("User asked for revenue report", source="user_chat")
        fw.inspect("generate_report", {"quarter": "Q3"}, session_id="s1")
        fw.inspect("send_email", {"to": "cfo@company.com", "body": "Attached"}, session_id="s1")

        # Verify intact chain
        v1 = verify_file(audit_file)
        print(f"\n[Step 2] Initial cryptographic chain verification:")
        print(f"  Valid: {v1.valid} | Records verified: {v1.checked} | Chain head: {audit.head[:16]}...")
        assert v1.valid is True

        # Simulate tampering with record #1
        print("\n[Step 3] Simulating attacker tampering with audit file record #1...")
        with open(audit_file, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]

        original_recipient = lines[2]["arguments"]["to"]
        # Attacker alters the logged destination to hide exfiltration
        lines[2]["arguments"]["to"] = "attacker@external-leak.com"

        tampered_file = os.path.join(tmpdir, "tampered_audit.jsonl")
        with open(tampered_file, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(json.dumps(line) + "\n")

        # Verify tampered chain
        v2 = verify_file(tampered_file)
        print(f"[Step 4] Audit verification on tampered log:")
        print(f"  Valid: {v2.valid}")
        print(f"  Tamper detected at record: {v2.broken_at}")
        print(f"  Reason: {v2.reason}")
        assert v2.valid is False
        assert v2.broken_at == 2

        print("\n[SUCCESS] Tamper-evidence verified! Unauthorized modifications break the cryptographic chain.")


if __name__ == "__main__":
    main()
