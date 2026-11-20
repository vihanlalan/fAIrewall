"""Synthetic refund desk with durable review and an offline policy-change preview."""
from pathlib import Path
from tempfile import TemporaryDirectory

from fairewall import Policy, Principal
from fairewall.actions import ActionStore, RegisteredAction
from fairewall.report import build_diff, render_diff_text


def main():
    policy = Policy.from_file(str(Path(__file__).with_name("policy.json")))
    definition = {"name": "refund", "description": "Refund a verified order in USD",
                  "inputSchema": {"type": "object", "required": ["order", "amount"],
                                  "properties": {"order": {"type": "string"}, "amount": {"type": "number"}}}}
    action = RegisteredAction("synthetic-ledger", definition, "v1",
                              lambda args, key: {"receipt": key, "refunded": args["amount"]})
    principal = Principal("returns-desk")
    args = {"order": "demo-1", "amount": 40}
    with TemporaryDirectory() as directory:
        path = Path(directory) / "actions.sqlite"
        store = ActionStore(path, policy, [action])
        store.screen("email", principal, "My item was damaged.")
        log = []
        for session, amount in [("email", 40), ("verified", 140), ("verified", 40)]:
            record = store.submit("refund", dict(args, amount=amount), session, principal, str(amount)+session)
            log.append({"tool": "refund", "arguments": record["arguments"], "session_id": session})
            if session == "email":
                log[-1]["untrusted_input"] = "My item was damaged."
            print(session, amount, record["status"], record["rules"])

        restarted = ActionStore(path, policy, [action])
        approved = restarted.review(record["id"], "finance-reviewer")
        print("Released", approved["reviewer"], approved["result"], approved["policy_hash"])
        proposed = Policy.from_dict(policy.to_dict())
        proposed.tools["refund"].require_human_approval = False
        print(render_diff_text(build_diff(log, policy, proposed)))


if __name__ == "__main__":
    main()
