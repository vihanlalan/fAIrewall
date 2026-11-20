"""Policy diff: replay one log under two policies and report changed verdicts."""

import json

from fairewall.cli import main
from fairewall.policy import Policy, ToolPolicy
from fairewall.report import build_diff, render_diff_text


def _old():
    return Policy(version="old", tools={
        "refund": ToolPolicy("refund", max_values={"amount": 300.0}),
        "send_contract": ToolPolicy("send_contract", require_human_approval=True),
        "lookup": ToolPolicy("lookup"),
    })


def _new():
    return Policy(version="new", tools={
        "refund": ToolPolicy("refund", max_values={"amount": 100.0}),        # tighter
        "send_contract": ToolPolicy("send_contract"),                        # approval dropped
        "lookup": ToolPolicy("lookup"),
    })


LOG = [
    {"session_id": "a", "tool": "refund", "arguments": {"amount": 50.0}},     # same
    {"session_id": "a", "tool": "refund", "arguments": {"amount": 200.0}},    # auto -> blocked
    {"session_id": "b", "tool": "send_contract", "arguments": {"customer": "K"}},  # review -> auto
    {"session_id": "b", "tool": "lookup", "arguments": {"q": "x"}},           # same
]


def test_diff_counts_and_directions():
    d = build_diff(LOG, _old(), _new())
    assert d["total_calls"] == 4
    assert d["changed"] == 2 and d["stricter"] == 1 and d["looser"] == 1
    assert d["old"]["buckets"] == {"auto_approved": 3, "human_review": 1, "blocked": 0}
    assert d["new"]["buckets"] == {"auto_approved": 3, "human_review": 0, "blocked": 1}
    assert d["by_tool"] == {"refund": {"stricter": 1, "looser": 0},
                            "send_contract": {"stricter": 0, "looser": 1}}
    stricter = next(e for e in d["examples"] if e["direction"] == "stricter")
    assert stricter["record"] == 2 and "financial.transaction_limit" in stricter["rules_added"]
    looser = next(e for e in d["examples"] if e["direction"] == "looser")
    assert looser["rules_removed"] == ["schema.human_approval_required"]


def test_identical_policies_have_no_changes():
    d = build_diff(LOG, _old(), _old())
    assert d["changed"] == 0 and d["examples"] == []
    assert "No call changes verdict" in render_diff_text(d)


def test_looser_examples_listed_first_and_capped():
    log = [{"session_id": "s%d" % i, "tool": "refund", "arguments": {"amount": 200.0}}
           for i in range(5)] + [{"session_id": "z", "tool": "send_contract", "arguments": {}}]
    d = build_diff(log, _old(), _new(), max_examples=2)
    assert d["examples"][0]["direction"] == "looser"
    assert len(d["examples"]) == 2 and d["examples_truncated"]


def test_each_policy_keeps_its_own_session_budget():
    # Old: no session budget. New: $250 per session. Third $100 refund only blocked under new.
    old = Policy(max_spend_per_session=10_000.0)
    new = Policy(max_spend_per_session=250.0)
    log = [{"session_id": "s", "tool": "pay", "arguments": {"amount": 100.0}}] * 3
    d = build_diff(log, old, new)
    assert d["stricter"] == 1 and d["examples"][0]["record"] == 3


def test_render_mentions_looser():
    text = render_diff_text(build_diff(LOG, _old(), _new()))
    assert "1 stricter, 1 LOOSER" in text
    assert "HUMAN REVIEW   -> AUTO-APPROVED" in text


def _write(tmp_path):
    old_p, new_p, log_p = tmp_path / "old.json", tmp_path / "new.json", tmp_path / "log.jsonl"
    old_p.write_text(json.dumps(_old().to_dict()))
    new_p.write_text(json.dumps(_new().to_dict()))
    log_p.write_text("\n".join(json.dumps(r) for r in LOG))
    return str(old_p), str(new_p), str(log_p)


def test_cli_diff_text_and_fail_on_looser(tmp_path, capsys):
    old_p, new_p, log_p = _write(tmp_path)
    assert main(["diff", old_p, new_p, log_p]) == 0
    assert "Verdict changed on 2 calls" in capsys.readouterr().out
    assert main(["diff", old_p, new_p, log_p, "--fail-on-looser"]) == 1
    # Reversed, the refund change becomes the looser one.
    assert main(["diff", new_p, old_p, log_p, "--fail-on-looser"]) == 1
    assert main(["diff", old_p, old_p, log_p, "--fail-on-looser"]) == 0


def test_cli_diff_json_and_presets(tmp_path, capsys):
    _, _, log_p = _write(tmp_path)
    assert main(["diff", "ZAPIER_SME", "COPILOT_ENTERPRISE", log_p, "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["total_calls"] == 4


def test_cli_diff_bad_policy(tmp_path, capsys):
    _, _, log_p = _write(tmp_path)
    assert main(["diff", "NOT_A_PRESET", "ZAPIER_SME", log_p]) == 2
    assert "neither a policy file nor a known preset" in capsys.readouterr().err
