"""fAIrewall CLI -- deterministic security utilities for autonomous AI agents."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

from .audit import verify_file
from .detectors import Detector, build_detectors
from .firewall import Firewall
from .policy import Policy
from .types import Action, Decision, Principal, Trust


def _detectors(args: argparse.Namespace) -> List[Detector]:
    return build_detectors(args.detector or [], args.onnx_model, args.onnx_tokenizer)


def _add_detector_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--detector", action="append", choices=["heuristic", "onnx"],
                   help="Enable a tier-1 detector (repeatable). Runs only on escalated calls.")
    p.add_argument("--onnx-model", help="Path to ONNX classifier (with --detector onnx)")
    p.add_argument("--onnx-tokenizer", help="Path to tokenizer.json (with --detector onnx)")


def _print_decision_summary(decision: Decision) -> None:
    action_color = {
        Action.ALLOW: "\033[92m",  # green
        Action.FLAG: "\033[93m",   # yellow
        Action.BLOCK: "\033[91m",  # red
    }.get(decision.action, "")
    reset = "\033[0m"

    print(f"Action:   {action_color}{decision.action.value.upper()}{reset}")
    print(f"Severity: {decision.severity.value.upper()}")
    print(f"Reason:   {decision.reason}")
    print(f"Latency:  {decision.latency_ms:.3f} ms")
    print(f"Tiers:    {', '.join(decision.tiers)} (route: {decision.route})")

    if decision.findings:
        print("\nFindings:")
        for idx, f in enumerate(decision.findings, 1):
            color = "\033[91m" if f.action is Action.BLOCK else "\033[93m"
            print(f"  {idx}. [{color}{f.rule_id}{reset}] ({f.severity.value}) {f.message}")
            if f.evidence:
                print(f"     Evidence: {json.dumps(f.evidence)}")


def cmd_inspect(args: argparse.Namespace) -> int:
    """Screen text against prompt-injection signatures."""
    trust = Trust(args.trust.lower())
    fw = Firewall(detectors=_detectors(args))
    decision = fw.inspect_input(args.text, trust=trust, source=args.source)

    if args.json:
        print(json.dumps(decision.to_dict(), indent=2))
    else:
        print(f"=== fAIrewall Inbound Screening ({args.source}) ===")
        print(f"Trust:    {trust.value}")
        print(f"Length:   {len(args.text)} chars")
        _print_decision_summary(decision)

    return 1 if decision.blocked else 0


def cmd_check_call(args: argparse.Namespace) -> int:
    """Adjudicate a candidate tool call against a policy."""
    policy = Policy.from_file(args.policy) if args.policy else Policy()
    fw = Firewall(policy=policy, detectors=_detectors(args))

    try:
        call_args = json.loads(args.args) if args.args else {}
    except json.JSONDecodeError as exc:
        print(f"Error parsing tool arguments as JSON: {exc}", file=sys.stderr)
        return 2

    roles = [r.strip() for r in args.roles.split(",") if r.strip()] if args.roles else []
    principal = Principal(id=args.principal, roles=roles)
    ctx = fw.session(session_id=args.session_id, principal=principal)
    if args.tainted:
        ctx.taint("cli-flag")

    decision = fw.inspect(tool=args.tool, arguments=call_args, ctx=ctx)

    if args.json:
        print(json.dumps(decision.to_dict(), indent=2))
    else:
        print(f"=== fAIrewall Outbound Tool Evaluation ===")
        print(f"Tool:      {args.tool}")
        print(f"Session:   {ctx.session_id}")
        print(f"Principal: {ctx.principal.id} (roles: {ctx.principal.roles})")
        print(f"Tainted:   {ctx.tainted}")
        print(f"Risk tier: {policy.risk_tier(args.tool, call_args)}")
        print(f"Policy:    v{policy.version} [{policy.fingerprint()}]")
        _print_decision_summary(decision)

    return 1 if decision.blocked else 0


def cmd_verify_audit(args: argparse.Namespace) -> int:
    """Verify cryptographic hash-chain integrity of an audit file."""
    if not os.path.exists(args.file):
        print(f"Audit log file not found: {args.file}", file=sys.stderr)
        return 2

    res = verify_file(args.file)
    if args.json:
        print(json.dumps({
            "valid": res.valid,
            "checked": res.checked,
            "broken_at": res.broken_at,
            "reason": res.reason,
        }, indent=2))
    else:
        print(f"=== fAIrewall Audit Verification ===")
        print(f"File:     {args.file}")
        print(f"Records:  {res.checked}")
        if res.valid:
            print("\033[92m[OK] Hash-chain is VALID and intact.\033[0m")
        else:
            print(f"\033[91m[FAIL] Chain broken at record {res.broken_at}: {res.reason}\033[0m")

    return 0 if res.valid else 1


def cmd_init_policy(args: argparse.Namespace) -> int:
    """Generate a starter policy file."""
    starter: Dict[str, Any] = {
        "version": "1",
        "default_deny": False,
        "max_spend_per_transaction": 500.0,
        "max_spend_per_session": 2000.0,
        "max_calls_per_minute": 60,
        "spend_arg_names": ["amount", "total", "value"],
        "allowed_egress_domains": ["api.stripe.com", "api.github.com"],
        "flag_only_rules": [],
        "unknown_tool_risk": "high",
        "detector_flag_threshold": 0.5,
        "detector_block_threshold": 0.85,
        "tools": {
            "web_search": {
                "risk_tier": "low",
                "produces_untrusted_output": True,
                "allowed_roles": [],
                "required_args": ["query"],
                "allowed_args": ["query", "limit"],
                "max_values": {},
                "arg_patterns": {},
                "rate_limit_per_minute": 30,
                "forbid_when_tainted": False,
                "require_human_approval": False,
            },
            "process_refund": {
                "risk_tier": "high",
                "allowed_roles": ["billing_admin", "finance"],
                "required_args": ["amount", "order_id"],
                "allowed_args": ["amount", "order_id", "reason"],
                "max_values": {"amount": 500.0},
                "arg_patterns": {"order_id": r"^ord_[a-zA-Z0-9]+$"},
                "rate_limit_per_minute": 10,
                "forbid_when_tainted": True,
                "require_human_approval": False,
            },
            "send_email": {
                "risk_tier": "high",
                "allowed_roles": ["agent"],
                "required_args": ["recipient", "body"],
                "allowed_args": ["recipient", "subject", "body"],
                "max_values": {},
                "arg_patterns": {},
                "rate_limit_per_minute": 20,
                "forbid_when_tainted": False,
                "require_human_approval": False,
            },
        },
    }

    content: str
    fmt = args.format.lower()
    if fmt == "yaml":
        try:
            import yaml  # type: ignore
            content = yaml.dump(starter, sort_keys=False)
        except ImportError:
            print("PyYAML not installed. Defaulting to JSON format.", file=sys.stderr)
            content = json.dumps(starter, indent=2)
    else:
        content = json.dumps(starter, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(content + "\n")
        print(f"Policy scaffold written to {args.output}")
    else:
        print(content)

    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Launch the HTTP proxy gateway."""
    try:
        from .proxy import run_server
    except ImportError as exc:
        print(f"Failed to load proxy: {exc}. Ensure fastapi and uvicorn are installed.", file=sys.stderr)
        return 2

    run_server(
        host=args.host,
        port=args.port,
        policy_path=args.policy,
        audit_path=args.audit,
        shadow=args.shadow,
        upstream_url=args.upstream_url,
        api_key=args.api_key,
        detectors=_detectors(args),
    )
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="fairewall",
        description="Deterministic security firewall for autonomous AI agents.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # inspect
    p_inspect = subparsers.add_parser("inspect", help="Screen inbound text for prompt injection")
    p_inspect.add_argument("text", help="Text to screen")
    p_inspect.add_argument("--trust", choices=["user", "untrusted", "trusted"], default="user",
                           help="Provenance trust level (default: user)")
    p_inspect.add_argument("--source", default="cli", help="Source identifier")
    p_inspect.add_argument("--json", action="store_true", help="Output raw JSON")
    _add_detector_args(p_inspect)
    p_inspect.set_defaults(func=cmd_inspect)

    # check-call
    p_call = subparsers.add_parser("check-call", help="Evaluate a candidate tool call against a policy")
    p_call.add_argument("tool", help="Tool name")
    p_call.add_argument("args", nargs="?", default="{}", help="Tool arguments as JSON")
    p_call.add_argument("--policy", help="Path to policy JSON/YAML file")
    p_call.add_argument("--session-id", default="cli_session", help="Session ID")
    p_call.add_argument("--principal", default="cli_user", help="Principal ID")
    p_call.add_argument("--roles", default="", help="Comma-separated principal roles")
    p_call.add_argument("--tainted", action="store_true", help="Mark session as already tainted")
    p_call.add_argument("--json", action="store_true", help="Output raw JSON")
    _add_detector_args(p_call)
    p_call.set_defaults(func=cmd_check_call)

    # verify-audit
    p_audit = subparsers.add_parser("verify-audit", help="Verify cryptographic hash-chain of an audit file")
    p_audit.add_argument("file", help="Path to audit JSONL file")
    p_audit.add_argument("--json", action="store_true", help="Output raw JSON")
    p_audit.set_defaults(func=cmd_verify_audit)

    # init-policy
    p_init = subparsers.add_parser("init-policy", help="Scaffold a starter policy configuration")
    p_init.add_argument("--format", choices=["json", "yaml"], default="json", help="Output format")
    p_init.add_argument("--output", "-o", help="Output file path (default: stdout)")
    p_init.set_defaults(func=cmd_init_policy)

    # serve
    p_serve = subparsers.add_parser("serve", help="Launch the HTTP proxy gateway")
    p_serve.add_argument("--policy", help="Path to policy JSON/YAML file")
    p_serve.add_argument("--audit", help="Path to audit log JSONL file")
    p_serve.add_argument("--host", default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    p_serve.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    p_serve.add_argument("--shadow", action="store_true", help="Run in shadow mode (log but do not block)")
    p_serve.add_argument(
        "--upstream-url", "--upstream",
        dest="upstream_url",
        default=None,
        help="Upstream LLM base URL to proxy to (default: https://api.openai.com). "
             "Can also be set via FAIREWALL_UPSTREAM_URL environment variable.",
    )
    p_serve.add_argument(
        "--api-key",
        dest="api_key",
        default=None,
        help="API key required to access management endpoints (/v1/inspect/*, "
             "/v1/commit/tool, /v1/audit/verify). Can also be set via FAIREWALL_API_KEY "
             "environment variable. When unset, endpoints are unauthenticated (local dev only).",
    )
    _add_detector_args(p_serve)
    p_serve.set_defaults(func=cmd_serve)

    parsed = parser.parse_args(argv)
    if not hasattr(parsed, "func"):
        parser.print_help()
        return 1

    return parsed.func(parsed)


if __name__ == "__main__":
    sys.exit(main())
