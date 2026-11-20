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
    p.add_argument("--detector", action="append", choices=["heuristic", "learned", "onnx"],
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


def cmd_serve_sdk(args: argparse.Namespace) -> int:
    """Launch the full SDK gateway with all configured platform adapters.

    Reads configuration from environment variables (or a .env file if
    python-dotenv is installed).  Only the adapters whose secrets are
    present in the environment are mounted; others are skipped with a
    warning.  See .env.example for the full variable reference.
    """
    try:
        import uvicorn  # type: ignore
    except ImportError:
        print("uvicorn is required: pip install uvicorn", file=sys.stderr)
        return 2

    # Allow CLI flags to override env vars
    if args.host:
        os.environ.setdefault("FAIREWALL_HOST", args.host)
    if args.port:
        os.environ.setdefault("FAIREWALL_PORT", str(args.port))
    if args.shadow:
        os.environ["FAIREWALL_SHADOW"] = "true"
    if args.preset:
        os.environ.setdefault("FAIREWALL_PRESET", args.preset)

    host = os.environ.get("FAIREWALL_HOST", args.host)
    port = int(os.environ.get("FAIREWALL_PORT", str(args.port)))

    print(f"Starting fAIrewall SDK Gateway on {host}:{port}")
    print("Platform adapters are auto-mounted from environment variables.")
    print("See .env.example for configuration reference.")
    print()

    uvicorn.run(
        "fairewall.server:app",
        host=host,
        port=port,
        reload=args.reload,
        log_level="info",
        proxy_headers=True,
    )
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
        reviewer_api_key=args.reviewer_key,
    )
    return 0


def cmd_simulate(args: argparse.Namespace) -> int:
    """Write a SYNTHETIC agent tool-call log for trying out the report."""
    from .harness import generate_log, write_log

    records = generate_log(count=args.count, seed=args.seed)
    write_log(records, args.output)
    print(f"Wrote {args.count} SYNTHETIC tool calls to {args.output}")
    print("This is invented demo data, not customer traffic.")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Replay a tool-call log and print what would be approved, reviewed, blocked."""
    from .presets import load_preset
    from .report import build_report, default_policy_for, load_log, render_text

    try:
        meta, records = load_log(args.log)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    if not records:
        print("Error: the log has no tool-call records.", file=sys.stderr)
        return 2

    if args.policy:
        policy = Policy.from_file(args.policy)
    elif args.preset:
        policy = load_preset(args.preset)
    else:
        policy = default_policy_for(meta) or Policy()

    synthetic = bool(meta.get("synthetic")) or args.synthetic
    try:
        report = build_report(records, policy, args.minutes_per_review, synthetic=synthetic,
                              detectors=_detectors(args))
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    out = json.dumps(report, indent=2) if args.json else render_text(report)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
        print(f"Wrote report to {args.output}")
    else:
        print(out)
    return 0


def _load_policy_arg(value: str) -> Policy:
    """A policy argument is a file path if one exists, otherwise a preset name."""
    if os.path.exists(value):
        return Policy.from_file(value)
    from .presets import load_preset
    try:
        return load_preset(value)
    except (KeyError, ValueError) as exc:
        raise ValueError(f"'{value}' is neither a policy file nor a known preset") from exc


def cmd_diff(args: argparse.Namespace) -> int:
    """Replay a log under two policies and show every call whose verdict changes."""
    from .report import build_diff, load_log, render_diff_text

    try:
        old_policy = _load_policy_arg(args.old)
        new_policy = _load_policy_arg(args.new)
        _, records = load_log(args.log)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    if not records:
        print("Error: the log has no tool-call records.", file=sys.stderr)
        return 2

    try:
        diff = build_diff(records, old_policy, new_policy, detectors=_detectors(args),
                          max_examples=args.examples, refund_metrics=args.refund_metrics)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    out = json.dumps(diff, indent=2) if args.json else render_diff_text(diff)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
        print(f"Wrote diff to {args.output}")
    else:
        print(out)
    # Non-zero only when asked, so the command can gate a CI pipeline.
    return 1 if (args.fail_on_looser and diff["looser"]) else 0


def cmd_demo(args: argparse.Namespace) -> int:
    """Serve the judge-facing demo page backed by the real engine."""
    try:
        import uvicorn  # type: ignore
        from .demo import create_demo_app
    except ImportError as exc:
        print(f"Failed to load the demo: {exc}. Install with: pip install -e \".[proxy]\"", file=sys.stderr)
        return 2
    print(f"[fAIrewall] Demo running at http://{args.host}:{args.port}/demo")
    print("[fAIrewall] Real engine, simulated tools. Press Ctrl+C to stop.")
    if args.host not in ("127.0.0.1", "localhost"):
        print("[fAIrewall] WARNING: the demo endpoints have no authentication.", file=sys.stderr)
    uvicorn.run(create_demo_app(), host=args.host, port=args.port, log_level="warning")
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
    p_serve.add_argument(
        "--reviewer-key",
        dest="reviewer_key",
        default=None,
        help="Key required to list, approve or reject held calls (/v1/approvals). "
             "Can also be set via FAIREWALL_REVIEWER_KEY. Defaults to --api-key; use a "
             "different key so an agent cannot approve its own calls.",
    )
    _add_detector_args(p_serve)
    p_serve.set_defaults(func=cmd_serve)

    # serve-sdk  (SDK gateway with all platform adapters auto-mounted)
    p_serve_sdk = subparsers.add_parser(
        "serve-sdk",
        help="Launch the SDK gateway with all configured platform adapters (reads .env)",
    )
    p_serve_sdk.add_argument(
        "--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)"
    )
    p_serve_sdk.add_argument(
        "--port", type=int, default=8000, help="Bind port (default: 8000)"
    )
    p_serve_sdk.add_argument(
        "--preset",
        default=None,
        help="Global policy preset (ZAPIER_SME | COPILOT_ENTERPRISE | "
             "SALESFORCE_CRM | WHATSAPP_BOT | UIPATH_RPA). "
             "Can also be set via FAIREWALL_PRESET env var.",
    )
    p_serve_sdk.add_argument(
        "--shadow", action="store_true",
        help="Log-only mode: decisions are recorded but never block.",
    )
    p_serve_sdk.add_argument(
        "--reload", action="store_true",
        help="Enable uvicorn auto-reload (development only).",
    )
    p_serve_sdk.set_defaults(func=cmd_serve_sdk)

    # simulate
    p_sim = subparsers.add_parser("simulate", help="Generate a SYNTHETIC tool-call log for demos")
    p_sim.add_argument("--count", type=int, default=1000, help="Number of tool calls (default: 1000)")
    p_sim.add_argument("--seed", type=int, default=None,
                       help="Random seed (default: a fresh random one, recorded in the log header)")
    p_sim.add_argument("--output", "-o", default="synthetic_log.jsonl", help="Output JSONL path")
    p_sim.set_defaults(func=cmd_simulate)

    # report
    p_rep = subparsers.add_parser(
        "report", help="Replay a tool-call log: what would be auto-approved, reviewed, or blocked")
    p_rep.add_argument("log", help="Path to a JSONL tool-call log")
    p_rep.add_argument("--minutes-per-review", type=float, required=True,
                       help="Minutes one manual review takes (your estimate; no default)")
    p_rep.add_argument("--policy", help="Path to policy JSON/YAML file")
    p_rep.add_argument("--preset", help="Policy preset name (e.g. ZAPIER_SME)")
    p_rep.add_argument("--synthetic", action="store_true", help="Stamp the report as synthetic")
    _add_detector_args(p_rep)
    p_rep.add_argument("--json", action="store_true", help="Output raw JSON")
    p_rep.add_argument("--output", "-o", help="Write the report to a file")
    p_rep.set_defaults(func=cmd_report)

    # diff
    from .suite import command as policy_suite
    suite = subparsers.add_parser("policy-suite", help="Run ordered policy fixtures and emit JUnit")
    suite.add_argument("policy")
    suite.add_argument("suite")
    suite.add_argument("--target", choices=("sdk", "gateway", "both"), default="sdk")
    suite.add_argument("--junit")
    suite.set_defaults(func=policy_suite)

    p_diff = subparsers.add_parser(
        "diff", help="Preview a policy change: replay a log under OLD and NEW, list changed verdicts")
    p_diff.add_argument("old", help="Current policy: a JSON/YAML file or a preset name")
    p_diff.add_argument("new", help="Proposed policy: a JSON/YAML file or a preset name")
    p_diff.add_argument("log", help="Path to a JSONL tool-call log")
    p_diff.add_argument("--refund-metrics", action="store_true",
                        help="Compare USD refund bands, reviewer labels and paired replay latency")
    p_diff.add_argument("--examples", type=int, default=20,
                        help="How many changed calls to list (default: 20)")
    p_diff.add_argument("--fail-on-looser", action="store_true",
                        help="Exit 1 if the new policy lets through anything the old one stopped")
    _add_detector_args(p_diff)
    p_diff.add_argument("--json", action="store_true", help="Output raw JSON")
    p_diff.add_argument("--output", "-o", help="Write the diff to a file")
    p_diff.set_defaults(func=cmd_diff)

    # demo
    p_demo = subparsers.add_parser("demo", help="Serve the browser demo for judges (real engine, simulated tools)")
    p_demo.add_argument("--host", default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    p_demo.add_argument("--port", type=int, default=8080, help="Port (default: 8080)")
    p_demo.set_defaults(func=cmd_demo)

    parsed = parser.parse_args(argv)
    if not hasattr(parsed, "func"):
        parser.print_help()
        return 1

    return parsed.func(parsed)


if __name__ == "__main__":
    sys.exit(main())
