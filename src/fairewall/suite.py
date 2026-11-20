"""Run ordered JSON policy fixtures against isolated local SDK and HTTP gateways."""
import json
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

from .sdk import GovernanceSDK
from .types import Trust


def run_suite(policy, steps, target):
    if not isinstance(steps, list) or not steps:
        raise ValueError("Provide a nonempty JSON array of policy steps")
    results = []
    for surface in (("sdk", "gateway") if target == "both" else (target,)):
        sdk = GovernanceSDK(policy)
        client = None
        if surface == "gateway":
            from fastapi.testclient import TestClient
            from .proxy.app import create_app
            client = TestClient(create_app(policy=policy, api_key="fixture"))
            client.headers.update({"X-API-Key": "fixture"})
        try:
            for index, step in enumerate(steps, 1):
                if not isinstance(step, dict) or not isinstance(step.get("rules"), list):
                    raise ValueError(f"Step {index} requires an object with a rules array")
                session = step.get("session", "fixture")
                expect = step["expect"]
                if expect not in ("allow", "block", "flag"):
                    raise ValueError("expect must be allow, block or flag")
                fields = set(step)
                if ("text" in fields) == ("tool" in fields):
                    raise ValueError("Each step needs exactly one of text or tool")
                if "text" in step:
                    trust = Trust(step.get("trust", "untrusted"))
                    if client:
                        res = client.post("/v1/inspect/input", json=dict(
                            text=step["text"], trust=trust.value, session_id=session))
                    else:
                        decision = sdk.screen(step["text"], trust=trust, session_id=session)
                else:
                    tool, args = step["tool"], step.get("arguments", {})
                    payload = dict(tool=tool, arguments=args, session_id=session)
                    if client:
                        res = client.post("/v1/inspect/tool", json=payload)
                    else:
                        decision = sdk.guard_action(tool, args, session_id=session)
                if client:
                    res.raise_for_status()
                    actual = res.json()["decision"]
                else:
                    actual = decision.to_dict()
                outcome = actual["action"]
                rules = sorted({f["rule_id"] for f in actual["findings"]})
                error = ""
                if outcome != expect or rules != sorted(step["rules"]):
                    error = f"expected {expect} {step['rules']}, got {outcome} {rules}"
                results.append((surface, step.get("name", str(index)), error))
                if client and "tool" in step and outcome != "block":
                    client.post("/v1/commit/tool", json=payload).raise_for_status()
        finally:
            if client:
                client.close()
    return results


def command(args):
    from .cli import _load_policy_arg
    try:
        steps = json.loads(Path(args.suite).read_text(encoding="utf-8"))
        results = run_suite(_load_policy_arg(args.policy), steps, args.target)
        failures = sum(bool(error) for _, _, error in results)
        xml = ET.Element("testsuite", name="fairewall", tests=str(len(results)), failures=str(failures))
        for surface, name, error in results:
            case = ET.SubElement(xml, "testcase", classname=surface, name=name)
            if error:
                ET.SubElement(case, "failure", message=error)
                print(f"{surface} {name}: {error}", file=sys.stderr)
        if args.junit:
            ET.ElementTree(xml).write(args.junit, encoding="utf-8", xml_declaration=True)
        print(f"{len(results)} checks, {failures} failed")
        return int(bool(failures))
    except (KeyError, ValueError, OSError, ImportError, TypeError) as exc:
        print(f"Policy suite error: {exc}", file=sys.stderr)
        return 2
