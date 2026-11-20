"""fAIrewall proxy module."""

from __future__ import annotations

from typing import Optional, Sequence

from ..audit import AuditLog
from ..detectors import Detector
from ..firewall import Firewall
from ..policy import Policy


def create_app(
    firewall: Optional[Firewall] = None,
    policy: Optional[Policy] = None,
    audit_path: Optional[str] = None,
    shadow: bool = False,
    upstream_url: Optional[str] = None,
    api_key: Optional[str] = None,
    detectors: Optional[Sequence[Detector]] = None,
    approvals=None,
    reviewer_api_key: Optional[str] = None,
    kill_switch_path: Optional[str] = None,
    learning: Optional[str] = None,
    source_sampling: bool = False,
    database: Optional[str] = None,
    action_baseline: Optional[str] = None,
    canaries: Optional[bool] = None,
):
    from .app import create_app as _create_app
    return _create_app(
        firewall=firewall,
        policy=policy,
        audit_path=audit_path,
        shadow=shadow,
        upstream_url=upstream_url,
        api_key=api_key,
        detectors=detectors,
        approvals=approvals,
        reviewer_api_key=reviewer_api_key,
        kill_switch_path=kill_switch_path,
        learning=learning,
        source_sampling=source_sampling,
        database=database,
        action_baseline=action_baseline,
        canaries=canaries,
    )


def run_server(
    host: str = "127.0.0.1",
    port: int = 8000,
    policy_path: Optional[str] = None,
    audit_path: Optional[str] = None,
    shadow: bool = False,
    upstream_url: Optional[str] = None,
    api_key: Optional[str] = None,
    detectors: Optional[Sequence[Detector]] = None,
    reviewer_api_key: Optional[str] = None,
    kill_switch_path: Optional[str] = None,
    control_plane_url: Optional[str] = None,
    gateway_token: Optional[str] = None,
    learning: Optional[str] = None,
    source_sampling: bool = False,
    database: Optional[str] = None,
    action_baseline: Optional[str] = None,
    canaries: Optional[bool] = None,
) -> None:
    """Run the proxy using uvicorn."""
    try:
        import uvicorn  # type: ignore
    except ImportError as exc:
        raise ImportError("Running the proxy server requires `pip install uvicorn`") from exc

    policy = Policy.from_file(policy_path) if policy_path else Policy()
    import os
    from ..db import redact_url
    from ..state import build_gateway_firewall
    try:
        fw = build_gateway_firewall(
            policy=policy, database=database, audit_path=audit_path, learning=learning,
            source_sampling=source_sampling, shadow=shadow, detectors=detectors,
            kill_switch_path=kill_switch_path, action_baseline=action_baseline, canaries=canaries)
    except ValueError as exc:
        raise SystemExit("[fAIrewall] %s" % exc)
    memory, sampler, state = fw.memory, fw.sampler, fw.state
    kill_switch_path = fw._kill_switch_path
    learning = memory.db.location if memory is not None else None
    app = create_app(firewall=fw, upstream_url=upstream_url, api_key=api_key,
                     reviewer_api_key=reviewer_api_key)

    control_plane_url = control_plane_url or os.environ.get("FAIREWALL_CONTROL_PLANE_URL")
    gateway_token = gateway_token or os.environ.get("FAIREWALL_GATEWAY_TOKEN")
    if control_plane_url or gateway_token:
        if not (control_plane_url and gateway_token):
            raise SystemExit("[fAIrewall] --control-plane and --gateway-token must be given together.")
        from ..control import ControlPlaneSync
        effective_key = api_key or os.environ.get("FAIREWALL_API_KEY")
        effective_reviewer = reviewer_api_key or os.environ.get("FAIREWALL_REVIEWER_KEY")
        sync = ControlPlaneSync(
            fw, control_plane_url, gateway_token,
            auth_required=bool(effective_key),
            separate_reviewer_key=bool(effective_reviewer) and effective_reviewer != effective_key,
        )
        ok = sync.sync_once()
        print(f"[fAIrewall] Control plane: {control_plane_url} "
              + ("(connected)" if ok else f"(not reachable yet: {sync.status['last_error']}; "
                                         "enforcing the local policy and retrying)"))
        if sync.status.get("policy"):
            p = sync.status["policy"]
            print(f"[fAIrewall] Policy from control plane: {p['name']} v{p['version']}"
                  + (" (shadow)" if p.get("shadow") else ""))
        sync.start()

    print(f"[fAIrewall] Starting proxy server on http://{host}:{port}")
    print(f"[fAIrewall] Console: http://{'127.0.0.1' if host in ('0.0.0.0', '::') else host}:{port}/console")
    print(f"[fAIrewall] Policy: v{policy.version} [{policy.fingerprint()}] | Shadow: {shadow}")
    if kill_switch_path:
        print(f"[fAIrewall] Kill switch state is saved to {kill_switch_path}")
    if fw.freezes():
        print(f"[fAIrewall] WARNING: kill switch is ON ({len(fw.freezes())} freeze(s)); "
              "tool calls in scope are blocked until released in the console.")
    print(f"[fAIrewall] Detector tier: {', '.join(d.name for d in fw.detectors) or 'off (rules only)'}")
    if state is not None:
        print(f"[fAIrewall] Shared state: {redact_url(state.db.location)} (sessions, freezes, approvals, "
              f"audit chain {fw.audit.log_id}). Safe to run several instances.")
    if memory is not None:
        print(f"[fAIrewall] Learning: on ({redact_url(learning)}). Unseen threats go to a reviewer "
              "at /v1/learning/cases; their decisions are learned.")
    if fw.baseline is not None:
        print(f"[fAIrewall] Action baseline: holds first-time actions ({fw.baseline.hold_when}).")
    if fw.canaries is not None:
        print("[fAIrewall] Canaries: on. Issue decoys with POST /v1/canaries (reviewer key).")
    if sampler is not None:
        print("[fAIrewall] Source sampling: on. New sources are fully deep-checked; trusted ones sampled.")
    if api_key:
        print("[fAIrewall] Management endpoints are authenticated (API key configured).")
    else:
        if os.environ.get("FAIREWALL_API_KEY"):
            print("[fAIrewall] Management endpoints are authenticated (FAIREWALL_API_KEY set).")
        else:
            print("[fAIrewall] WARNING: Management endpoints have no authentication. "
                  "Set --api-key or FAIREWALL_API_KEY before exposing externally.")
    uvicorn.run(app, host=host, port=port)


__all__ = ["create_app", "run_server"]
