"""fAIrewall proxy module."""

from __future__ import annotations

from typing import Optional

from ..audit import AuditLog
from ..firewall import Firewall
from ..policy import Policy


def create_app(
    firewall: Optional[Firewall] = None,
    policy: Optional[Policy] = None,
    audit_path: Optional[str] = None,
    shadow: bool = False,
    upstream_url: Optional[str] = None,
    api_key: Optional[str] = None,
):
    from .app import create_app as _create_app
    return _create_app(
        firewall=firewall,
        policy=policy,
        audit_path=audit_path,
        shadow=shadow,
        upstream_url=upstream_url,
        api_key=api_key,
    )


def run_server(
    host: str = "127.0.0.1",
    port: int = 8000,
    policy_path: Optional[str] = None,
    audit_path: Optional[str] = None,
    shadow: bool = False,
    upstream_url: Optional[str] = None,
    api_key: Optional[str] = None,
) -> None:
    """Run the proxy using uvicorn."""
    try:
        import uvicorn  # type: ignore
    except ImportError as exc:
        raise ImportError("Running the proxy server requires `pip install uvicorn`") from exc

    policy = Policy.from_file(policy_path) if policy_path else Policy()
    audit = AuditLog(path=audit_path) if audit_path else None
    fw = Firewall(policy=policy, audit=audit, shadow=shadow)
    app = create_app(firewall=fw, upstream_url=upstream_url, api_key=api_key)

    print(f"[fAIrewall] Starting proxy server on http://{host}:{port}")
    print(f"[fAIrewall] Policy: v{policy.version} [{policy.fingerprint()}] | Shadow: {shadow}")
    if api_key:
        print("[fAIrewall] Management endpoints are authenticated (API key configured).")
    else:
        import os
        if os.environ.get("FAIREWALL_API_KEY"):
            print("[fAIrewall] Management endpoints are authenticated (FAIREWALL_API_KEY set).")
        else:
            print("[fAIrewall] WARNING: Management endpoints have no authentication. "
                  "Set --api-key or FAIREWALL_API_KEY before exposing externally.")
    uvicorn.run(app, host=host, port=port)


__all__ = ["create_app", "run_server"]
