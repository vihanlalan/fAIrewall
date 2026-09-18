"""fAIrewall SDK Gateway Server — auto-mounting entry point.

Reads environment variables at startup and mounts every platform adapter
whose secrets are present.  If a platform's env vars are missing the adapter
is skipped with a warning so one unconfigured platform does not bring down all
the others.

Usage
-----
Direct (development)::

    python -m fairewall.server          # reads .env automatically if python-dotenv installed
    fairewall serve-sdk                 # via CLI

Docker::

    docker compose up                   # reads docker-compose.yml → .env

Environment variables
---------------------
See .env.example in the project root for the full reference.

Global
~~~~~~
FAIREWALL_PRESET        Policy preset for any platform that does not have its own
                        override (ZAPIER_SME | COPILOT_ENTERPRISE | SALESFORCE_CRM |
                        WHATSAPP_BOT | UIPATH_RPA).  Defaults to ZAPIER_SME.
FAIREWALL_API_KEY       Optional API key for management endpoints.
FAIREWALL_AUDIT_PATH    File path for persistent audit log (default: audit.jsonl).
FAIREWALL_SHADOW        "true" → log-only mode; never actually block.
FAIREWALL_HOST          Bind host (default 0.0.0.0).
FAIREWALL_PORT          Bind port (default 8000).

Zapier
~~~~~~
ZAPIER_WEBHOOK_SECRET   HMAC-SHA256 secret shared with Zapier.
ZAPIER_PRESET           Override preset (defaults to FAIREWALL_PRESET).

Microsoft Copilot Studio
~~~~~~~~~~~~~~~~~~~~~~~~
COPILOT_TENANT_ID       Azure AD tenant ID for JWT validation.
COPILOT_PRESET          Override preset (defaults to FAIREWALL_PRESET).

Salesforce Agentforce
~~~~~~~~~~~~~~~~~~~~~
SALESFORCE_CONSUMER_KEY JWT audience / consumer key for the Connected App.
SALESFORCE_PRESET       Override preset (defaults to FAIREWALL_PRESET).

Haptik / WhatsApp
~~~~~~~~~~~~~~~~~
META_APP_SECRET         HMAC secret from Meta App Dashboard.
META_VERIFY_TOKEN       Webhook challenge verification token.
HAPTIK_CLIENT_ID        Haptik platform client ID.
HAPTIK_API_TOKEN        Haptik platform API token.
HAPTIK_PRESET           Override preset (defaults to FAIREWALL_PRESET).

UiPath
~~~~~~
UIPATH_WEBHOOK_SECRET   HMAC-SHA256 secret from Automation Cloud webhook settings.
UIPATH_PRESET           Override preset (defaults to FAIREWALL_PRESET).
"""

from __future__ import annotations

import logging
import os
import sys
from typing import List, Tuple

logger = logging.getLogger("fairewall.server")

# ---------------------------------------------------------------------------
# Optional: load .env file automatically if python-dotenv is installed
# ---------------------------------------------------------------------------
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except ImportError:
    pass  # fine — .env loading is optional

# ---------------------------------------------------------------------------
# FastAPI + proxy
# ---------------------------------------------------------------------------
try:
    from fastapi import FastAPI
    from fairewall.proxy.app import create_app
except ImportError as exc:
    raise ImportError(
        "fairewall server requires `pip install fairewall[sdk]`"
    ) from exc

from fairewall.audit import AuditLog
from fairewall.firewall import Firewall
from fairewall.policy import Policy
from fairewall.presets import load_preset


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()


def _bool_env(key: str) -> bool:
    return _env(key).lower() in ("1", "true", "yes")


def _preset(platform_key: str) -> Policy:
    """Return the policy for a platform, falling back to the global preset."""
    name = _env(platform_key) or _env("FAIREWALL_PRESET", "ZAPIER_SME")
    try:
        return load_preset(name)
    except ValueError:
        logger.warning(
            "Unknown preset %r for %s; falling back to ZAPIER_SME.", name, platform_key
        )
        return load_preset("ZAPIER_SME")


def _mount_zapier(app: FastAPI) -> bool:
    secret = _env("ZAPIER_WEBHOOK_SECRET")
    if not secret:
        logger.info("Zapier adapter skipped (ZAPIER_WEBHOOK_SECRET not set).")
        return False
    try:
        from fairewall.integrations.zapier import ZapierWebhookAdapter
        from fairewall.sdk import GovernanceSDK
        sdk = GovernanceSDK(policy=_preset("ZAPIER_PRESET"), platform="zapier")
        adapter = ZapierWebhookAdapter(sdk, webhook_secret=secret, verify_signature=True)
        app.include_router(adapter.router)
        logger.info("✓  Zapier adapter mounted  →  /v1/zapier/*")
        return True
    except Exception as exc:
        logger.warning("Zapier adapter failed to mount: %s", exc)
        return False


def _mount_copilot(app: FastAPI) -> bool:
    tenant_id = _env("COPILOT_TENANT_ID")
    # Copilot can run without JWT validation (dev mode) but warn if no tenant
    if not tenant_id:
        logger.info(
            "Copilot adapter mounting in DEV mode (COPILOT_TENANT_ID not set — JWT not validated)."
        )
    try:
        from fairewall.integrations.copilot import CopilotAdapter
        from fairewall.sdk import GovernanceSDK
        sdk = GovernanceSDK(policy=_preset("COPILOT_PRESET"), platform="copilot")
        adapter = CopilotAdapter(
            sdk,
            tenant_id=tenant_id or None,
            validate_jwt=bool(tenant_id),
        )
        app.include_router(adapter.router)
        logger.info("✓  Copilot Studio adapter mounted  →  /v1/copilot/*")
        return True
    except Exception as exc:
        logger.warning("Copilot adapter failed to mount: %s", exc)
        return False


def _mount_salesforce(app: FastAPI) -> bool:
    consumer_key = _env("SALESFORCE_CONSUMER_KEY")
    if not consumer_key:
        logger.info("Salesforce adapter skipped (SALESFORCE_CONSUMER_KEY not set).")
        return False
    try:
        from fairewall.integrations.salesforce import AgentforceAdapter
        from fairewall.sdk import GovernanceSDK
        sdk = GovernanceSDK(policy=_preset("SALESFORCE_PRESET"), platform="salesforce")
        adapter = AgentforceAdapter(
            sdk,
            consumer_key=consumer_key,
            validate_jwt=True,
        )
        app.include_router(adapter.router)
        logger.info("✓  Salesforce Agentforce adapter mounted  →  /v1/salesforce/*")
        return True
    except Exception as exc:
        logger.warning("Salesforce adapter failed to mount: %s", exc)
        return False


def _mount_haptik(app: FastAPI) -> bool:
    meta_secret = _env("META_APP_SECRET")
    haptik_client = _env("HAPTIK_CLIENT_ID")
    haptik_token = _env("HAPTIK_API_TOKEN")
    verify_token = _env("META_VERIFY_TOKEN", "fairewall-verify")

    if not meta_secret and not haptik_client:
        logger.info(
            "Haptik/WhatsApp adapter skipped "
            "(META_APP_SECRET and HAPTIK_CLIENT_ID not set)."
        )
        return False
    try:
        from fairewall.integrations.haptik import HaptikAdapter
        from fairewall.sdk import GovernanceSDK
        sdk = GovernanceSDK(policy=_preset("HAPTIK_PRESET"), platform="whatsapp/haptik")
        adapter = HaptikAdapter(
            sdk,
            meta_app_secret=meta_secret or None,
            meta_verify_token=verify_token,
            haptik_client_id=haptik_client or None,
            haptik_api_token=haptik_token or None,
            verify_signature=bool(meta_secret),
        )
        app.include_router(adapter.router)
        logger.info("✓  Haptik/WhatsApp adapter mounted  →  /v1/whatsapp/*  /v1/haptik/*")
        return True
    except Exception as exc:
        logger.warning("Haptik/WhatsApp adapter failed to mount: %s", exc)
        return False


def _mount_uipath(app: FastAPI) -> bool:
    secret = _env("UIPATH_WEBHOOK_SECRET")
    if not secret:
        logger.info("UiPath adapter skipped (UIPATH_WEBHOOK_SECRET not set).")
        return False
    try:
        from fairewall.integrations.uipath import UiPathAdapter
        from fairewall.sdk import GovernanceSDK
        sdk = GovernanceSDK(policy=_preset("UIPATH_PRESET"), platform="uipath")
        adapter = UiPathAdapter(sdk, webhook_secret=secret, verify_signature=True)
        app.include_router(adapter.router)
        logger.info("✓  UiPath adapter mounted  →  /v1/uipath/*")
        return True
    except Exception as exc:
        logger.warning("UiPath adapter failed to mount: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_app() -> FastAPI:
    """Construct and return the fully configured gateway application.

    Called by ``uvicorn`` (via ``fairewall.server:build_app``) or directly
    in tests.  Reads all configuration from environment variables.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )

    audit_path = _env("FAIREWALL_AUDIT_PATH", "audit.jsonl")
    shadow = _bool_env("FAIREWALL_SHADOW")
    api_key = _env("FAIREWALL_API_KEY") or None

    # Build the base gateway (shared firewall + core endpoints)
    app = create_app(
        audit_path=audit_path,
        shadow=shadow,
        api_key=api_key,
    )

    # Mount platform adapters for every configured platform
    mounted: List[str] = []
    _MOUNTERS = [
        ("zapier",      _mount_zapier),
        ("copilot",     _mount_copilot),
        ("salesforce",  _mount_salesforce),
        ("haptik",      _mount_haptik),
        ("uipath",      _mount_uipath),
    ]
    for name, fn in _MOUNTERS:
        if fn(app):
            mounted.append(name)

    if not mounted:
        logger.warning(
            "No platform adapters mounted.  Set at least one platform secret in .env  "
            "(e.g. ZAPIER_WEBHOOK_SECRET).  The base gateway is still running."
        )
    else:
        logger.info("Gateway ready.  Adapters: %s", ", ".join(mounted))

    return app


# Single shared application instance — imported by uvicorn as
#   uvicorn fairewall.server:app
app = build_app()


if __name__ == "__main__":
    try:
        import uvicorn  # type: ignore
    except ImportError:
        print("Install uvicorn:  pip install uvicorn", file=sys.stderr)
        sys.exit(1)

    host = _env("FAIREWALL_HOST", "0.0.0.0")
    port = int(_env("FAIREWALL_PORT", "8000"))
    uvicorn.run("fairewall.server:app", host=host, port=port, reload=False)
