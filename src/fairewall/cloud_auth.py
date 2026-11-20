"""Google credentials for fAIrewall when it runs outside Google Cloud (for example on Vercel).

On Cloud Run the service account is found automatically. Elsewhere, fAIrewall uses Workload
Identity Federation: the host issues a short-lived OIDC token for each request, Google's STS
exchanges it, and fAIrewall acts as a Google service account. No key file exists anywhere.

Set (``deploy/vercel/README.md`` shows the Cloud Shell commands that print them):

    GCP_WIF_AUDIENCE           //iam.googleapis.com/projects/NUMBER/locations/global/
                               workloadIdentityPools/POOL/providers/PROVIDER
    GCP_ARMOR_SERVICE_ACCOUNT  the service account to act as (e.g. with roles/modelarmor.user)

Every Google client in fAIrewall (Model Armor, Vertex AI Gemini, the evidence bucket) uses
Application Default Credentials, so pointing ``GOOGLE_APPLICATION_CREDENTIALS`` at the
external-account configuration written here is all they need.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from typing import Any, Dict, MutableMapping, Optional

OIDC_HEADER = b"x-vercel-oidc-token"

_lock = threading.Lock()
_last_token: Dict[str, str] = {}


def token_file(env: Optional[MutableMapping[str, str]] = None) -> str:
    env = os.environ if env is None else env
    return env.get("FAIREWALL_OIDC_TOKEN_FILE") or os.path.join(tempfile.gettempdir(),
                                                                "fairewall-oidc-token")


def federation_settings(env: MutableMapping[str, str]) -> Optional[Dict[str, str]]:
    """(audience, service account) from the environment, or None when federation isn't configured.

    Also accepts the pieces separately: GCP_PROJECT_NUMBER, GCP_WORKLOAD_IDENTITY_POOL_ID,
    GCP_WORKLOAD_IDENTITY_POOL_PROVIDER_ID, GCP_SERVICE_ACCOUNT_EMAIL (Vercel's documented names).
    """
    audience = env.get("GCP_WIF_AUDIENCE", "").strip()
    if not audience and all(env.get(v) for v in ("GCP_PROJECT_NUMBER", "GCP_WORKLOAD_IDENTITY_POOL_ID",
                                                  "GCP_WORKLOAD_IDENTITY_POOL_PROVIDER_ID")):
        audience = "//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s" % (
            env["GCP_PROJECT_NUMBER"], env["GCP_WORKLOAD_IDENTITY_POOL_ID"],
            env["GCP_WORKLOAD_IDENTITY_POOL_PROVIDER_ID"])
    account = (env.get("GCP_ARMOR_SERVICE_ACCOUNT") or env.get("GCP_SERVICE_ACCOUNT_EMAIL") or "").strip()
    if not audience or not account:
        return None
    return {"audience": audience, "service_account": account}


def external_account_config(audience: str, service_account: str, token_path: str) -> Dict[str, Any]:
    """The google-auth external-account configuration for Workload Identity Federation."""
    return {
        "type": "external_account",
        "audience": audience,
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "token_url": "https://sts.googleapis.com/v1/token",
        "service_account_impersonation_url": (
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken"
            % service_account),
        # google-auth re-reads this file whenever it refreshes, so a newer token is always used.
        "credential_source": {"file": token_path, "format": {"type": "text"}},
    }


def store_oidc_token(token: str, path: Optional[str] = None) -> None:
    """Write the host's current OIDC token where the Google credentials read it (only when it changed)."""
    token = (token or "").strip()
    if not token:
        return
    path = path or token_file()
    with _lock:
        if _last_token.get(path) == token and os.path.exists(path):
            return
        tmp = "%s.%d.tmp" % (path, os.getpid())
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(token)
        os.replace(tmp, path)
        _last_token[path] = token


def configure_google_credentials(env: Optional[MutableMapping[str, str]] = None) -> Optional[str]:
    """Make Application Default Credentials work on this host. Returns how, or None.

    - ``"application-default"``: GOOGLE_APPLICATION_CREDENTIALS is already set (left alone).
    - ``"workload-identity"``: federation is configured; a keyless config file is written.
    - ``None``: neither; Google calls fall back to whatever ADC finds (or fail and say so).
    """
    env = os.environ if env is None else env
    if env.get("GOOGLE_APPLICATION_CREDENTIALS"):
        return "application-default"
    settings = federation_settings(env)
    if settings is None:
        return None
    token_path = token_file(env)
    config_path = env.get("FAIREWALL_GCP_CREDENTIALS_FILE") or os.path.join(
        tempfile.gettempdir(), "fairewall-gcp-external-account.json")
    with open(config_path, "w", encoding="utf-8") as fh:
        json.dump(external_account_config(settings["audience"], settings["service_account"], token_path), fh)
    env["GOOGLE_APPLICATION_CREDENTIALS"] = config_path
    # Local runs (`vercel env pull`) carry the token as a variable rather than a request header.
    if env.get("VERCEL_OIDC_TOKEN"):
        store_oidc_token(env["VERCEL_OIDC_TOKEN"], token_path)
    return "workload-identity"


class OidcTokenCapture:
    """ASGI middleware: keeps each request's Vercel OIDC token where the Google credentials read it."""

    def __init__(self, app: Any, path: Optional[str] = None) -> None:
        self.app = app
        self.path = path

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") == "http":
            for key, value in scope.get("headers") or ():
                if key == OIDC_HEADER:
                    store_oidc_token(value.decode("latin-1"), self.path)
                    break
        await self.app(scope, receive, send)
