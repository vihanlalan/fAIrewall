"""Running the fAIrewall Lab on Vercel (``app.py`` at the repo root calls :func:`build_app`).

- State: Postgres, because Vercel functions keep nothing on disk between requests. Use Neon's
  pooled connection string as ``FAIREWALL_DATABASE_URL`` (``DATABASE_URL`` also works).
- Gemini: ``GEMINI_API_KEY`` from Google AI Studio (or Vertex AI with federation, below).
- Model Armor: ``MODEL_ARMOR_TEMPLATE``, reached keylessly through Workload Identity
  Federation (``GCP_WIF_AUDIENCE`` + ``GCP_ARMOR_SERVICE_ACCOUNT``; see :mod:`fairewall.cloud_auth`).
- The fleet chapters use in-process gateway identities; evidence is sealed into Merkle batches
  in Postgres and verified in the Lab. ``/api/cron/anchor`` can publish to a bucket if you add one.

See ``deploy/vercel/README.md``.
"""

from __future__ import annotations

import os
from typing import Any, MutableMapping, Optional

from .cloud_auth import OidcTokenCapture, configure_google_credentials
from .db import is_postgres

DATABASE_VARS = ("FAIREWALL_DATABASE_URL", "DATABASE_URL", "POSTGRES_URL")


class VercelConfigError(RuntimeError):
    """The deployment is missing something it needs; the message says what."""


def database_url(env: MutableMapping[str, str]) -> str:
    for var in DATABASE_VARS:
        if env.get(var):
            return env[var]
    return ""


def build_app(env: Optional[MutableMapping[str, str]] = None) -> Any:
    env = os.environ if env is None else env
    url = database_url(env)
    if not is_postgres(url):
        raise VercelConfigError(
            "The fAIrewall Lab on Vercel needs Postgres: Vercel functions keep nothing on disk between "
            "requests. Set FAIREWALL_DATABASE_URL to your Neon pooled connection string.")
    env["FAIREWALL_DATABASE_URL"] = url
    # Many short-lived function instances share one database: keep each one's pool small.
    env.setdefault("FAIREWALL_DB_POOL_SIZE", "3")
    env.setdefault("LAB_ENVIRONMENT", "vercel")
    configure_google_credentials(env)

    from .lab import create_app
    app = create_app()
    # Keeps each request's Vercel OIDC token where the Google credentials read it.
    app.add_middleware(OidcTokenCapture)
    return app
