import asyncio
import json

import pytest

from fairewall import cloud_auth
from fairewall.db import _behind_pooler
from fairewall.vercel import VercelConfigError, build_app


def test_federation_writes_keyless_external_account_config(tmp_path):
    env = {"GCP_WIF_AUDIENCE": "//iam.googleapis.com/projects/42/locations/global/workloadIdentityPools/p/providers/v",
           "GCP_ARMOR_SERVICE_ACCOUNT": "armor@proj.iam.gserviceaccount.com",
           "FAIREWALL_OIDC_TOKEN_FILE": str(tmp_path / "token"),
           "FAIREWALL_GCP_CREDENTIALS_FILE": str(tmp_path / "creds.json")}
    assert cloud_auth.configure_google_credentials(env) == "workload-identity"
    cfg = json.loads((tmp_path / "creds.json").read_text())
    assert env["GOOGLE_APPLICATION_CREDENTIALS"] == str(tmp_path / "creds.json")
    assert cfg["type"] == "external_account" and cfg["audience"] == env["GCP_WIF_AUDIENCE"]
    assert cfg["credential_source"]["file"] == str(tmp_path / "token")
    assert "armor@proj.iam.gserviceaccount.com:generateAccessToken" in cfg["service_account_impersonation_url"]
    assert "private_key" not in json.dumps(cfg)


def test_federation_from_vercel_documented_names_and_absent_config():
    env = {"GCP_PROJECT_NUMBER": "7", "GCP_WORKLOAD_IDENTITY_POOL_ID": "pool",
           "GCP_WORKLOAD_IDENTITY_POOL_PROVIDER_ID": "prov", "GCP_SERVICE_ACCOUNT_EMAIL": "sa@x"}
    s = cloud_auth.federation_settings(env)
    assert s["audience"].endswith("/projects/7/locations/global/workloadIdentityPools/pool/providers/prov")
    assert cloud_auth.configure_google_credentials({}) is None
    assert cloud_auth.configure_google_credentials({"GOOGLE_APPLICATION_CREDENTIALS": "x"}) == "application-default"


def test_request_token_is_captured_for_google_credentials(tmp_path):
    path = str(tmp_path / "token")
    seen = []

    async def inner(scope, receive, send):
        seen.append(scope["path"])

    mw = cloud_auth.OidcTokenCapture(inner, path=path)
    asyncio.run(mw({"type": "http", "path": "/x", "headers": [(b"x-vercel-oidc-token", b"jwt-1")]}, None, None))
    assert seen == ["/x"] and (tmp_path / "token").read_text() == "jwt-1"
    asyncio.run(mw({"type": "http", "path": "/y", "headers": [(b"x-vercel-oidc-token", b"jwt-2")]}, None, None))
    assert (tmp_path / "token").read_text() == "jwt-2"


def test_vercel_refuses_to_run_without_postgres():
    with pytest.raises(VercelConfigError, match="needs Postgres"):
        build_app({"VERCEL": "1"})
    with pytest.raises(VercelConfigError):
        build_app({"FAIREWALL_DATABASE_URL": "lab-data"})


def test_pooled_hosts_disable_prepared_statements(monkeypatch):
    monkeypatch.delenv("FAIREWALL_DB_POOLER", raising=False)
    assert _behind_pooler("postgresql://u:p@ep-cool-1234-pooler.us-east-2.aws.neon.tech/db?sslmode=require")
    assert not _behind_pooler("postgresql://u:p@ep-cool-1234.us-east-2.aws.neon.tech/db")
    monkeypatch.setenv("FAIREWALL_DB_POOLER", "1")
    assert _behind_pooler("postgresql://u:p@localhost/db")


def test_cron_anchor_needs_the_secret(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from fairewall.lab import Lab
    from fairewall.lab.app import create_lab_app

    monkeypatch.delenv("FAIREWALL_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("POSTGRES_URL", raising=False)
    monkeypatch.delenv("FAIREWALL_ANCHOR_BUCKET", raising=False)
    monkeypatch.delenv("FAIREWALL_ANCHOR_KEY", raising=False)
    monkeypatch.setenv("LAB_DATA_DIR", str(tmp_path))
    client = TestClient(create_lab_app(Lab(str(tmp_path))))
    monkeypatch.delenv("CRON_SECRET", raising=False)
    assert client.get("/api/cron/anchor").status_code == 404
    monkeypatch.setenv("CRON_SECRET", "s3cret")
    assert client.get("/api/cron/anchor", headers={"Authorization": "Bearer nope"}).status_code == 401
    ok = client.get("/api/cron/anchor", headers={"Authorization": "Bearer s3cret"})
    assert ok.status_code == 200 and ok.json()["ok"] is True
