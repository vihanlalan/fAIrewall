"""Regression tests for the adapter-authentication fixes (D5)."""

import time

import pytest

fastapi = pytest.importorskip("fastapi")
jose_jwt = pytest.importorskip("jose.jwt")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from jose import jwk  # noqa: E402

from fairewall.integrations.copilot import CopilotAdapter  # noqa: E402
from fairewall.sdk import GovernanceSDK  # noqa: E402

TENANT = "tenant-1"
AUDIENCE = "app-1"
ISSUER = "https://login.microsoftonline.com/%s/v2.0" % TENANT
ACTIVITY = {
    "type": "message",
    "text": "What is the status of my project?",
    "from": {"id": "user-001"},
    "conversation": {"id": "conv-001"},
}


def _keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    public_jwk = jwk.construct(public_pem, "RS256").to_dict()
    public_jwk["kid"] = "k1"
    return private_pem, {"keys": [public_jwk]}


@pytest.fixture(scope="module")
def keys():
    return _keypair()


def _client(jwks):
    adapter = CopilotAdapter(
        GovernanceSDK.from_preset("COPILOT_ENTERPRISE"),
        validate_jwt=True, tenant_id=TENANT, audience=AUDIENCE,
        jwks_provider=lambda: jwks,
    )
    app = FastAPI()
    app.include_router(adapter.router)
    return TestClient(app, raise_server_exceptions=False)


def _token(private_pem, **overrides):
    claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": "user-001",
              "exp": int(time.time()) + 300}
    claims.update(overrides)
    return jose_jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": "k1"})


def _post(client, token=None):
    headers = {"Authorization": "Bearer " + token} if token else {}
    return client.post("/v1/copilot/activity", json=ACTIVITY, headers=headers)


def test_valid_signed_token_is_accepted(keys):
    private_pem, jwks = keys
    assert _post(_client(jwks), _token(private_pem)).status_code == 200


def test_garbage_bearer_token_is_rejected(keys):
    _, jwks = keys
    assert _post(_client(jwks), "not.a.jwt").status_code == 401


def test_missing_token_is_rejected(keys):
    _, jwks = keys
    assert _post(_client(jwks)).status_code == 401


def test_token_signed_by_another_key_is_rejected(keys):
    _, jwks = keys
    other_private, _ = _keypair()
    assert _post(_client(jwks), _token(other_private)).status_code == 401


def test_wrong_audience_and_wrong_issuer_and_expired_are_rejected(keys):
    private_pem, jwks = keys
    client = _client(jwks)
    assert _post(client, _token(private_pem, aud="someone-else")).status_code == 401
    assert _post(client, _token(private_pem, iss="https://evil.example/")).status_code == 401
    assert _post(client, _token(private_pem, exp=int(time.time()) - 10)).status_code == 401


def test_unsigned_token_is_rejected(keys):
    _, jwks = keys
    unsigned = jose_jwt.encode({"iss": ISSUER, "aud": AUDIENCE, "sub": "x"}, "", algorithm="HS256")
    assert _post(_client(jwks), unsigned).status_code == 401


def test_jwks_fetch_failure_fails_closed(keys):
    private_pem, _ = keys

    def boom():
        raise OSError("no network")

    adapter = CopilotAdapter(GovernanceSDK.from_preset("COPILOT_ENTERPRISE"),
                             validate_jwt=True, tenant_id=TENANT, audience=AUDIENCE,
                             jwks_provider=boom)
    app = FastAPI()
    app.include_router(adapter.router)
    client = TestClient(app, raise_server_exceptions=False)
    assert _post(client, _token(private_pem)).status_code == 401


def test_validate_jwt_requires_tenant_and_audience():
    sdk = GovernanceSDK.from_preset("COPILOT_ENTERPRISE")
    with pytest.raises(ValueError):
        CopilotAdapter(sdk, validate_jwt=True)
    with pytest.raises(ValueError):
        CopilotAdapter(sdk, validate_jwt=True, tenant_id=TENANT)


# ------------------------------------------------------------ server mounting

def _fresh_server(monkeypatch, **env):
    import importlib
    for key in ("ZAPIER_WEBHOOK_SECRET", "COPILOT_TENANT_ID", "COPILOT_AUDIENCE",
                "FAIREWALL_INSECURE_DEV", "FAIREWALL_API_KEY", "META_APP_SECRET",
                "HAPTIK_CLIENT_ID", "SALESFORCE_CONSUMER_KEY", "UIPATH_WEBHOOK_SECRET"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    import fairewall.server as server
    return importlib.reload(server)


def _paths(app):
    return {getattr(r, "path", "") for r in app.routes}


def test_copilot_is_not_mounted_without_tenant_and_audience(monkeypatch):
    server = _fresh_server(monkeypatch)
    assert not any(p.startswith("/v1/copilot") for p in _paths(server.build_app()))


def test_copilot_mounts_in_explicit_insecure_dev_mode(monkeypatch):
    server = _fresh_server(monkeypatch, FAIREWALL_INSECURE_DEV="1")
    assert any(p.startswith("/v1/copilot") for p in _paths(server.build_app()))


def test_copilot_mounts_with_tenant_and_audience(monkeypatch):
    server = _fresh_server(monkeypatch, COPILOT_TENANT_ID=TENANT, COPILOT_AUDIENCE=AUDIENCE)
    assert any(p.startswith("/v1/copilot") for p in _paths(server.build_app()))


def test_placeholder_zapier_secret_does_not_mount_adapter(monkeypatch):
    server = _fresh_server(monkeypatch, ZAPIER_WEBHOOK_SECRET="your-zapier-hmac-secret-here")
    assert not any(p.startswith("/v1/zapier") for p in _paths(server.build_app()))


def test_real_zapier_secret_mounts_and_audit_needs_the_api_key(monkeypatch):
    server = _fresh_server(monkeypatch, ZAPIER_WEBHOOK_SECRET="s3cr3t-value-9f2",
                           FAIREWALL_API_KEY="k-9f2-real")
    client = TestClient(server.build_app(), raise_server_exceptions=False)
    assert client.get("/v1/zapier/audit").status_code == 401
    assert client.get("/v1/zapier/audit", headers={"X-API-Key": "k-9f2-real"}).status_code == 200


def test_zapier_audit_is_disabled_when_no_api_key_is_configured(monkeypatch):
    server = _fresh_server(monkeypatch, ZAPIER_WEBHOOK_SECRET="s3cr3t-value-9f2")
    client = TestClient(server.build_app(), raise_server_exceptions=False)
    assert client.get("/v1/zapier/audit").status_code == 403
