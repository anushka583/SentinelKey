from datetime import datetime, timedelta, timezone
import secrets
from types import SimpleNamespace

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.core.config import settings
from app.models.asset import Asset
from app.models.audit_event import AuditEvent
from app.models.security_event import SecurityEvent
from app.security import authentication
from app.security.authentication import issue_development_token
from tests.conftest import TEST_JWT_SECRET


def _token(identity_id: str, **claim_overrides: object) -> str:
    now = datetime.now(timezone.utc)
    claims: dict[str, object] = {
        "sub": identity_id,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }
    claims.update(claim_overrides)
    return jwt.encode(claims, TEST_JWT_SECRET, algorithm="HS256")


def test_missing_token_is_rejected(client: TestClient):
    response = client.get("/api/v1/identities")

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_invalid_token_is_rejected(client: TestClient):
    response = client.get(
        "/api/v1/identities",
        headers={"Authorization": "Bearer not-a-jwt"},
    )

    assert response.status_code == 401


def test_expired_token_is_rejected(client, create_identity):
    identity = create_identity()
    token = issue_development_token(identity.id, expires_in=timedelta(seconds=-1))

    response = client.get(
        "/api/v1/identities",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_unknown_and_inactive_identities_are_rejected(
    client, create_identity, auth_headers
):
    unknown_response = client.get(
        "/api/v1/identities",
        headers={"Authorization": f"Bearer {_token('unknown-identity')}"},
    )
    suspended = create_identity(status="suspended")
    suspended_response = client.get(
        "/api/v1/identities",
        headers=auth_headers(suspended),
    )

    assert unknown_response.status_code == 401
    assert suspended_response.status_code == 401


def test_missing_development_secret_fails_closed(
    client, create_identity, auth_headers, monkeypatch
):
    identity = create_identity()
    headers = auth_headers(identity)
    monkeypatch.setattr(settings, "jwt_secret", None)

    response = client.get("/api/v1/identities", headers=headers)

    assert response.status_code == 503


def test_development_tokens_are_disabled_outside_development(
    client, create_identity, auth_headers, monkeypatch
):
    identity = create_identity()
    headers = auth_headers(identity)
    monkeypatch.setattr(settings, "environment", "production")

    response = client.get("/api/v1/identities", headers=headers)

    assert response.status_code == 503


def test_invalid_database_role_is_denied(client, create_identity, auth_headers):
    identity = create_identity(role="unknown-role")

    response = client.get("/api/v1/identities", headers=auth_headers(identity))

    assert response.status_code == 403


def test_invalid_signature_issuer_and_audience_are_rejected(
    client, create_identity
):
    identity = create_identity()
    wrong_signature = jwt.encode(
        {
            "sub": identity.id,
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        },
        secrets.token_urlsafe(48),
        algorithm="HS256",
    )
    wrong_issuer = _token(identity.id, iss="https://untrusted.example")
    wrong_audience = _token(identity.id, aud="another-api")

    for token in (wrong_signature, wrong_issuer, wrong_audience):
        response = client.get(
            "/api/v1/identities",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 401


def test_valid_authenticated_request(client, create_identity, auth_headers):
    identity = create_identity(role="analyst")

    response = client.get("/api/v1/identities", headers=auth_headers(identity))

    assert response.status_code == 200
    assert [record["id"] for record in response.json()] == [identity.id]
    assert response.json()[0]["role"] == "analyst"


def test_insufficient_role_cannot_create_tenant(client, create_identity, auth_headers):
    analyst = create_identity(role="analyst")

    response = client.post(
        "/api/v1/tenants",
        json={"name": "Unapproved", "slug": "unapproved"},
        headers=auth_headers(analyst),
    )

    assert response.status_code == 403


def test_tenant_owned_reads_never_return_another_tenants_records(
    client, db_session, create_tenant, create_identity, auth_headers
):
    tenant_a = create_tenant(slug="tenant-a")
    tenant_b = create_tenant(slug="tenant-b")
    identity_a = create_identity(tenant=tenant_a, email="a@example.com")
    identity_b = create_identity(tenant=tenant_b, email="b@example.com")

    for tenant, identity, suffix in (
        (tenant_a, identity_a, "a"),
        (tenant_b, identity_b, "b"),
    ):
        asset = Asset(
            tenant_id=tenant.id,
            hostname=f"host-{suffix}.example.test",
            asset_type="server",
            criticality="high",
        )
        event = SecurityEvent(
            tenant_id=tenant.id,
            event_type="test_event",
            severity="low",
            source="automated-test",
            description="Clearly labeled test event",
            payload={"test_data": True},
        )
        audit_event = AuditEvent(
            tenant_id=tenant.id,
            actor_identity_id=identity.id,
            action="test.read",
            resource_type="test",
            resource_id=identity.id,
            outcome="success",
            details={"test_data": True},
        )
        db_session.add_all([asset, event, audit_event])
    db_session.commit()

    headers = auth_headers(identity_a)
    responses = {
        "tenants": client.get("/api/v1/tenants", headers=headers),
        "identities": client.get("/api/v1/identities", headers=headers),
        "assets": client.get("/api/v1/assets", headers=headers),
        "security-events": client.get("/api/v1/security-events", headers=headers),
        "audit-events": client.get("/api/v1/audit-events", headers=headers),
    }

    for response in responses.values():
        assert response.status_code == 200
    assert [row["id"] for row in responses["tenants"].json()] == [tenant_a.id]
    assert [row["id"] for row in responses["identities"].json()] == [identity_a.id]
    assert [row["hostname"] for row in responses["assets"].json()] == ["host-a.example.test"]
    assert [row["tenant_id"] for row in responses["security-events"].json()] == [tenant_a.id]
    assert [row["tenant_id"] for row in responses["audit-events"].json()] == [tenant_a.id]


def test_oidc_rs256_token_maps_to_identity_and_checks_signature(
    client, db_session, create_tenant, create_identity, monkeypatch
):
    tenant = create_tenant()
    issuer = "https://issuer.example.test/"
    identity = create_identity(
        tenant=tenant,
        email="oidc@example.com",
    )
    identity.external_issuer = issuer
    identity.external_subject = "oidc-subject-123"
    db_session.commit()

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    class LocalSigningKeyClient:
        def get_signing_key_from_jwt(self, token: str):
            return SimpleNamespace(key=public_key)

    monkeypatch.setattr(settings, "auth_mode", "oidc")
    monkeypatch.setattr(settings, "jwt_issuer", issuer)
    monkeypatch.setattr(settings, "oidc_jwks_url", "https://issuer.example.test/jwks")
    monkeypatch.setattr(
        authentication,
        "_jwks_client",
        lambda url: LocalSigningKeyClient(),
    )
    now = datetime.now(timezone.utc)
    claims = {
        "sub": "oidc-subject-123",
        "iss": issuer,
        "aud": settings.jwt_audience,
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }
    token = jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "test-key"})
    forged_token = jwt.encode(
        claims,
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        algorithm="RS256",
        headers={"kid": "test-key"},
    )

    response = client.get(
        "/api/v1/tenants",
        headers={"Authorization": f"Bearer {token}"},
    )
    forged_response = client.get(
        "/api/v1/tenants",
        headers={"Authorization": f"Bearer {forged_token}"},
    )

    assert response.status_code == 200
    assert [row["id"] for row in response.json()] == [tenant.id]
    assert forged_response.status_code == 401
