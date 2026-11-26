from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError
import pytest

from app.models.asset import Asset
from app.models.alert import Alert
from app.models.audit_event import AuditEvent
from app.models.identity import Identity
from app.models.security_event import SecurityEvent
from app.models.tenant import Tenant


def test_database_connection(db_session):
    result = db_session.execute(text("SELECT 1")).scalar()
    assert result == 1


def test_table_creation(db_engine):
    inspector = inspect(db_engine)
    table_names = set(inspector.get_table_names())
    assert {
        "tenants",
        "identities",
        "assets",
        "security_events",
        "audit_events",
        "alerts",
    }.issubset(table_names)


def test_tenant_creation(db_session):
    tenant = Tenant(name="Acme Corp", slug="acme-corp")
    db_session.add(tenant)
    db_session.commit()
    db_session.refresh(tenant)

    assert tenant.id is not None
    assert tenant.name == "Acme Corp"
    assert tenant.slug == "acme-corp"


def test_duplicate_tenant_slug_rejection(db_session):
    db_session.add(Tenant(name="Acme Corp", slug="acme-corp"))
    db_session.commit()

    db_session.add(Tenant(name="Acme Corp 2", slug="acme-corp"))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_identity_tenant_relationship(db_session):
    tenant = Tenant(name="Acme Corp", slug="acme-corp")
    db_session.add(tenant)
    db_session.commit()
    db_session.refresh(tenant)

    identity = Identity(
        tenant_id=tenant.id,
        email="analyst@acme.com",
        identity_type="human",
        status="active",
    )
    db_session.add(identity)
    db_session.commit()
    db_session.refresh(identity)

    assert identity.tenant_id == tenant.id
    assert identity.tenant.slug == "acme-corp"


def test_asset_tenant_relationship(db_session):
    tenant = Tenant(name="Acme Corp", slug="acme-corp")
    db_session.add(tenant)
    db_session.commit()
    db_session.refresh(tenant)

    asset = Asset(
        tenant_id=tenant.id,
        hostname="srv-01.acme.local",
        asset_type="server",
        criticality="high",
    )
    db_session.add(asset)
    db_session.commit()
    db_session.refresh(asset)

    assert asset.tenant_id == tenant.id
    assert asset.tenant.name == "Acme Corp"


def test_security_event_persistence(db_session):
    tenant = Tenant(name="Acme Corp", slug="acme-corp")
    db_session.add(tenant)
    db_session.commit()
    db_session.refresh(tenant)

    event = SecurityEvent(
        tenant_id=tenant.id,
        event_type="failed_login",
        severity="high",
        source="identity-provider",
        description="Multiple failed login attempts detected.",
        payload={"attempts": 5, "ip": "203.0.113.10"},
    )
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)

    assert event.id is not None
    assert event.tenant_id == tenant.id
    assert event.payload["attempts"] == 5


def test_audit_event_persistence(db_session):
    tenant = Tenant(name="Acme Corp", slug="acme-corp")
    db_session.add(tenant)
    db_session.commit()
    db_session.refresh(tenant)

    actor = Identity(
        tenant_id=tenant.id,
        email="admin@acme.com",
        identity_type="human",
        status="active",
    )
    db_session.add(actor)
    db_session.commit()
    db_session.refresh(actor)

    audit_event = AuditEvent(
        tenant_id=tenant.id,
        actor_identity_id=actor.id,
        action="tenant.created",
        resource_type="tenant",
        resource_id=tenant.id,
        outcome="success",
        details={"source": "test"},
    )
    db_session.add(audit_event)
    db_session.commit()
    db_session.refresh(audit_event)

    assert audit_event.id is not None
    assert audit_event.actor_identity_id == actor.id
    assert audit_event.details["source"] == "test"


def test_database_health_endpoint(client):
    response = client.get("/api/v1/system/database/health")

    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "database": "connected"}


def test_existing_root_and_liveness_endpoints(client):
    root_response = client.get("/")
    assert root_response.status_code == 200
    assert root_response.json()["product"] == "SentinelKey"
    assert root_response.json()["version"] == "0.1.0"

    health_response = client.get("/health/live")
    assert health_response.status_code == 200
    assert health_response.json()["status"] == "healthy"
    assert health_response.json()["service"] == "sentinelkey-api"

def test_tenant_create_endpoint(client, create_identity, auth_headers):
    admin = create_identity(role="platform_admin")
    response = client.post(
        "/api/v1/tenants",
        json={"name": "Acme Corp", "slug": "acme-corp"},
        headers=auth_headers(admin),
    )

    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "Acme Corp"
    assert body["slug"] == "acme-corp"
    assert "id" in body


def test_duplicate_tenant_slug_rejected_by_api(client, create_identity, auth_headers):
    admin = create_identity(role="platform_admin")
    payload = {"name": "Acme Corp", "slug": "acme-corp"}
    headers = auth_headers(admin)
    first = client.post("/api/v1/tenants", json=payload, headers=headers)
    second = client.post(
        "/api/v1/tenants",
        json={"name": "Acme Two", "slug": "acme-corp"},
        headers=headers,
    )

    assert first.status_code == 201
    assert second.status_code == 409


def test_list_endpoints_are_authenticated_and_tenant_scoped(
    client, create_identity, auth_headers
):
    identity = create_identity()
    headers = auth_headers(identity)

    tenants = client.get("/api/v1/tenants", headers=headers).json()
    identities = client.get("/api/v1/identities", headers=headers).json()
    assert [tenant["id"] for tenant in tenants] == [identity.tenant_id]
    assert [item["id"] for item in identities] == [identity.id]
    assert client.get("/api/v1/assets", headers=headers).json() == []
    assert client.get("/api/v1/security-events", headers=headers).json() == []
    assert client.get("/api/v1/audit-events", headers=headers).json() == []