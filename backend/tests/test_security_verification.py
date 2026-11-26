import logging
from types import SimpleNamespace

import pytest
from fastapi.routing import APIRoute

from app.api.v1 import (
    alerts,
    audit_events,
    assets,
    identities,
    security_events,
    tenants,
)
from app.models.asset import Asset
from app.models.audit_event import AuditEvent
from app.models.security_event import SecurityEvent
from app.security import policy
from app.security.policy import PolicyDecision, PolicyInput, evaluate_policy


@pytest.fixture
def tenant_pair(db_session, create_tenant, create_identity):
    tenant_a = create_tenant(slug="audit-tenant-a")
    tenant_b = create_tenant(slug="audit-tenant-b")
    identity_a = create_identity(
        tenant=tenant_a,
        role="viewer",
        email="tenant-a@example.com",
    )
    identity_b = create_identity(
        tenant=tenant_b,
        role="viewer",
        email="tenant-b@example.com",
    )
    resources = {}

    for tenant, identity, suffix in (
        (tenant_a, identity_a, "a"),
        (tenant_b, identity_b, "b"),
    ):
        asset = Asset(
            tenant_id=tenant.id,
            hostname=f"audit-host-{suffix}.example.com",
            asset_type="server",
            criticality="high",
        )
        event = SecurityEvent(
            tenant_id=tenant.id,
            event_type="security-audit-test",
            severity="low",
            source="automated-security-audit",
            description="Clearly labeled security verification test data",
            payload={"test_data": True},
        )
        audit_event = AuditEvent(
            tenant_id=tenant.id,
            actor_identity_id=identity.id,
            action="security.audit.test",
            resource_type="test",
            resource_id=identity.id,
            outcome="success",
            details={"test_data": True},
        )
        db_session.add_all([asset, event, audit_event])
        resources[suffix] = SimpleNamespace(
            asset=asset,
            event=event,
            audit_event=audit_event,
        )

    db_session.commit()
    return SimpleNamespace(
        tenant_a=tenant_a,
        tenant_b=tenant_b,
        identity_a=identity_a,
        identity_b=identity_b,
        resources=resources,
    )


def test_tenant_a_cannot_read_tenant_b_identities(
    client, tenant_pair, auth_headers
):
    response = client.get(
        "/api/v1/identities",
        params={"tenant_id": tenant_pair.tenant_b.id},
        headers=auth_headers(tenant_pair.identity_a),
    )

    assert response.status_code == 200
    identity_ids = {row["id"] for row in response.json()}
    assert tenant_pair.identity_a.id in identity_ids
    assert tenant_pair.identity_b.id not in identity_ids


def test_tenant_a_cannot_read_tenant_b_assets(client, tenant_pair, auth_headers):
    response = client.get(
        "/api/v1/assets",
        params={"tenant_id": tenant_pair.tenant_b.id},
        headers=auth_headers(tenant_pair.identity_a),
    )

    assert response.status_code == 200
    assert [row["id"] for row in response.json()] == [
        tenant_pair.resources["a"].asset.id
    ]


def test_tenant_a_cannot_read_tenant_b_security_events(
    client, tenant_pair, auth_headers
):
    response = client.get(
        "/api/v1/security-events",
        params={"tenant_id": tenant_pair.tenant_b.id},
        headers=auth_headers(tenant_pair.identity_a),
    )

    assert response.status_code == 200
    assert [row["id"] for row in response.json()] == [
        tenant_pair.resources["a"].event.id
    ]


def test_tenant_a_cannot_read_tenant_b_audit_events(
    client, tenant_pair, auth_headers
):
    response = client.get(
        "/api/v1/audit-events",
        params={"tenant_id": tenant_pair.tenant_b.id},
        headers=auth_headers(tenant_pair.identity_a),
    )

    assert response.status_code == 200
    assert [row["id"] for row in response.json()] == [
        tenant_pair.resources["a"].audit_event.id
    ]


def test_analyst_cannot_create_identities(client, create_identity, auth_headers):
    analyst = create_identity(role="analyst")

    response = client.post(
        "/api/v1/identities",
        json={"email": "unauthorized-identity@example.com"},
        headers=auth_headers(analyst),
    )

    assert response.status_code == 403


def test_viewer_cannot_ingest_security_events(client, create_identity, auth_headers):
    viewer = create_identity(role="viewer")

    response = client.post(
        "/api/v1/security-events",
        json={
            "event_type": "viewer-ingest-attempt",
            "severity": "low",
            "source": "security-verification",
            "description": "Labeled test data",
        },
        headers=auth_headers(viewer),
    )

    assert response.status_code == 403


def test_admin_cannot_create_tenants(client, create_identity, auth_headers):
    admin = create_identity(role="admin")

    response = client.post(
        "/api/v1/tenants",
        json={"name": "Unauthorized Tenant", "slug": "unauthorized-tenant"},
        headers=auth_headers(admin),
    )

    assert response.status_code == 403


def test_unauthenticated_requests_cannot_access_protected_routes(client):
    requests = (
        ("GET", "/api/v1/tenants", None),
        ("POST", "/api/v1/tenants", {"name": "No Auth", "slug": "no-auth"}),
        ("GET", "/api/v1/identities", None),
        ("POST", "/api/v1/identities", {"email": "no-auth@example.com"}),
        ("GET", "/api/v1/assets", None),
        ("GET", "/api/v1/security-events", None),
        (
            "POST",
            "/api/v1/security-events",
            {
                "event_type": "no-auth",
                "severity": "low",
                "source": "test",
                "description": "Labeled test data",
            },
        ),
        ("GET", "/api/v1/audit-events", None),
    )

    for method, path, body in requests:
        response = client.request(method, path, json=body)
        assert response.status_code == 401, f"{method} {path} returned {response.status_code}"


def test_platform_admin_can_create_tenant_and_policy_allows_explicit_cross_tenant_action(
    client, create_identity, auth_headers
):
    platform_admin = create_identity(role="platform_admin")
    response = client.post(
        "/api/v1/tenants",
        json={"name": "Platform Created", "slug": "platform-created"},
        headers=auth_headers(platform_admin),
    )
    cross_tenant_decision = evaluate_policy(
        PolicyInput(
            identity_id=platform_admin.id,
            role=platform_admin.role,
            tenant_id=platform_admin.tenant_id,
            action="read",
            resource_type="asset",
            resource_tenant_id="another-tenant",
        )
    )

    assert response.status_code == 201
    assert cross_tenant_decision.allow


def _dependency_calls(route: APIRoute):
    def visit(dependant):
        for dependency in dependant.dependencies:
            yield dependency.call
            yield from visit(dependency)

    return set(visit(route.dependant))


def test_every_sensitive_route_uses_central_policy_dependency():
    expected_routes = {
        ("GET", "/api/v1/tenants"),
        ("POST", "/api/v1/tenants"),
        ("GET", "/api/v1/identities"),
        ("POST", "/api/v1/identities"),
        ("GET", "/api/v1/assets"),
        ("GET", "/api/v1/security-events"),
        ("POST", "/api/v1/security-events"),
        ("GET", "/api/v1/security-events/summary"),
        ("GET", "/api/v1/alerts"),
        ("GET", "/api/v1/alerts/{alert_id}"),
        ("PATCH", "/api/v1/alerts/{alert_id}"),
        ("GET", "/api/v1/audit-events"),
    }
    routes = {}
    for api_module in (
        tenants,
        identities,
        assets,
        security_events,
        alerts,
        audit_events,
    ):
        for route in api_module.router.routes:
            if isinstance(route, APIRoute):
                for method in route.methods or ():
                    routes[(method, route.path)] = route

    assert expected_routes <= routes.keys()
    for endpoint in expected_routes:
        calls = _dependency_calls(routes[endpoint])
        assert any(
            getattr(call, "__name__", "") == "permission_dependency"
            and getattr(call, "__module__", "") == "app.security.policy"
            for call in calls
        ), f"{endpoint} is missing the centralized policy dependency"


@pytest.mark.parametrize(
    "malformed_decision",
    [
        None,
        PolicyDecision(allow=True, reason="allowed", policy_id=None),
        PolicyDecision(allow=True, reason="not-a-valid-allow", policy_id="asset-read-v1"),
        PolicyDecision(allow=True, reason="allowed", policy_id="wrong-policy"),
    ],
)
def test_missing_or_malformed_policy_allow_fails_closed(
    client, create_identity, auth_headers, monkeypatch, malformed_decision
):
    viewer = create_identity(role="viewer")
    monkeypatch.setattr(
        policy,
        "evaluate_policy",
        lambda _input: malformed_decision,
    )

    response = client.get("/api/v1/assets", headers=auth_headers(viewer))

    assert response.status_code == 403


def test_identity_and_event_requests_cannot_override_tenant_ownership(
    client, create_identity, create_tenant, auth_headers
):
    tenant_a = create_tenant(slug="owner-a")
    tenant_b = create_tenant(slug="owner-b")
    admin = create_identity(
        tenant=tenant_a,
        role="admin",
        email="owner-admin@example.com",
    )
    headers = auth_headers(admin)

    identity_response = client.post(
        "/api/v1/identities",
        json={"email": "forged-owner@example.com", "tenant_id": tenant_b.id},
        headers=headers,
    )
    event_response = client.post(
        "/api/v1/security-events",
        json={
            "event_type": "forged-owner",
            "severity": "low",
            "source": "security-verification",
            "description": "Labeled test data",
            "tenant_id": tenant_b.id,
        },
        headers=headers,
    )

    assert identity_response.status_code == 422
    assert event_response.status_code == 422


def test_authorization_denial_logs_no_token_or_personal_data(
    client, create_identity, auth_headers, caplog
):
    viewer = create_identity(
        role="viewer",
        email="private-personal-data@example.com",
    )
    headers = auth_headers(viewer)
    token = headers["Authorization"].removeprefix("Bearer ")
    caplog.set_level(logging.WARNING, logger="app.security.policy")

    response = client.post(
        "/api/v1/identities",
        json={"email": "blocked@example.com"},
        headers=headers,
    )

    assert response.status_code == 403
    assert "Authorization denied" in caplog.text
    assert token not in caplog.text
    assert viewer.email not in caplog.text
    assert "blocked@example.com" not in caplog.text
