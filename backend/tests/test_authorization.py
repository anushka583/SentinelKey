import logging

from app.security import policy
from app.security.authentication import IdentityRole
from app.security.policy import (
    PolicyInput,
    evaluate_policy,
)


def _policy_input(
    *,
    role: str = "viewer",
    action: str = "read",
    resource_type: str = "asset",
    subject_tenant_id: str | None = "tenant-a",
    resource_tenant_id: str | None = "tenant-a",
) -> PolicyInput:
    return PolicyInput(
        identity_id="identity-a",
        role=role,
        tenant_id=subject_tenant_id,
        action=action,
        resource_type=resource_type,
        resource_tenant_id=resource_tenant_id,
    )


def test_admin_can_manage_identities_but_cannot_create_tenants():
    manage_identity = evaluate_policy(
        _policy_input(role="admin", action="manage", resource_type="identity")
    )
    create_tenant = evaluate_policy(
        _policy_input(
            role="admin",
            action="create",
            resource_type="tenant",
            resource_tenant_id=None,
        )
    )

    assert manage_identity.allow
    assert not create_tenant.allow


def test_analyst_can_ingest_security_events_but_not_manage_identities():
    ingest_event = evaluate_policy(
        _policy_input(
            role="analyst",
            action="ingest",
            resource_type="security_event",
        )
    )
    manage_identity = evaluate_policy(
        _policy_input(role="analyst", action="manage", resource_type="identity")
    )

    assert ingest_event.allow
    assert not manage_identity.allow


def test_viewer_is_read_only():
    read_asset = evaluate_policy(_policy_input(role="viewer"))
    ingest_event = evaluate_policy(
        _policy_input(
            role="viewer",
            action="ingest",
            resource_type="security_event",
        )
    )

    assert read_asset.allow
    assert not ingest_event.allow


def test_platform_admin_can_access_cross_tenant_and_create_tenants():
    cross_tenant_read = evaluate_policy(
        _policy_input(
            role="platform_admin",
            resource_tenant_id="tenant-b",
        )
    )
    create_tenant = evaluate_policy(
        _policy_input(
            role="platform_admin",
            action="create",
            resource_type="tenant",
            resource_tenant_id=None,
        )
    )

    assert cross_tenant_read.allow
    assert create_tenant.allow


def test_cross_tenant_access_is_denied_for_every_non_platform_role():
    for role in ("admin", "analyst", "viewer"):
        decision = evaluate_policy(
            _policy_input(role=role, resource_tenant_id="tenant-b")
        )

        assert not decision.allow
        assert decision.reason == "cross_tenant_access"


def test_unknown_role_missing_policy_and_missing_context_default_to_deny():
    unknown_role = evaluate_policy(_policy_input(role="root"))
    missing_policy = evaluate_policy(
        _policy_input(role="platform_admin", action="delete", resource_type="asset")
    )
    missing_owner = evaluate_policy(
        _policy_input(role="admin", resource_tenant_id=None)
    )
    missing_subject = evaluate_policy(_policy_input(subject_tenant_id=None))

    assert unknown_role.reason == "unknown_role"
    assert missing_policy.reason == "missing_policy"
    assert missing_owner.reason == "missing_resource_owner"
    assert missing_subject.reason == "missing_subject_context"
    assert not any(
        (
            unknown_role.allow,
            missing_policy.allow,
            missing_owner.allow,
            missing_subject.allow,
        )
    )


def test_policy_input_and_decision_have_opa_compatible_shapes():
    input_data = _policy_input(role="analyst").to_opa_input()
    decision = evaluate_policy(_policy_input(role="analyst")).to_opa_output()

    assert input_data == {
        "subject": {
            "identity_id": "identity-a",
            "role": "analyst",
            "tenant_id": "tenant-a",
        },
        "action": "read",
        "resource": {"type": "asset", "tenant_id": "tenant-a"},
    }
    assert decision == {
        "allow": True,
        "reason": "allowed",
        "policy_id": "asset-read-v1",
    }


def test_admin_can_create_tenant_identity_without_accepting_client_tenant_id(
    client, create_identity, auth_headers
):
    admin = create_identity(role=IdentityRole.ADMIN.value)

    response = client.post(
        "/api/v1/identities",
        json={"email": "new-analyst@example.com", "role": "analyst"},
        headers=auth_headers(admin),
    )

    assert response.status_code == 201
    assert response.json()["tenant_id"] == admin.tenant_id

    cross_tenant_payload = client.post(
        "/api/v1/identities",
        json={
            "email": "forged@example.com",
            "role": "viewer",
            "tenant_id": "another-tenant",
        },
        headers=auth_headers(admin),
    )
    platform_role_payload = client.post(
        "/api/v1/identities",
        json={"email": "root@example.com", "role": "platform_admin"},
        headers=auth_headers(admin),
    )

    assert cross_tenant_payload.status_code == 422
    assert platform_role_payload.status_code == 422


def test_analyst_can_ingest_events_in_own_tenant(client, create_identity, auth_headers):
    analyst = create_identity(role="analyst")

    response = client.post(
        "/api/v1/security-events",
        json={
            "event_type": "failed_login",
            "severity": "high",
            "source": "test-agent",
            "description": "Clearly labeled authorization test event",
            "payload": {"test_data": True},
        },
        headers=auth_headers(analyst),
    )

    assert response.status_code == 201
    assert response.json()["tenant_id"] == analyst.tenant_id


def test_viewer_can_read_but_cannot_manage_identities_or_ingest_events(
    client, create_identity, auth_headers
):
    viewer = create_identity(role="viewer")
    headers = auth_headers(viewer)

    assert client.get("/api/v1/identities", headers=headers).status_code == 200
    identity_response = client.post(
        "/api/v1/identities",
        json={"email": "blocked@example.com"},
        headers=headers,
    )
    event_response = client.post(
        "/api/v1/security-events",
        json={
            "event_type": "test",
            "severity": "low",
            "source": "test-agent",
            "description": "Clearly labeled test event",
        },
        headers=headers,
    )

    assert identity_response.status_code == 403
    assert event_response.status_code == 403


def test_policy_evaluation_failure_denies_and_logs_no_token(
    client, create_identity, auth_headers, monkeypatch, caplog
):
    viewer = create_identity(role="viewer")
    headers = auth_headers(viewer)
    token = headers["Authorization"].removeprefix("Bearer ")

    def fail_evaluation(_policy_input):
        raise RuntimeError("sensitive evaluator details")

    monkeypatch.setattr(policy, "evaluate_policy", fail_evaluation)
    caplog.set_level(logging.ERROR, logger="app.security.policy")

    response = client.get("/api/v1/assets", headers=headers)

    assert response.status_code == 403
    assert "Authorization policy evaluation failed" in caplog.text
    assert "sensitive evaluator details" not in caplog.text
    assert token not in caplog.text
