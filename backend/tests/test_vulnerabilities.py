from datetime import datetime, timedelta, timezone

import pytest

from app.models.asset import Asset
from app.models.vulnerability import Vulnerability


def _create_asset(db_session, tenant_id: str, suffix: str) -> Asset:
    asset = Asset(
        tenant_id=tenant_id,
        hostname=f"vulnerability-{suffix}.example.com",
        asset_type="server",
        criticality="high",
    )
    db_session.add(asset)
    db_session.commit()
    db_session.refresh(asset)
    return asset


def _vulnerability_payload(asset_id: str, **overrides) -> dict[str, object]:
    payload: dict[str, object] = {
        "asset_id": asset_id,
        "title": "Outdated TLS configuration",
        "description": "The service allows a deprecated TLS protocol.",
        "cve_id": "CVE-2025-1234",
        "cvss_score": 8.1,
        "severity": "High",
        "status": "Open",
        "detection_source": "manual-review",
        "remediation_recommendation": "Disable deprecated TLS versions.",
    }
    payload.update(overrides)
    return payload


def _persist_vulnerability(
    db_session,
    tenant_id: str,
    asset_id: str,
    *,
    severity: str,
    status: str,
    due_date,
) -> Vulnerability:
    vulnerability = Vulnerability(
        tenant_id=tenant_id,
        asset_id=asset_id,
        title=f"{severity} finding",
        description="Clearly labeled test vulnerability.",
        cvss_score=7.0,
        severity=severity,
        status=status,
        detection_source="automated-test-fixture",
        remediation_recommendation="This is test data only.",
        remediation_due_date=due_date,
    )
    db_session.add(vulnerability)
    db_session.commit()
    db_session.refresh(vulnerability)
    return vulnerability


def test_analyst_can_create_and_retrieve_vulnerability(
    client, db_session, create_identity, auth_headers
):
    analyst = create_identity(role="analyst")
    asset = _create_asset(db_session, analyst.tenant_id, "analyst")

    response = client.post(
        "/api/v1/vulnerabilities",
        json=_vulnerability_payload(asset.id),
        headers=auth_headers(analyst),
    )

    assert response.status_code == 201
    body = response.json()
    assert body["tenant_id"] == analyst.tenant_id
    assert body["asset_id"] == asset.id
    assert body["status"] == "Open"
    assert body["first_detected_at"]
    assert body["last_updated_at"]

    detail = client.get(
        f"/api/v1/vulnerabilities/{body['id']}",
        headers=auth_headers(analyst),
    )
    assert detail.status_code == 200
    assert detail.json()["id"] == body["id"]


def test_vulnerability_list_filters_by_severity_status_and_asset(
    client, db_session, create_identity, auth_headers
):
    analyst = create_identity(role="analyst")
    asset_a = _create_asset(db_session, analyst.tenant_id, "filter-a")
    asset_b = _create_asset(db_session, analyst.tenant_id, "filter-b")
    headers = auth_headers(analyst)
    created = []
    for asset, severity, status_value in (
        (asset_a, "Critical", "Open"),
        (asset_b, "High", "Resolved"),
    ):
        response = client.post(
            "/api/v1/vulnerabilities",
            json=_vulnerability_payload(
                asset.id,
                severity=severity,
                status=status_value,
                cve_id=None,
            ),
            headers=headers,
        )
        assert response.status_code == 201
        created.append(response.json())

    critical = client.get(
        "/api/v1/vulnerabilities",
        params={"severity": "Critical"},
        headers=headers,
    )
    resolved = client.get(
        "/api/v1/vulnerabilities",
        params={"status": "Resolved"},
        headers=headers,
    )
    asset_filter = client.get(
        "/api/v1/vulnerabilities",
        params={"asset_id": asset_a.id},
        headers=headers,
    )

    assert [row["id"] for row in critical.json()] == [created[0]["id"]]
    assert [row["id"] for row in resolved.json()] == [created[1]["id"]]
    assert [row["id"] for row in asset_filter.json()] == [created[0]["id"]]


@pytest.mark.parametrize("cvss_score", [-0.1, 10.1])
def test_invalid_cvss_score_is_rejected(
    client, db_session, create_identity, auth_headers, cvss_score
):
    analyst = create_identity(role="analyst")
    asset = _create_asset(db_session, analyst.tenant_id, "invalid-cvss")

    response = client.post(
        "/api/v1/vulnerabilities",
        json=_vulnerability_payload(asset.id, cvss_score=cvss_score),
        headers=auth_headers(analyst),
    )

    assert response.status_code == 422


@pytest.mark.parametrize(
    ("field", "value"),
    [("severity", "Urgent"), ("status", "Closed")],
)
def test_invalid_severity_and_status_are_rejected(
    client, db_session, create_identity, auth_headers, field, value
):
    analyst = create_identity(role="analyst")
    asset = _create_asset(db_session, analyst.tenant_id, "invalid-enum")

    response = client.post(
        "/api/v1/vulnerabilities",
        json=_vulnerability_payload(asset.id, **{field: value}),
        headers=auth_headers(analyst),
    )

    assert response.status_code == 422


def test_analyst_can_update_vulnerability_status(
    client, db_session, create_identity, auth_headers
):
    analyst = create_identity(role="analyst")
    asset = _create_asset(db_session, analyst.tenant_id, "analyst-update")
    create_response = client.post(
        "/api/v1/vulnerabilities",
        json=_vulnerability_payload(asset.id),
        headers=auth_headers(analyst),
    )
    vulnerability_id = create_response.json()["id"]

    response = client.patch(
        f"/api/v1/vulnerabilities/{vulnerability_id}",
        json={"status": "In Progress"},
        headers=auth_headers(analyst),
    )

    assert response.status_code == 200
    assert response.json()["status"] == "In Progress"


def test_admin_can_manage_vulnerabilities_in_own_tenant(
    client, db_session, create_identity, auth_headers
):
    admin = create_identity(role="admin")
    asset = _create_asset(db_session, admin.tenant_id, "admin")

    created = client.post(
        "/api/v1/vulnerabilities",
        json=_vulnerability_payload(asset.id),
        headers=auth_headers(admin),
    )
    updated = client.patch(
        f"/api/v1/vulnerabilities/{created.json()['id']}",
        json={"status": "Accepted Risk"},
        headers=auth_headers(admin),
    )

    assert created.status_code == 201
    assert updated.status_code == 200
    assert updated.json()["status"] == "Accepted Risk"


def test_viewer_is_read_only_for_vulnerability_endpoints(
    client, db_session, create_identity, auth_headers
):
    viewer = create_identity(role="viewer")
    asset = _create_asset(db_session, viewer.tenant_id, "viewer")
    vulnerability = _persist_vulnerability(
        db_session,
        viewer.tenant_id,
        asset.id,
        severity="Low",
        status="Open",
        due_date=None,
    )
    headers = auth_headers(viewer)

    assert (
        client.get(
            f"/api/v1/vulnerabilities/{vulnerability.id}",
            headers=headers,
        ).status_code
        == 200
    )
    create_response = client.post(
        "/api/v1/vulnerabilities",
        json=_vulnerability_payload(asset.id),
        headers=headers,
    )
    update_response = client.patch(
        f"/api/v1/vulnerabilities/{vulnerability.id}",
        json={"status": "Resolved"},
        headers=headers,
    )

    assert create_response.status_code == 403
    assert update_response.status_code == 403


def test_platform_admin_has_only_explicit_vulnerability_permissions(
    client, db_session, create_identity, auth_headers
):
    platform_admin = create_identity(role="platform_admin")
    asset = _create_asset(db_session, platform_admin.tenant_id, "platform-admin")
    headers = auth_headers(platform_admin)

    read_response = client.get("/api/v1/vulnerabilities", headers=headers)
    create_response = client.post(
        "/api/v1/vulnerabilities",
        json=_vulnerability_payload(asset.id),
        headers=headers,
    )

    assert read_response.status_code == 200
    assert create_response.status_code == 403


def test_cross_tenant_vulnerability_reads_are_hidden(
    client, db_session, create_tenant, create_identity, auth_headers
):
    tenant_a = create_tenant(slug="vulnerability-tenant-a")
    tenant_b = create_tenant(slug="vulnerability-tenant-b")
    identity_a = create_identity(
        tenant=tenant_a,
        role="analyst",
        email="vulnerability-a@example.com",
    )
    asset_b = _create_asset(db_session, tenant_b.id, "tenant-b")
    vulnerability_b = _persist_vulnerability(
        db_session,
        tenant_b.id,
        asset_b.id,
        severity="Critical",
        status="Open",
        due_date=None,
    )
    headers = auth_headers(identity_a)

    list_response = client.get(
        "/api/v1/vulnerabilities",
        params={"tenant_id": tenant_b.id},
        headers=headers,
    )
    detail_response = client.get(
        f"/api/v1/vulnerabilities/{vulnerability_b.id}",
        headers=headers,
    )

    assert list_response.status_code == 200
    assert list_response.json() == []
    assert detail_response.status_code == 404


def test_cross_tenant_asset_assignment_is_rejected_for_create_and_update(
    client, db_session, create_tenant, create_identity, auth_headers
):
    tenant_a = create_tenant(slug="asset-owner-a")
    tenant_b = create_tenant(slug="asset-owner-b")
    analyst = create_identity(
        tenant=tenant_a,
        role="analyst",
        email="asset-analyst@example.com",
    )
    asset_a = _create_asset(db_session, tenant_a.id, "owned-a")
    asset_b = _create_asset(db_session, tenant_b.id, "owned-b")
    headers = auth_headers(analyst)
    create_response = client.post(
        "/api/v1/vulnerabilities",
        json=_vulnerability_payload(asset_b.id),
        headers=headers,
    )
    vulnerability = _persist_vulnerability(
        db_session,
        tenant_a.id,
        asset_a.id,
        severity="High",
        status="Open",
        due_date=None,
    )
    update_response = client.patch(
        f"/api/v1/vulnerabilities/{vulnerability.id}",
        json={"asset_id": asset_b.id},
        headers=headers,
    )

    assert create_response.status_code == 404
    assert update_response.status_code == 404
    assert vulnerability.asset_id == asset_a.id


def test_summary_counts_are_tenant_scoped_and_exclude_closed_from_overdue(
    client, db_session, create_tenant, create_identity, auth_headers
):
    tenant_a = create_tenant(slug="summary-tenant-a")
    tenant_b = create_tenant(slug="summary-tenant-b")
    analyst_a = create_identity(
        tenant=tenant_a,
        role="analyst",
        email="summary-a@example.com",
    )
    asset_a = _create_asset(db_session, tenant_a.id, "summary-a")
    asset_b = _create_asset(db_session, tenant_b.id, "summary-b")
    today = datetime.now(timezone.utc).date()
    yesterday = today - timedelta(days=1)
    tomorrow = today + timedelta(days=1)
    for severity, finding_status, due_date in (
        ("Critical", "Open", yesterday),
        ("High", "In Progress", yesterday),
        ("Medium", "Resolved", yesterday),
        ("Low", "Accepted Risk", yesterday),
        ("Informational", "Open", tomorrow),
    ):
        _persist_vulnerability(
            db_session,
            tenant_a.id,
            asset_a.id,
            severity=severity,
            status=finding_status,
            due_date=due_date,
        )
    _persist_vulnerability(
        db_session,
        tenant_b.id,
        asset_b.id,
        severity="Critical",
        status="Open",
        due_date=yesterday,
    )

    response = client.get(
        "/api/v1/vulnerabilities/summary",
        headers=auth_headers(analyst_a),
    )

    assert response.status_code == 200
    assert response.json() == {
        "total_vulnerabilities": 5,
        "critical_findings": 1,
        "high_findings": 1,
        "medium_findings": 1,
        "low_findings": 1,
        "open_findings": 2,
        "resolved_findings": 1,
        "overdue_findings": 2,
    }
