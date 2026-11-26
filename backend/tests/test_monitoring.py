from datetime import datetime, timedelta, timezone

import pytest

from app.core.config import settings
from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.schemas.security_event import SecurityEventCreate
from app.services.event_normalization import normalize_event


def _event_payload(**overrides):
    payload = {
        "event_type": "test_observation",
        "severity": "medium",
        "source": "synthetic-monitoring-test",
        "description": "Clearly labelled synthetic monitoring test event.",
        "metadata": {"test_data": True},
        "origin": "simulated",
    }
    payload.update(overrides)
    return payload


def _ingest(client, identity, auth_headers, **overrides):
    return client.post(
        "/api/v1/security-events",
        json=_event_payload(**overrides),
        headers=auth_headers(identity),
    )


def test_event_normalization_canonicalizes_and_converts_to_utc():
    timestamp = datetime.now(timezone(timedelta(hours=2)))
    event = normalize_event(
        SecurityEventCreate.model_validate(
            _event_payload(
                event_type=" Failed-Login ",
                severity="HIGH",
                source=" identity-provider ",
                description=" Synthetic event ",
                timestamp=timestamp.isoformat(),
            )
        )
    )

    assert event.event_type == "failed_login"
    assert event.severity == "high"
    assert event.source == "identity-provider"
    assert event.timestamp.utcoffset() == timedelta(0)
    assert event.origin == "simulated"


def test_event_ingestion_uses_identity_tenant_and_returns_normalized_metadata(
    client, create_tenant, create_identity, auth_headers
):
    tenant = create_tenant(slug="monitoring-ingest")
    analyst = create_identity(tenant=tenant, role="analyst")
    timestamp = datetime.now(timezone.utc).isoformat()

    response = _ingest(
        client,
        analyst,
        auth_headers,
        event_type=" Failed-Login ",
        severity="High",
        timestamp=timestamp,
        tenant_id="forged-tenant",
    )

    assert response.status_code == 422
    valid_response = _ingest(
        client,
        analyst,
        auth_headers,
        event_type=" Failed-Login ",
        severity="High",
        timestamp=timestamp,
    )
    assert valid_response.status_code == 201
    body = valid_response.json()
    assert body["tenant_id"] == tenant.id
    assert body["event_type"] == "failed_login"
    assert body["severity"] == "high"
    assert body["origin"] == "simulated"
    assert body["metadata"] == {"test_data": True}
    assert body["payload"] == body["metadata"]
    response_timestamp = datetime.fromisoformat(
        body["timestamp"].replace("Z", "+00:00")
    )
    assert response_timestamp.utcoffset() == timedelta(0)


def test_platform_admin_can_ingest_events_in_its_authenticated_tenant(
    client, create_tenant, create_identity, auth_headers
):
    tenant = create_tenant(slug="monitoring-platform-admin")
    platform_admin = create_identity(tenant=tenant, role="platform_admin")

    response = _ingest(client, platform_admin, auth_headers)

    assert response.status_code == 201
    assert response.json()["tenant_id"] == tenant.id


@pytest.mark.parametrize(
    "overrides",
    [
        {"event_type": "bad event!"},
        {"severity": "urgent"},
        {"origin": "scanner"},
        {"timestamp": "2026-01-01T10:00:00"},
        {
            "timestamp": (
                datetime.now(timezone.utc) + timedelta(minutes=6)
            ).isoformat()
        },
        {"metadata": {"data": "x" * 17_000}},
        {"description": " "},
    ],
)
def test_malformed_or_oversized_events_are_rejected(
    client, create_identity, auth_headers, overrides
):
    analyst = create_identity(role="analyst")

    response = _ingest(client, analyst, auth_headers, **overrides)

    assert response.status_code == 422


def test_legacy_payload_is_accepted_but_cannot_conflict_with_metadata(
    client, create_identity, auth_headers
):
    analyst = create_identity(role="analyst")
    legacy = _event_payload()
    legacy["payload"] = legacy.pop("metadata")
    response = client.post(
        "/api/v1/security-events",
        json=legacy,
        headers=auth_headers(analyst),
    )
    conflicting = client.post(
        "/api/v1/security-events",
        json={**_event_payload(), "payload": {"legacy": True}},
        headers=auth_headers(analyst),
    )

    assert response.status_code == 201
    assert response.json()["metadata"] == {"test_data": True}
    assert conflicting.status_code == 422


@pytest.mark.parametrize(
    ("event_type", "severity", "expected_rule"),
    [
        ("suspicious_login", "low", "suspicious_login_activity"),
        (
            "privilege_escalation_attempt",
            "medium",
            "privilege_escalation_attempt",
        ),
        ("test_observation", "critical", "high_severity_event"),
    ],
)
def test_deterministic_event_rules_generate_alerts(
    client, create_identity, auth_headers, event_type, severity, expected_rule
):
    analyst = create_identity(role="analyst")
    response = _ingest(
        client,
        analyst,
        auth_headers,
        event_type=event_type,
        severity=severity,
    )

    assert response.status_code == 201
    alert_response = client.get("/api/v1/alerts", headers=auth_headers(analyst))
    assert alert_response.status_code == 200
    assert [alert["rule_id"] for alert in alert_response.json()] == [expected_rule]


def test_repeated_failed_authentication_uses_configured_threshold(
    client, create_identity, auth_headers, monkeypatch
):
    monkeypatch.setattr(settings, "detection_failed_auth_threshold", 3)
    monkeypatch.setattr(settings, "detection_failed_auth_window_seconds", 600)
    analyst = create_identity(role="analyst")

    responses = [
        _ingest(
            client,
            analyst,
            auth_headers,
            event_type="failed_login",
            severity="medium",
        )
        for _ in range(3)
    ]
    alerts = client.get("/api/v1/alerts", headers=auth_headers(analyst)).json()

    assert all(response.status_code == 201 for response in responses)
    assert [alert["rule_id"] for alert in alerts] == [
        "repeated_failed_authentication"
    ]


def test_events_outside_the_detection_window_do_not_match(
    client, db_session, create_identity, auth_headers, monkeypatch
):
    monkeypatch.setattr(settings, "detection_failed_auth_threshold", 3)
    monkeypatch.setattr(settings, "detection_failed_auth_window_seconds", 600)
    analyst = create_identity(role="analyst")
    old_time = datetime.now(timezone.utc) - timedelta(minutes=20)
    db_session.add_all(
        [
            SecurityEvent(
                tenant_id=analyst.tenant_id,
                event_type="failed_login",
                severity="medium",
                source="synthetic-monitoring-test",
                description="Clearly labelled synthetic old test event.",
                payload={"test_data": True},
                event_timestamp=old_time,
                created_at=old_time,
            )
            for _ in range(2)
        ]
    )
    db_session.commit()

    response = _ingest(
        client,
        analyst,
        auth_headers,
        event_type="failed_login",
    )

    assert response.status_code == 201
    assert client.get(
        "/api/v1/alerts", headers=auth_headers(analyst)
    ).json() == []


def test_repeated_access_denied_rule_and_tenant_isolation(
    client, create_tenant, create_identity, auth_headers, monkeypatch
):
    monkeypatch.setattr(settings, "detection_access_denied_threshold", 3)
    monkeypatch.setattr(settings, "detection_access_denied_window_seconds", 600)
    tenant_a = create_tenant(slug="monitoring-tenant-a")
    tenant_b = create_tenant(slug="monitoring-tenant-b")
    analyst_a = create_identity(tenant=tenant_a, role="analyst")
    analyst_b = create_identity(tenant=tenant_b, role="analyst")

    for _ in range(2):
        assert _ingest(
            client,
            analyst_b,
            auth_headers,
            event_type="access_denied",
        ).status_code == 201
    for _ in range(2):
        assert _ingest(
            client,
            analyst_a,
            auth_headers,
            event_type="access_denied",
        ).status_code == 201
    assert _ingest(
        client,
        analyst_a,
        auth_headers,
        event_type="access_denied",
    ).status_code == 201

    alerts_a = client.get("/api/v1/alerts", headers=auth_headers(analyst_a))
    alerts_b = client.get("/api/v1/alerts", headers=auth_headers(analyst_b))
    assert len(alerts_a.json()) == 1
    assert alerts_a.json()[0]["rule_id"] == "repeated_access_denied"
    assert alerts_b.json() == []


def test_alert_tenant_isolation_and_status_permissions(
    client, create_tenant, create_identity, auth_headers
):
    tenant_a = create_tenant(slug="alert-owner-a")
    tenant_b = create_tenant(slug="alert-owner-b")
    analyst_a = create_identity(tenant=tenant_a, role="analyst")
    analyst_b = create_identity(tenant=tenant_b, role="analyst")
    viewer_a = create_identity(tenant=tenant_a, role="viewer")
    for analyst in (analyst_a, analyst_b):
        assert _ingest(
            client,
            analyst,
            auth_headers,
            event_type="suspicious_login",
        ).status_code == 201
    alert_b = client.get(
        "/api/v1/alerts",
        headers=auth_headers(analyst_b),
    ).json()[0]

    assert client.get(
        f"/api/v1/alerts/{alert_b['id']}",
        headers=auth_headers(analyst_a),
    ).status_code == 404
    assert client.patch(
        f"/api/v1/alerts/{alert_b['id']}",
        json={"status": "Resolved"},
        headers=auth_headers(analyst_a),
    ).status_code == 404
    assert client.patch(
        f"/api/v1/alerts/{alert_b['id']}",
        json={"status": "Acknowledged"},
        headers=auth_headers(viewer_a),
    ).status_code == 403
    assert client.get("/api/v1/alerts", headers=auth_headers(viewer_a)).status_code == 200
    updated = client.patch(
        f"/api/v1/alerts/{alert_b['id']}",
        json={"status": "Acknowledged"},
        headers=auth_headers(analyst_b),
    )
    assert updated.status_code == 200
    assert updated.json()["status"] == "Acknowledged"


def test_admin_can_update_alert_status(client, create_identity, auth_headers):
    admin = create_identity(role="admin")
    assert _ingest(
        client,
        admin,
        auth_headers,
        event_type="privilege_escalation_attempt",
    ).status_code == 201
    alert = client.get("/api/v1/alerts", headers=auth_headers(admin)).json()[0]

    response = client.patch(
        f"/api/v1/alerts/{alert['id']}",
        json={"status": "Resolved"},
        headers=auth_headers(admin),
    )

    assert response.status_code == 200
    assert response.json()["status"] == "Resolved"


def test_monitoring_summary_is_tenant_scoped_and_calculates_metrics(
    client, create_tenant, create_identity, auth_headers
):
    tenant_a = create_tenant(slug="summary-monitoring-a")
    tenant_b = create_tenant(slug="summary-monitoring-b")
    analyst_a = create_identity(tenant=tenant_a, role="analyst")
    analyst_b = create_identity(tenant=tenant_b, role="analyst")
    _ingest(
        client,
        analyst_a,
        auth_headers,
        severity="critical",
        source="synthetic-idp",
        event_type="test_observation",
    )
    _ingest(
        client,
        analyst_a,
        auth_headers,
        severity="high",
        source="synthetic-endpoint",
        event_type="test_observation",
    )
    _ingest(
        client,
        analyst_b,
        auth_headers,
        severity="critical",
        source="other-tenant",
        event_type="suspicious_login",
    )
    analyst_alerts = client.get(
        "/api/v1/alerts",
        headers=auth_headers(analyst_a),
    ).json()
    client.patch(
        f"/api/v1/alerts/{analyst_alerts[0]['id']}",
        json={"status": "Acknowledged"},
        headers=auth_headers(analyst_a),
    )

    response = client.get(
        "/api/v1/security-events/summary?days=2",
        headers=auth_headers(analyst_a),
    )
    body = response.json()

    assert response.status_code == 200
    assert body["total_events"] == 2
    assert body["critical_events"] == 1
    assert body["high_severity_events"] == 1
    assert body["events_by_source"] == {
        "synthetic-idp": 1,
        "synthetic-endpoint": 1,
    }
    assert body["new_alerts"] == 1
    assert body["acknowledged_alerts"] == 1
    assert body["resolved_alerts"] == 0
    assert len(body["events_over_time"]) == 2
    assert sum(bucket["count"] for bucket in body["events_over_time"]) == 2


def test_alert_status_values_are_validated_and_alert_origin_is_not_client_settable(
    client, create_identity, auth_headers
):
    analyst = create_identity(role="analyst")
    assert _ingest(
        client,
        analyst,
        auth_headers,
        event_type="privilege_escalation_attempt",
    ).status_code == 201
    alert = client.get("/api/v1/alerts", headers=auth_headers(analyst)).json()[0]

    invalid_status = client.patch(
        f"/api/v1/alerts/{alert['id']}",
        json={"status": "Closed"},
        headers=auth_headers(analyst),
    )
    extra_field = client.patch(
        f"/api/v1/alerts/{alert['id']}",
        json={"status": "Resolved", "tenant_id": "forged"},
        headers=auth_headers(analyst),
    )

    assert invalid_status.status_code == 422
    assert extra_field.status_code == 422


def test_event_and_alert_logs_do_not_include_event_contents(
    client, create_identity, auth_headers, caplog
):
    analyst = create_identity(role="analyst")
    secret_like_value = "synthetic-sensitive-value-avoid-logging"

    response = _ingest(
        client,
        analyst,
        auth_headers,
        event_type="suspicious_login",
        description=secret_like_value,
        metadata={"credential": secret_like_value},
    )

    assert response.status_code == 201
    assert secret_like_value not in caplog.text


def test_alert_model_has_tenant_and_event_foreign_keys(db_session, create_identity):
    analyst = create_identity(role="analyst")
    event = SecurityEvent(
        tenant_id=analyst.tenant_id,
        event_type="unit_test",
        severity="low",
        source="synthetic",
        description="Clearly labelled synthetic event.",
        payload={},
    )
    db_session.add(event)
    db_session.flush()
    alert = Alert(
        tenant_id=analyst.tenant_id,
        event_id=event.id,
        rule_id="test-rule",
        severity="low",
        description="Synthetic test alert.",
    )
    db_session.add(alert)
    db_session.commit()

    assert alert.event_id == event.id
    assert alert.tenant_id == analyst.tenant_id
