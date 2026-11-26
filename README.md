# SentinelKey - Unified Cybersecurity & Zero-Trust Platform

**SentinelKey is a modular cybersecurity engineering project that falls under CompTIA Security+ designed to integrate identity security, network threat detection, vulnerability management, cryptographic key management, incident response, and security governance.**

---

## Core Modules
- Zero-Trust Identity & Access Management 
- Network Security & Packet Analysis
- Threat Detection & Security Monitoring
- Vulnerability Assessment & Management
- Cryptographic Key Management & PKI
- Incident Response & Digital Forencics
- Governance, Risk & Complianace

---

## Technology Stack
- Python
- FastAPI
- React
- TypeScript
- PostgreSQL
- Redis
- Docker
- Keycloak
- Open Policy Agent
- Wazuh
- Wireshark
- Suricata
- Zeek
- Greenbone
- HashiCorp Vault

---

## Project Status
Status: Initial setup / Under Development

**Individual modules will be implemented, tested and integrated incrementally.**

## Frontend foundation

The React, TypeScript, Vite, Tailwind CSS, and React Router frontend is in
`frontend/`. Start the FastAPI backend on `127.0.0.1:8000`, then run the
frontend from its directory:

```powershell
npm install
npm run dev
```

Vite proxies `/api` requests to the local backend. The Phase 1 screens are
navigation placeholders; no security data is mocked. There is no login API:
generate a short-lived development token with the backend CLI and paste it into
the frontend token-entry form. The token exists in browser memory only and is
cleared on sign out or page reload. See `frontend/README.md` for build and test
commands.

## Local API authentication

The API uses signed bearer tokens for protected routes. Tenant, role, and active
status are loaded from the database identity record after token verification;
tenant IDs and roles in client input are not used to authorize access.

The default `development` auth mode supports short-lived HS256 tokens for local
testing only. It requires a locally configured `SENTINELKEY_JWT_SECRET` of at
least 32 characters and refuses to issue or accept development tokens when
`SENTINELKEY_ENVIRONMENT` is not `development`. No secret is included in this
repository. Copy `.env.example` to `backend/.env` and set a private generated
secret there; `.env` is ignored by Git.

From the `backend` directory, after configuring the environment:

```powershell
Copy-Item ..\.env.example .env
.\venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))"
# Put the generated value in SENTINELKEY_JWT_SECRET in the local .env file.
.\venv\Scripts\python.exe -m alembic upgrade head
.\venv\Scripts\python.exe -m app.security.dev_token `
  --tenant-name "Local Lab" `
  --tenant-slug local-lab `
  --email admin@example.com `
  --role platform_admin
```

The command creates a local tenant and active human identity if they do not
already exist, then prints a 15-minute bearer token to standard output. It is
restricted to development auth mode. Treat the token as a credential and do
not paste it into logs or commit it.

Use the token with a protected endpoint (PowerShell example):

Start the API in a separate PowerShell terminal from `backend`:

```powershell
.\venv\Scripts\python.exe -m uvicorn main:app --reload
```

In the configured terminal, request a token and call the endpoint:

```powershell
$token = .\venv\Scripts\python.exe -m app.security.dev_token `
  --tenant-name "Local Lab" `
  --tenant-slug local-lab `
  --email admin@example.com `
  --role platform_admin
$headers = @{ Authorization = "Bearer $token" }
Invoke-RestMethod http://127.0.0.1:8000/api/v1/identities -Headers $headers
```

Protected tenant/resource reads require a valid identity and are scoped to that
identity's tenant. Only `platform_admin` may create tenants; tenant admins,
analysts, and viewers cannot perform that global action. Root, liveness, and
database-health endpoints remain public.

## Authorization policies

Protected routes use a centralized, default-deny policy evaluator separate
from JWT authentication. Policy input is JSON-shaped for a future OPA adapter:
verified subject identity, database-backed role and tenant, action, resource
type, and the resource's owning tenant. Route handlers derive tenant ownership
from the authenticated identity; client-supplied tenant IDs are rejected or
never used to select records.

| Role | Read tenant resources | Manage identities | Ingest security events | Create tenants | Cross-tenant access |
| --- | --- | --- | --- | --- | --- |
| `platform_admin` | Yes | Yes | Yes | Yes | Allowed by policy |
| `admin` | Own tenant | Own tenant | Own tenant | No | Denied |
| `analyst` | Own tenant | No | Own tenant | No | Denied |
| `viewer` | Own tenant | No | No | No | Denied |

Unknown roles, missing policy rules, missing ownership context, and policy
evaluation errors deny access with HTTP 403. Denials are logged with only
role/action/resource and a fixed reason code; tokens, passwords, and evaluator
details are not logged. The in-process evaluator and its input/output are
designed to map to OPA/Rego, but **OPA is not integrated**.

For OIDC-compatible validation, set `SENTINELKEY_AUTH_MODE=oidc`,
`SENTINELKEY_OIDC_JWKS_URL`, `SENTINELKEY_JWT_ISSUER`, and
`SENTINELKEY_JWT_AUDIENCE`. The API validates RS256 signatures and standard
issuer, audience, and time claims, then maps the verified issuer/subject pair
to an active database identity. This is a generic JWKS-based validation path;
Keycloak itself is not currently integrated. Federated identity provisioning
is not yet exposed as an API.

## Security monitoring and alerts

Apply the current schema from `backend`:

```powershell
.\venv\Scripts\python.exe -m alembic upgrade head
```

Ingest events using a token for an admin or analyst. The API takes `tenant_id`
from the authenticated identity; sending a `tenant_id` in the request is
rejected. Event timestamps must include a timezone and cannot be more than five
minutes in the future. Event types are normalized to lowercase snake case and
severity to `critical`, `high`, `medium`, `low`, or `informational`. Metadata is
JSON and limited by `SENTINELKEY_EVENT_METADATA_MAX_BYTES` (16 KiB by default).
The older `payload` field remains accepted as a compatibility alias for
`metadata` but cannot be sent alongside it.

Example (synthetic data only; the `simulated` origin is explicit):

```powershell
$event = @{
  event_type = "failed_login"
  severity = "medium"
  source = "synthetic-identity-provider"
  description = "Synthetic demonstration failed-login event."
  timestamp = [DateTime]::UtcNow.ToString("o")
  metadata = @{ test_data = $true }
  origin = "simulated"
} | ConvertTo-Json
Invoke-RestMethod http://127.0.0.1:8000/api/v1/security-events `
  -Method Post -Headers $headers -Body $event -ContentType "application/json"
```

Detection rules are deterministic and tenant-scoped. Repeated-event windows use
server-recorded ingestion time, not the client timestamp:

| Rule ID | Match condition | Default |
| --- | --- | --- |
| `repeated_failed_authentication` | `failed_login`, `failed_authentication`, or `authentication_failed` | 5 events in 600 seconds |
| `suspicious_login_activity` | `suspicious_login`, `unusual_login`, or `login_from_unusual_location` | Each matching event |
| `repeated_access_denied` | `access_denied` or `authorization_denied` | 5 events in 600 seconds |
| `privilege_escalation_attempt` | `privilege_escalation` or `privilege_escalation_attempt` | Each matching event |
| `high_severity_event` | Severity is `high` or `critical` | Each matching event |

Thresholds and windows can be configured with
`SENTINELKEY_DETECTION_FAILED_AUTH_THRESHOLD`,
`SENTINELKEY_DETECTION_FAILED_AUTH_WINDOW_SECONDS`,
`SENTINELKEY_DETECTION_ACCESS_DENIED_THRESHOLD`, and
`SENTINELKEY_DETECTION_ACCESS_DENIED_WINDOW_SECONDS`. Admins and analysts can
update alert status; platform admins, admins, and analysts can ingest events.
All roles can read their tenant's events and alerts. Alert reads and updates are
tenant-scoped; cross-tenant alert IDs return 404.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/security-events` | Ingest a validated event and evaluate detection rules |
| `GET` | `/api/v1/security-events` | List this tenant's events |
| `GET` | `/api/v1/security-events/summary?days=30` | Tenant summary with event-source counts, alert statuses, and daily event counts (1–90 days) |
| `GET` | `/api/v1/alerts` | List tenant alerts; optional `status` filter |
| `GET` | `/api/v1/alerts/{id}` | Retrieve a tenant alert |
| `PATCH` | `/api/v1/alerts/{id}` | Set alert status to `New`, `Acknowledged`, or `Resolved` |

This module uses event signals supplied by the caller; a `suspicious_login` or
privilege-escalation event is an assertion, not an independent identity-provider
analysis. It does not provide machine-learning detection, live threat
intelligence, or Wazuh, Suricata, or Zeek integration.

## Vulnerability management

Apply the schema migration from the `backend` directory:

```powershell
.\venv\Scripts\alembic.exe upgrade head
```

The tenant-scoped vulnerability API provides:

| Method | Path | Purpose | Authorization |
| --- | --- | --- | --- |
| `GET` | `/api/v1/vulnerabilities` | List findings; optional `severity`, `status`, `asset_id`, and `cve_id` filters | Read |
| `POST` | `/api/v1/vulnerabilities` | Create a finding | Admin or analyst |
| `GET` | `/api/v1/vulnerabilities/{id}` | Retrieve a finding | Read |
| `PATCH` | `/api/v1/vulnerabilities/{id}` | Update finding fields/status | Admin or analyst |
| `GET` | `/api/v1/vulnerabilities/summary` | Tenant summary metrics | Read |

All reads and writes are scoped to the authenticated tenant. The API resolves
the asset within that tenant and does not accept a vulnerability `tenant_id`.
Cross-tenant or missing assets/findings return 404. CVSS scores must be finite
and in the inclusive range 0–10; severity and status values are case-sensitive.
Viewers can read but cannot create or update. Platform administrators have
explicit read access only for this module; their other permissions do not
implicitly grant vulnerability writes.

Example requests (run from PowerShell after obtaining a development token as
described above; replace the asset ID with one belonging to the token's tenant):

```powershell
$headers = @{
  Authorization = "Bearer $token"
  "Content-Type" = "application/json"
}
$body = @{
  asset_id = "00000000-0000-4000-8000-000000000001"
  title = "Outdated TLS configuration"
  description = "The service allows a deprecated TLS protocol."
  cve_id = "CVE-2025-1234"
  cvss_score = 8.1
  severity = "High"
  status = "Open"
  detection_source = "manual-review"
  remediation_recommendation = "Disable deprecated TLS versions."
  remediation_due_date = "2026-12-15"
} | ConvertTo-Json
Invoke-RestMethod http://127.0.0.1:8000/api/v1/vulnerabilities `
  -Method Post -Headers $headers -Body $body

Invoke-RestMethod "http://127.0.0.1:8000/api/v1/vulnerabilities?severity=High&status=Open" `
  -Headers $headers
Invoke-RestMethod http://127.0.0.1:8000/api/v1/vulnerabilities/summary `
  -Headers $headers
```

Overdue metrics count findings with a due date before the current UTC date and
status `Open` or `In Progress`; resolved and accepted-risk findings are not
counted as overdue. Findings can be entered through the API, but no vulnerability
scanner (including Greenbone/OpenVAS) is integrated.

---

## Note:
SentinelKey is a credit-based group project made to enhance Technical Skills in the area of cybersecurity. It is not affiliated with or endorsed by CompTIA. All security testing is intended for authorised, isolated lab environments.

## Created By:
- Anushka Sarkar CSE-Cyber Security Sec : BA
- Sangana Chamundeswari CSE-Cyber Security Sec : BA
