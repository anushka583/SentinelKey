# SentinelKey — Unified Cybersecurity & Zero-Trust Platform

SentinelKey is a modular cybersecurity engineering project designed around concepts covered by CompTIA Security+. It aims to bring together identity security, network security, threat detection, vulnerability management, cryptographic key management, incident response, and security governance in a unified platform.

The project is being developed incrementally, with an emphasis on tenant isolation, centralized authorization, secure API design, and practical cybersecurity engineering.

> SentinelKey is an independent educational project. It is not affiliated with or endorsed by CompTIA.

---

## Core Modules

The planned platform covers the following security areas:

- Zero-Trust Identity & Access Management
- Network Security & Packet Analysis
- Threat Detection & Security Monitoring
- Vulnerability Assessment & Management
- Cryptographic Key Management & PKI
- Incident Response & Digital Forensics
- Governance, Risk & Compliance

Implementation and integration of these modules will take place incrementally.

---

## Current Implementation Status

| Area | Current status |
|---|---|
| Backend foundation | Implemented |
| Database models and migrations | Implemented |
| JWT authentication | Implemented |
| Tenant-scoped authorization | Implemented |
| Centralized authorization policy evaluator | Implemented |
| Security event ingestion | Implemented |
| Deterministic threat detection rules | Implemented |
| Alert management API | Implemented |
| Vulnerability management API | Implemented |
| React frontend foundation | Implemented |
| Token-entry authentication screen | Implemented |
| Overview dashboard | Implemented |
| Security Events frontend | Implemented |
| Alerts frontend | Placeholder |
| Vulnerabilities frontend | Placeholder |
| External OIDC provider integration | Generic JWKS validation supported; provider integration pending |
| OPA integration | Not integrated |
| SIEM and network monitoring integrations | Not integrated |
| External vulnerability scanner integration | Not integrated |

---

## Technology Stack

### Currently used

- Python
- FastAPI
- SQLAlchemy
- SQLite (default local database)
- PostgreSQL support
- Alembic
- Pytest
- React
- TypeScript
- Vite
- Tailwind CSS
- React Router
- Vitest

### Planned or potential integrations

These technologies are part of the broader platform direction, not all currently integrated:

- Redis
- Docker
- Keycloak
- Open Policy Agent (OPA)
- Wazuh
- Wireshark
- Suricata
- Zeek
- Greenbone / OpenVAS
- HashiCorp Vault

---

# Backend

## Backend Setup

From the repository root:

```powershell
cd backend
```

Activate the existing virtual environment if necessary, or create one:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Install dependencies using the project's dependency file.

Apply database migrations:

```powershell
.\venv\Scripts\python.exe -m alembic upgrade head
```

Start the FastAPI development server:

```powershell
.\venv\Scripts\python.exe -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

The backend is available at:

- API: `http://127.0.0.1:8000`
- Interactive API documentation: `http://127.0.0.1:8000/docs`

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

## Local API Authentication

The API uses signed bearer tokens to authenticate protected routes.

After token verification, the API resolves the token subject to an active identity in the database. The identity record supplies the tenant and role used for authorization.

Client-supplied tenant IDs and role claims are not trusted for access control.

### Authentication modes

The application supports:

- `development` — local HS256 token authentication.
- `oidc` — generic RS256/JWKS-based token verification.

Development authentication is intended for local testing only.

### Configure development authentication

The development token CLI requires:

- `SENTINELKEY_ENVIRONMENT=development`
- `SENTINELKEY_AUTH_MODE=development`
- `SENTINELKEY_JWT_SECRET` containing at least 32 characters.

No signing secret is included in the repository.

Copy the example environment file from the repository root into the backend directory:

```powershell
Copy-Item ..\.env.example .env
```

Generate a secure local secret:

```powershell
.\venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))"
```

Put the generated value in `SENTINELKEY_JWT_SECRET` in `backend/.env`. Ensure the environment and authentication mode are set to `development`.

The `.env` file is ignored by Git. Never commit the generated secret.

### Generate a development token

From the `backend` directory:

```powershell
.\venv\Scripts\python.exe -m app.security.dev_token --tenant-name "Local Lab" --tenant-slug "local-lab" --email "admin@example.com" --role platform_admin
```

Supported roles:

- `platform_admin`
- `admin`
- `analyst`
- `viewer`

The CLI creates or reuses the local tenant and active identity, then prints a short-lived bearer token.

The token expires after 15 minutes. Treat it as a credential and do not commit it or expose it in logs.

The API must use the same JWT signing secret as the token-generation command.

### Use the token

For example, from PowerShell:

```powershell
$token = "YOUR_TOKEN"
$headers = @{ Authorization = "Bearer $token" }

Invoke-RestMethod http://127.0.0.1:8000/api/v1/identities -Headers $headers
```

Root, liveness, and database-health endpoints remain public. Protected resource endpoints require valid authentication and authorization.

---

## Authentication and Identity Security

The authentication implementation includes:

- JWT signature verification.
- Token expiry and time-claim validation.
- Issuer and audience validation.
- Database-backed identity resolution.
- Active identity checks.
- Tenant and role resolution from the database.

The generic OIDC-compatible path supports RS256 and JWKS-based public-key verification.

It is not a completed Keycloak integration. Federated identity provisioning is not yet exposed as an API.

---

## Authorization Policies

Protected routes use a centralized, default-deny policy evaluator separate from JWT authentication.

The policy evaluator receives structured information including:

- Verified subject identity.
- Database-backed role and tenant.
- Requested action.
- Resource type.
- Resource ownership context.

Route handlers derive tenant ownership from the authenticated identity rather than trusting client-supplied tenant IDs.

### Role permissions

| Role | Read tenant resources | Manage identities | Ingest security events | Create tenants | Cross-tenant access |
|---|---|---|---|---|---|
| `platform_admin` | Yes | Yes | Yes | Yes | Allowed by policy |
| `admin` | Own tenant | Own tenant | Own tenant | No | Denied |
| `analyst` | Own tenant | No | Own tenant | No | Denied |
| `viewer` | Own tenant | No | No | No | Denied |

Unknown roles, missing policy rules, missing ownership context, and policy evaluation errors deny access.

The evaluator is structured to support a future OPA/Rego adapter, but **OPA is not currently integrated**.

---

# Security Monitoring and Alerts

## Security Event Ingestion

Security events can be submitted through the API by authorized users.

The API derives `tenant_id` from the authenticated identity. A client-supplied tenant ID is rejected.

Event validation includes:

- Timezone-aware timestamps.
- Rejection of timestamps more than five minutes in the future.
- Event-type normalization to lowercase snake case.
- Severity normalization to supported values.
- JSON metadata size limits.
- A default metadata limit of 16 KiB.

Supported severity levels:

- `critical`
- `high`
- `medium`
- `low`
- `informational`

The older `payload` field is accepted as a compatibility alias for `metadata`, but both cannot be supplied together.

### Example event

The following is synthetic demonstration data:

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
    -Method Post `
    -Headers $headers `
    -Body $event `
    -ContentType "application/json"
```

## Detection Rules

The current detection engine uses deterministic, tenant-scoped rules.

Repeated-event windows use server-recorded ingestion time rather than the client timestamp.

| Rule ID | Match condition | Default |
|---|---|---|
| `repeated_failed_authentication` | Failed authentication event types | 5 events in 600 seconds |
| `suspicious_login_activity` | Suspicious or unusual login event types | Each matching event |
| `repeated_access_denied` | Access-denied event types | 5 events in 600 seconds |
| `privilege_escalation_attempt` | Privilege-escalation event types | Each matching event |
| `high_severity_event` | Severity is `high` or `critical` | Each matching event |

Thresholds and windows can be configured using:

- `SENTINELKEY_DETECTION_FAILED_AUTH_THRESHOLD`
- `SENTINELKEY_DETECTION_FAILED_AUTH_WINDOW_SECONDS`
- `SENTINELKEY_DETECTION_ACCESS_DENIED_THRESHOLD`
- `SENTINELKEY_DETECTION_ACCESS_DENIED_WINDOW_SECONDS`

These rules evaluate submitted event signals. A suspicious-login or privilege-escalation event is an assertion supplied by the event source, not an independent identity-provider analysis.

The current implementation does not include machine-learning detection, live threat intelligence, or Wazuh, Suricata, or Zeek integration.

## Security Monitoring API

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/v1/security-events` | Ingest a validated event and evaluate detection rules |
| `GET` | `/api/v1/security-events` | List tenant events |
| `GET` | `/api/v1/security-events/summary?days=30` | Tenant event and alert summary |
| `GET` | `/api/v1/alerts` | List tenant alerts; optional status filter |
| `GET` | `/api/v1/alerts/{id}` | Retrieve a tenant alert |
| `PATCH` | `/api/v1/alerts/{id}` | Update alert status |

Alert statuses:

- `New`
- `Acknowledged`
- `Resolved`

All roles can read their tenant's events and alerts. Admins and analysts can update alert status. Cross-tenant alert access is denied.

---

# Vulnerability Management

The vulnerability management backend provides a tenant-scoped API for recording and tracking findings.

### Vulnerability API

| Method | Endpoint | Purpose | Authorization |
|---|---|---|---|
| `GET` | `/api/v1/vulnerabilities` | List findings with optional filters | Read |
| `POST` | `/api/v1/vulnerabilities` | Create a finding | Admin or analyst |
| `GET` | `/api/v1/vulnerabilities/{id}` | Retrieve a finding | Read |
| `PATCH` | `/api/v1/vulnerabilities/{id}` | Update finding fields or status | Admin or analyst |
| `GET` | `/api/v1/vulnerabilities/summary` | Tenant summary metrics | Read |

Available list filters:

- `severity`
- `status`
- `asset_id`
- `cve_id`

The data model includes:

- Asset association.
- Finding title and description.
- Optional CVE identifier.
- CVSS score.
- Severity.
- Status.
- Detection source.
- Remediation recommendation.
- Remediation due date.
- Creation and update timestamps.

CVSS scores must be finite and within the inclusive range of 0–10.

All reads and writes are scoped to the authenticated tenant. The API resolves the asset within that tenant and does not accept a vulnerability `tenant_id`.

Viewers can read but cannot create or update findings. Platform administrators have read access only for this module.

The API supports vulnerability entry and tracking, but no external vulnerability scanner, including Greenbone/OpenVAS, is integrated.

---

# Frontend

## Frontend Technology

The frontend is built with:

- React
- TypeScript
- Vite
- Tailwind CSS
- React Router
- Lucide icons
- Vitest

The application is located in `frontend/`.

## Current Frontend Features

### Authentication screen

The frontend provides a token-entry screen rather than a username/password login API.

A development JWT generated by the backend CLI can be pasted into the application.

Token handling:

- Token is held in browser memory.
- Token is attached to protected API requests.
- Token is cleared on sign out.
- Token is cleared on page reload.
- Unauthorized responses clear the current token.

The frontend does not use client-side role information as a replacement for backend authorization.

### Overview dashboard

The dashboard retrieves data from the backend and displays:

- Event metrics.
- Alert metrics.
- Vulnerability metrics.
- Event trends.
- Event distribution by source.
- Vulnerability severity distribution.
- Recent alerts and events.

Dashboard sections have independent loading and error states, with a refresh action.

### Security Events

The Events page provides the current frontend workflow for security-event management and ingestion.

It uses the existing security-event API and supports event inspection and submission.

### Alerts and Vulnerabilities

The backend APIs for these modules are implemented. Their frontend pages remain intentional placeholders and are not yet complete management interfaces.

---

## Run the Frontend

Start the backend first on `127.0.0.1:8000`.

Open a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

If PowerShell blocks `npm.ps1` because of its execution policy, invoke the Windows command shim directly:

```powershell
& "C:\Program Files\nodejs\npm.cmd" install
& "C:\Program Files\nodejs\npm.cmd" run dev
```

Open the Vite development URL shown in the terminal, normally:

`http://localhost:5173/`

Vite proxies `/api` requests to the local FastAPI backend.

---

# Testing and Quality Checks

## Backend tests

From the `backend` directory:

```powershell
.\venv\Scripts\python.exe -m pytest
```

## Frontend tests

From the `frontend` directory:

```powershell
& "C:\Program Files\nodejs\npm.cmd" test
```

## Frontend lint

```powershell
& "C:\Program Files\nodejs\npm.cmd" run lint
```

## Production build

```powershell
& "C:\Program Files\nodejs\npm.cmd" run build
```

### Last verified results

At the Day 3 frontend finalization:

- Backend tests: 90 passed.
- Frontend tests: 14 passed across 4 test files.
- Frontend lint: passed.
- Frontend production build: passed.
- Git diff whitespace check: passed.

These are the recorded results from that verification run, not a guarantee that future changes will continue to pass.

Live frontend/backend integration was not tested as part of that finalization.

---

# Security and Development Notes

- Never commit `.env` files, JWT secrets, access tokens, private keys, or local database files.
- Use development authentication only for isolated local testing.
- Keep the backend signing secret consistent between token generation and API execution.
- Do not treat synthetic event data as verified real-world threat intelligence.
- Do not expose development credentials or tokens in logs, screenshots, or public repositories.
- All security testing should be performed in authorized, isolated lab environments.

---

## Project Roadmap

The broader SentinelKey vision includes further development in:

1. Expanded Zero-Trust identity and access management.
2. Network security and packet analysis.
3. External identity-provider integration.
4. Policy-as-code integration with OPA.
5. SIEM and network detection integrations.
6. Vulnerability scanner integration.
7. Cryptographic key management and PKI.
8. Incident response and digital forensics.
9. Governance, risk, and compliance workflows.
10. Expanded frontend management interfaces.

These are planned areas and should not be interpreted as completed integrations.

---

## Project Note

SentinelKey is an educational, credit-based group project created to strengthen practical technical skills in cybersecurity engineering. It is not affiliated with or endorsed by CompTIA.

All security testing is intended for authorized, isolated lab environments.

## Created By

- Anushka Sarkar — CSE, Cyber Security, Section BA
- Sangana Chamundeswari — CSE, Cyber Security, Section BA
