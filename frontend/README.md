# SentinelKey Frontend

Phase 1 frontend foundation: React, TypeScript, Vite, Tailwind CSS, and React
Router. Overview, events, alerts, and vulnerability routes are navigation
placeholders; no security data is mocked.

## Development

Start the backend from `backend/` on `127.0.0.1:8000`, then run:

```powershell
npm install
npm run dev
```

The Vite development server proxies `/api` to FastAPI, so CORS configuration
is not required for this local setup.

## Authentication

SentinelKey does not provide an HTTP login endpoint. Generate a development
token from the backend using `python -m app.security.dev_token`, then paste it
into the token-entry form. The frontend validates it with the protected tenant
read endpoint and holds it in memory only. Reloading or signing out clears it.
The backend remains authoritative for authentication and authorization.

## Checks

```powershell
npm test
npm run build
```
