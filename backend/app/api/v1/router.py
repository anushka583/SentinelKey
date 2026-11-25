from fastapi import APIRouter

from app.api.v1 import assets, audit_events, identities, security_events, system, tenants

api_router = APIRouter()
api_router.include_router(system.router)
api_router.include_router(tenants.router)
api_router.include_router(identities.router)
api_router.include_router(assets.router)
api_router.include_router(security_events.router)
api_router.include_router(audit_events.router)
