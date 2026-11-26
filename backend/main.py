
from fastapi import FastAPI

from app.api.v1.router import api_router
from app.core.config import settings

app = FastAPI(
    title=settings.app_name,
    description=(
        "Unified Cybersecurity and Zero-Trust "
        "Security Platform"
    ),
    version=settings.app_version,
    debug=settings.debug,
)

app.include_router(api_router)


@app.get("/", tags=["System"])
async def root():
    return {
        "product": settings.app_name,
        "version": settings.app_version,
        "message": "Welcome to SentinelKey"
    }


@app.get("/health/live", tags=["Health"])
async def health_check():
    return {
        "status": "healthy",
        "service": "sentinelkey-api"
    }
