from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from functools import lru_cache

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models.identity import Identity
from app.models.tenant import Tenant


class IdentityRole(str, Enum):
    PLATFORM_ADMIN = "platform_admin"
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


@dataclass(frozen=True)
class AuthenticatedIdentity:
    identity_id: str
    tenant_id: str
    role: IdentityRole


bearer_scheme = HTTPBearer(auto_error=False)


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing bearer token",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _configured_dev_secret() -> str:
    if settings.environment != "development":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Development authentication is disabled outside development",
        )
    if settings.jwt_secret is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Development authentication is not configured",
        )
    secret = settings.jwt_secret.get_secret_value()
    if len(secret) < 32:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Development JWT secret must be at least 32 characters",
        )
    return secret


@lru_cache(maxsize=4)
def _jwks_client(url: str) -> jwt.PyJWKClient:
    return jwt.PyJWKClient(url)


def issue_development_token(
    identity_id: str,
    expires_in: timedelta = timedelta(minutes=15),
) -> str:
    if settings.auth_mode != "development":
        raise RuntimeError("Development tokens are available only in development auth mode")
    secret = _configured_dev_secret()
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": identity_id,
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "iat": now,
            "exp": now + expires_in,
        },
        secret,
        algorithm="HS256",
    )


def _decode_and_validate_token(token: str) -> dict[str, object]:
    if settings.auth_mode == "development":
        key = _configured_dev_secret()
        algorithms = ["HS256"]
    else:
        if not settings.oidc_jwks_url:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="OIDC authentication is not configured",
            )
        try:
            key = _jwks_client(settings.oidc_jwks_url).get_signing_key_from_jwt(token).key
        except PyJWKClientConnectionError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="OIDC signing keys are unavailable",
            ) from None
        except PyJWKClientError:
            raise _unauthorized() from None
        algorithms = ["RS256"]

    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=algorithms,
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.InvalidTokenError:
        raise _unauthorized() from None

    return claims


def get_current_identity(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> AuthenticatedIdentity:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _unauthorized()

    claims = _decode_and_validate_token(credentials.credentials)
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise _unauthorized()
    if settings.auth_mode == "development":
        identity = db.get(Identity, subject)
    else:
        issuer = claims.get("iss")
        if not isinstance(issuer, str):
            raise _unauthorized()
        identity = db.scalar(
            select(Identity).where(
                Identity.external_issuer == issuer,
                Identity.external_subject == subject,
            )
        )

    if (
        identity is None
        or identity.status != "active"
        or identity.identity_type != "human"
        or db.get(Tenant, identity.tenant_id) is None
    ):
        raise _unauthorized()

    try:
        role = IdentityRole(identity.role)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Identity role is invalid",
        ) from None

    return AuthenticatedIdentity(
        identity_id=identity.id,
        tenant_id=identity.tenant_id,
        role=role,
    )


