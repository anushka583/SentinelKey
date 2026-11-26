from collections.abc import Generator
from pathlib import Path
import secrets
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from pydantic import SecretStr

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.core.database import get_db  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.models import Base  # noqa: E402
from app.models.identity import Identity  # noqa: E402
from app.models.tenant import Tenant  # noqa: E402
from app.security.authentication import issue_development_token  # noqa: E402
from main import app  # noqa: E402

TEST_JWT_SECRET = secrets.token_urlsafe(48)


@pytest.fixture(autouse=True)
def development_auth_settings(monkeypatch):
    monkeypatch.setattr(settings, "environment", "development")
    monkeypatch.setattr(settings, "auth_mode", "development")
    monkeypatch.setattr(settings, "jwt_issuer", "sentinelkey-test")
    monkeypatch.setattr(settings, "jwt_audience", "sentinelkey-test-api")
    monkeypatch.setattr(settings, "jwt_secret", SecretStr(TEST_JWT_SECRET))


@pytest.fixture()
def db_engine():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    try:
        yield engine
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


@pytest.fixture()
def db_session(db_engine) -> Generator[Session, None, None]:
    TestingSessionLocal = sessionmaker(bind=db_engine, autocommit=False, autoflush=False)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def create_tenant(db_session: Session):
    next_tenant = 0

    def factory(slug: str | None = None, name: str | None = None) -> Tenant:
        nonlocal next_tenant
        next_tenant += 1
        tenant = Tenant(
            name=name or f"Test Tenant {next_tenant}",
            slug=slug or f"test-tenant-{next_tenant}",
        )
        db_session.add(tenant)
        db_session.commit()
        db_session.refresh(tenant)
        return tenant

    return factory


@pytest.fixture()
def create_identity(db_session: Session, create_tenant):
    next_identity = 0

    def factory(
        *,
        tenant: Tenant | None = None,
        role: str = "viewer",
        email: str | None = None,
        status: str = "active",
    ) -> Identity:
        nonlocal next_identity
        next_identity += 1
        identity = Identity(
            tenant_id=(tenant or create_tenant()).id,
            email=email or f"user-{next_identity}@example.com",
            identity_type="human",
            status=status,
            role=role,
        )
        db_session.add(identity)
        db_session.commit()
        db_session.refresh(identity)
        return identity

    return factory


@pytest.fixture()
def auth_headers():
    def factory(identity: Identity, expires_in=None) -> dict[str, str]:
        if expires_in is None:
            token = issue_development_token(identity.id)
        else:
            token = issue_development_token(identity.id, expires_in=expires_in)
        return {"Authorization": f"Bearer {token}"}

    return factory


@pytest.fixture()
def client(db_session: Session) -> Generator[TestClient, None, None]:
    def override_get_db() -> Generator[Session, None, None]:
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()