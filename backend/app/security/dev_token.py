import argparse
import sys

from fastapi import HTTPException
from pydantic import EmailStr, TypeAdapter, ValidationError
from sqlalchemy import select

from app.core.config import settings
from app.core.database import SessionLocal
from app.models.identity import Identity
from app.models.tenant import Tenant
from app.schemas.tenant import TenantCreate
from app.security.authentication import IdentityRole, issue_development_token


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create a local development identity and print its short-lived JWT."
    )
    parser.add_argument("--tenant-name", required=True)
    parser.add_argument("--tenant-slug", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument(
        "--role",
        choices=[role.value for role in IdentityRole],
        default=IdentityRole.PLATFORM_ADMIN.value,
    )
    args = parser.parse_args()

    if settings.auth_mode != "development" or settings.environment != "development":
        parser.error("This command is restricted to development authentication mode.")
    try:
        TenantCreate(name=args.tenant_name, slug=args.tenant_slug)
        email = TypeAdapter(EmailStr).validate_python(args.email)
        issue_development_token("configuration-check")
    except (HTTPException, RuntimeError, ValidationError, ValueError) as error:
        if isinstance(error, HTTPException):
            parser.error(str(error.detail))
        parser.error(str(error))

    with SessionLocal() as db:
        tenant = db.scalar(select(Tenant).where(Tenant.slug == args.tenant_slug))
        if tenant is None:
            tenant = Tenant(name=args.tenant_name, slug=args.tenant_slug)
            db.add(tenant)
            db.flush()
        elif tenant.name != args.tenant_name:
            parser.error("The existing tenant slug has a different name.")

        identity = db.scalar(
            select(Identity).where(
                Identity.tenant_id == tenant.id,
                Identity.email == args.email,
            )
        )
        if identity is None:
            identity = Identity(
                tenant_id=tenant.id,
                email=str(email),
                identity_type="human",
                status="active",
                role=args.role,
            )
            db.add(identity)
            db.commit()
            db.refresh(identity)
        elif identity.role != args.role or identity.status != "active":
            parser.error("The existing identity is inactive or has a different role.")

        token = issue_development_token(identity.id)

    sys.stdout.write(token + "\n")


if __name__ == "__main__":
    main()
