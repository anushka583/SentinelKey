import logging
from dataclasses import dataclass
from enum import Enum
from typing import Final

from fastapi import Depends, HTTPException, status

from app.security.authentication import (
    AuthenticatedIdentity,
    IdentityRole,
    get_current_identity,
)

logger = logging.getLogger(__name__)


class PolicyEvaluationError(Exception):
    """Raised when a policy decision cannot be evaluated safely."""


@dataclass(frozen=True)
class PolicyInput:
    identity_id: str | None
    role: str | None
    tenant_id: str | None
    action: str | None
    resource_type: str | None
    resource_tenant_id: str | None

    def to_opa_input(self) -> dict[str, object]:
        return {
            "subject": {
                "identity_id": self.identity_id,
                "role": self.role,
                "tenant_id": self.tenant_id,
            },
            "action": self.action,
            "resource": {
                "type": self.resource_type,
                "tenant_id": self.resource_tenant_id,
            },
        }


@dataclass(frozen=True)
class PolicyDecision:
    allow: bool
    reason: str
    policy_id: str | None = None

    def to_opa_output(self) -> dict[str, object]:
        return {
            "allow": self.allow,
            "reason": self.reason,
            "policy_id": self.policy_id,
        }


@dataclass(frozen=True)
class _PolicyRule:
    policy_id: str
    roles: frozenset[IdentityRole]


_ALL_ROLES: Final = frozenset(IdentityRole)
_ADMIN_ROLES: Final = frozenset(
    {IdentityRole.PLATFORM_ADMIN, IdentityRole.ADMIN}
)
_INGEST_ROLES: Final = frozenset(
    {IdentityRole.PLATFORM_ADMIN, IdentityRole.ADMIN, IdentityRole.ANALYST}
)
_VULNERABILITY_WRITE_ROLES: Final = frozenset(
    {IdentityRole.ADMIN, IdentityRole.ANALYST}
)
_SAFE_DENIAL_REASONS: Final = frozenset(
    {
        "missing_subject_context",
        "missing_role",
        "missing_action_or_resource",
        "unknown_role",
        "missing_policy",
        "role_not_allowed",
        "missing_resource_owner",
        "invalid_resource_owner",
        "cross_tenant_access",
    }
)
_RULES: Final[dict[tuple[str, str], _PolicyRule]] = {
    ("read", "tenant"): _PolicyRule("tenant-read-v1", _ALL_ROLES),
    ("read", "identity"): _PolicyRule("identity-read-v1", _ALL_ROLES),
    ("read", "asset"): _PolicyRule("asset-read-v1", _ALL_ROLES),
    ("read", "vulnerability"): _PolicyRule("vulnerability-read-v1", _ALL_ROLES),
    ("read", "security_event"): _PolicyRule("security-event-read-v1", _ALL_ROLES),
    ("read", "alert"): _PolicyRule("alert-read-v1", _ALL_ROLES),
    ("update", "alert"): _PolicyRule(
        "alert-update-v1", _VULNERABILITY_WRITE_ROLES
    ),
    ("read", "audit_event"): _PolicyRule("audit-event-read-v1", _ALL_ROLES),
    ("create", "tenant"): _PolicyRule(
        "tenant-create-v1", frozenset({IdentityRole.PLATFORM_ADMIN})
    ),
    ("manage", "identity"): _PolicyRule("identity-manage-v1", _ADMIN_ROLES),
    ("create", "vulnerability"): _PolicyRule(
        "vulnerability-create-v1", _VULNERABILITY_WRITE_ROLES
    ),
    ("update", "vulnerability"): _PolicyRule(
        "vulnerability-update-v1", _VULNERABILITY_WRITE_ROLES
    ),
    ("ingest", "security_event"): _PolicyRule(
        "security-event-ingest-v1", _INGEST_ROLES
    ),
}


def evaluate_policy(policy_input: PolicyInput) -> PolicyDecision:
    if not policy_input.identity_id or not policy_input.tenant_id:
        return PolicyDecision(False, "missing_subject_context")
    if not policy_input.role:
        return PolicyDecision(False, "missing_role")
    if not policy_input.action or not policy_input.resource_type:
        return PolicyDecision(False, "missing_action_or_resource")

    try:
        role = IdentityRole(policy_input.role)
    except ValueError:
        return PolicyDecision(False, "unknown_role")

    rule = _RULES.get((policy_input.action, policy_input.resource_type))
    if rule is None:
        return PolicyDecision(False, "missing_policy")
    if role not in rule.roles:
        return PolicyDecision(False, "role_not_allowed", rule.policy_id)

    is_tenant_creation = (
        policy_input.action == "create"
        and policy_input.resource_type == "tenant"
        and role == IdentityRole.PLATFORM_ADMIN
    )
    if is_tenant_creation:
        if policy_input.resource_tenant_id is not None:
            return PolicyDecision(False, "invalid_resource_owner", rule.policy_id)
    else:
        if not policy_input.resource_tenant_id:
            return PolicyDecision(False, "missing_resource_owner", rule.policy_id)
        if (
            policy_input.resource_tenant_id != policy_input.tenant_id
            and role != IdentityRole.PLATFORM_ADMIN
        ):
            return PolicyDecision(False, "cross_tenant_access", rule.policy_id)

    return PolicyDecision(True, "allowed", rule.policy_id)


def require_permission(
    action: str,
    resource_type: str,
    *,
    resource_tenant_from_identity: bool = True,
):
    def permission_dependency(
        identity: AuthenticatedIdentity = Depends(get_current_identity),
    ) -> AuthenticatedIdentity:
        decision_input = PolicyInput(
            identity_id=identity.identity_id,
            role=identity.role.value,
            tenant_id=identity.tenant_id,
            action=action,
            resource_type=resource_type,
            resource_tenant_id=(
                identity.tenant_id if resource_tenant_from_identity else None
            ),
        )
        try:
            decision = evaluate_policy(decision_input)
        # Authorization must fail closed if an evaluator raises unexpectedly.
        except Exception as error:
            logger.error(
                "Authorization policy evaluation failed (%s)",
                type(error).__name__,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden",
            ) from None

        if (
            not isinstance(decision, PolicyDecision)
            or not isinstance(decision.allow, bool)
            or not isinstance(decision.reason, str)
            or not isinstance(decision.policy_id, (str, type(None)))
        ):
            logger.error("Authorization policy returned an invalid decision")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden",
            )

        expected_rule = _RULES.get((action, resource_type))
        if decision.allow and (
            decision.reason != "allowed"
            or expected_rule is None
            or decision.policy_id != expected_rule.policy_id
        ):
            logger.error("Authorization policy returned an invalid allow decision")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden",
            )

        if not decision.allow:
            reason = (
                decision.reason
                if isinstance(decision.reason, str)
                and decision.reason in _SAFE_DENIAL_REASONS
                else "policy_denied"
            )
            logger.warning(
                "Authorization denied role=%s action=%s resource_type=%s reason=%s",
                identity.role.value,
                action,
                resource_type,
                reason,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden",
            )
        return identity

    return permission_dependency


class PolicyAction(str, Enum):
    READ = "read"
    CREATE = "create"
    UPDATE = "update"
    MANAGE = "manage"
    INGEST = "ingest"


class PolicyResource(str, Enum):
    TENANT = "tenant"
    IDENTITY = "identity"
    ASSET = "asset"
    VULNERABILITY = "vulnerability"
    SECURITY_EVENT = "security_event"
    ALERT = "alert"
    AUDIT_EVENT = "audit_event"
