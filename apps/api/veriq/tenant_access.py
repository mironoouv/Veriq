"""Internal tenant authorization for a server-verified subject."""

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import Connection, Engine, text

from veriq.permissions import organization_permission_codes


class AccessDenied(PermissionError):
    """A tenant access policy did not grant access."""


@dataclass(frozen=True)
class VerifiedSubject:
    """Constructed by the trusted authentication boundary, never from request fields."""

    user_id: UUID


@dataclass(frozen=True)
class TenantResource:
    """Attributes loaded by a trusted resource repository."""

    organization_id: UUID
    owner_user_id: UUID | None = None


@dataclass(frozen=True)
class ResourcePolicy:
    permission_code: str
    owner_only: bool = False


@dataclass(frozen=True)
class TenantAccess:
    connection: Connection
    subject: VerifiedSubject
    organization_id: UUID

    def require(self, policy: ResourcePolicy, resource: TenantResource | None) -> None:
        if resource is None or resource.organization_id != self.organization_id:
            raise AccessDenied
        if policy.owner_only and resource.owner_user_id != self.subject.user_id:
            raise AccessDenied
        grants = organization_permission_codes(
            self.connection,
            organization_id=self.organization_id,
            user_id=self.subject.user_id,
        )
        if not policy.permission_code or policy.permission_code not in grants:
            raise AccessDenied


@contextmanager
def tenant_transaction(
    engine: Engine, *, subject: VerifiedSubject | None, requested_organization_id: UUID
) -> Iterator[TenantAccess]:
    if subject is None:
        raise AccessDenied
    with engine.begin() as connection:
        identity = {
            "tenant": requested_organization_id,
            "subject": str(subject.user_id),
        }
        if not connection.execute(
            text("SELECT public.veriq_active_membership(:tenant, :subject)"), identity
        ).scalar_one():
            raise AccessDenied
        connection.execute(
            text("""
                SELECT set_config('veriq.organization_id', :tenant, true),
                       set_config('veriq.user_id', :subject, true)
            """),
            {"tenant": str(requested_organization_id), "subject": str(subject.user_id)},
        )
        yield TenantAccess(connection, subject, requested_organization_id)
