"""Internal identity models. Schema changes are managed by Alembic."""

from datetime import datetime
from enum import StrEnum
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, declared_attr, mapped_column


class IdentityBase(DeclarativeBase):
    pass


class Organization(IdentityBase):
    __tablename__ = "organizations"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(unique=True)
    display_name: Mapped[str]
    timezone: Mapped[str]
    status: Mapped[str]
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class User(IdentityBase):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    email_normalized: Mapped[str] = mapped_column(unique=True)
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    password_hash: Mapped[str]
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class MembershipStatus(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class OrganizationMembership(IdentityBase):
    __tablename__ = "organization_memberships"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "user_id", name="uq_memberships_organization_user"
        ),
        UniqueConstraint(
            "organization_id", "id", name="uq_memberships_organization_id"
        ),
        Index("ix_memberships_user_id", "user_id"),
        CheckConstraint("version > 0", name="ck_memberships_version"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "organizations.id", name="fk_memberships_organization", ondelete="RESTRICT"
        )
    )
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", name="fk_memberships_user", ondelete="RESTRICT")
    )
    status: Mapped[MembershipStatus] = mapped_column(
        Enum(
            MembershipStatus,
            values_callable=lambda statuses: [status.value for status in statuses],
            name="ck_memberships_status",
            native_enum=False,
            create_constraint=True,
            validate_strings=True,
            length=9,
        ),
        server_default=MembershipStatus.PENDING.value,
    )
    joined_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    version: Mapped[int] = mapped_column(server_default=text("1"))

    @declared_attr.directive
    def __mapper_args__(cls) -> dict[str, object]:
        return {"version_id_col": cls.version}

    @property
    def is_active(self) -> bool:
        return self.status == MembershipStatus.ACTIVE
