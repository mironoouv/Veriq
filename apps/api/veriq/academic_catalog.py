"""Catalog commands using the existing tenant session and RLS."""

import json
from datetime import datetime
from enum import StrEnum
from hashlib import sha256
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import text

from veriq.sessions import Sessions, SessionToken
from veriq.tenant_access import AccessDenied, ResourcePolicy, TenantResource


class CatalogKind(StrEnum):
    COURSES = "courses"
    GROUPS = "study_groups"


class CatalogConflict(RuntimeError):
    """The request no longer matches the catalog revision."""


class CatalogInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=2000)

    @field_validator("title", mode="before")
    @classmethod
    def trim_title(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value


class CatalogEdit(CatalogInput):
    version: int = Field(strict=True, ge=1, le=2147483647)


class CatalogArchive(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: int = Field(strict=True, ge=1, le=2147483647)


class CatalogRestore(CatalogArchive):
    pass


class CatalogRow(BaseModel):
    id: UUID
    title: str
    description: str | None
    status: str
    version: int
    created_at: datetime
    updated_at: datetime


class CatalogPage(BaseModel):
    items: list[CatalogRow]
    total: int
    can_restore: bool = False


_FIELDS = "id,title,description,status,version,created_at,updated_at"


class AcademicCatalog:
    def __init__(self, sessions: Sessions) -> None:
        self.sessions = sessions

    def read(
        self,
        token: SessionToken,
        org: UUID,
        kind: CatalogKind,
        item: UUID | None,
        archived: bool,
        query: str,
        page: int,
    ) -> CatalogRow | CatalogPage:
        with self.sessions.tenant(token) as access:
            resource = TenantResource(org)
            access.require(ResourcePolicy("academic.catalog.read"), resource)
            if archived:
                access.require(ResourcePolicy("academic.catalog.archive"), resource)
            connection = access.connection
            if item is not None:
                row = (
                    connection.execute(
                        text(f"""
                    SELECT {_FIELDS} FROM public.{kind.value}
                    WHERE organization_id=:org AND id=:item
                """),
                        {"org": org, "item": item},
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is None:
                    raise AccessDenied
                return CatalogRow.model_validate(dict(row))
            where = "organization_id=:org AND status=:status AND strpos(lower(title),lower(:query))>0"
            params = {
                "org": org,
                "status": "archived" if archived else "active",
                "query": query,
                "offset": (page - 1) * 20,
            }
            count = connection.execute(
                text(f"SELECT count(*) FROM public.{kind.value} WHERE {where}"), params
            ).scalar_one()
            rows = connection.execute(
                text(f"""
                SELECT {_FIELDS} FROM public.{kind.value} WHERE {where}
                ORDER BY title,id LIMIT 20 OFFSET :offset
            """),
                params,
            ).mappings()
            return CatalogPage(
                items=[CatalogRow.model_validate(dict(row)) for row in rows],
                total=count,
                can_restore=archived
                and bool(
                    connection.execute(
                        text(
                            "SELECT public.veriq_catalog_permission(:org,'academic.catalog.manage')"
                        ),
                        {"org": org},
                    ).scalar_one()
                ),
            )

    def write(
        self,
        token: SessionToken,
        org: UUID,
        kind: CatalogKind,
        item: UUID,
        data: CatalogInput | CatalogEdit | CatalogArchive,
        request_id: UUID,
    ) -> CatalogRow:
        with self.sessions.tenant(token, lock_authority=True) as access:
            resource = TenantResource(org)
            access.require(ResourcePolicy("academic.catalog.read"), resource)
            access.require(ResourcePolicy("academic.catalog.manage"), resource)
            connection = access.connection
            gate = access.session_gate
            if gate is None:
                raise AccessDenied
            connection.execute(
                text("""
                    SELECT set_config('veriq.catalog_session_id',:session,true),
                           set_config('veriq.catalog_session_digest',:digest,true),
                           set_config('veriq.catalog_request_id',:request,true)
                """),
                {
                    "session": str(gate.session_id),
                    "digest": gate.digest.hex(),
                    "request": str(request_id),
                },
            )
            params: dict[str, object] = {"org": org, "item": item}
            if isinstance(data, CatalogArchive):
                restoring = isinstance(data, CatalogRestore)
                action = "restore" if restoring else "archive"
                access.require(ResourcePolicy("academic.catalog.archive"), resource)
                params.update(
                    version=data.version,
                    source="archived" if restoring else "active",
                    destination="active" if restoring else "archived",
                )
                row = (
                    connection.execute(
                        text(f"""
                    UPDATE public.{kind.value} SET status=:destination,version=version+1,updated_at=clock_timestamp()
                    WHERE organization_id=:org AND id=:item AND status=:source AND version=:version RETURNING {_FIELDS}
                """),
                        params,
                    )
                    .mappings()
                    .one_or_none()
                )
            elif isinstance(data, CatalogEdit):
                action = "edit"
                params.update(
                    title=data.title, description=data.description, version=data.version
                )
                row = (
                    connection.execute(
                        text(f"""
                    UPDATE public.{kind.value} SET title=:title,description=:description,version=version+1,
                        updated_at=clock_timestamp()
                    WHERE organization_id=:org AND id=:item AND status='active' AND version=:version RETURNING {_FIELDS}
                """),
                        params,
                    )
                    .mappings()
                    .one_or_none()
                )
            else:
                action = "create"
                digest = sha256(
                    json.dumps([data.title, data.description]).encode()
                ).digest()
                params.update(
                    title=data.title, description=data.description, digest=digest
                )
                row = (
                    connection.execute(
                        text(f"""
                    INSERT INTO public.{kind.value}(organization_id,id,title,description,create_digest)
                    VALUES (:org,:item,:title,:description,:digest) ON CONFLICT DO NOTHING RETURNING {_FIELDS}
                """),
                        params,
                    )
                    .mappings()
                    .one_or_none()
                )
            if row is None:
                existing = (
                    connection.execute(
                        text(f"""
                    SELECT {_FIELDS},create_digest FROM public.{kind.value}
                    WHERE organization_id=:org AND id=:item
                """),
                        params,
                    )
                    .mappings()
                    .one_or_none()
                )
                if existing is None:
                    raise AccessDenied
                if (action == "archive" and existing["status"] == "archived") or (
                    action == "create" and existing["create_digest"] == params["digest"]
                ):
                    return CatalogRow.model_validate(dict(existing))
                raise CatalogConflict
            return CatalogRow.model_validate(dict(row))
