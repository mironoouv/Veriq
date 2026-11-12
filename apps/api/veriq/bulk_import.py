"""Invoke the scoped SQL import commands using the established session."""

import json
from dataclasses import asdict
from hashlib import sha256
from typing import cast
from uuid import UUID, uuid4

from sqlalchemy import Engine, text

from veriq.bulk_import_format import preview
from veriq.sessions import SessionPolicy, SessionToken
from veriq.tenant_access import AccessDenied


class BulkImport:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self.policy = SessionPolicy.from_environment()

    def upload(
        self,
        organization: UUID,
        token: SessionToken,
        payload: bytes,
        kind: str,
        column: str,
    ) -> dict[str, object]:
        rows = preview(payload, kind, column)
        digest = sha256(
            json.dumps([kind, column.strip().casefold()]).encode() + b"\x00" + payload
        ).digest()
        return self.command(
            organization,
            token,
            "preview",
            uuid4(),
            digest,
            json.dumps([asdict(row) for row in rows]),
        )

    def command(
        self,
        organization: UUID,
        token: SessionToken,
        action: str,
        batch: UUID,
        version: bytes | None = None,
        rows: str | None = None,
    ) -> dict[str, object]:
        gate = token._gate(self.policy)
        with self.engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL statement_timeout='5s'")
            connection.exec_driver_sql("SET LOCAL lock_timeout='2s'")
            result = connection.execute(
                text("""SELECT public.veriq_user_import(
                    :session,:digest,CAST(:limits AS interval[]),:org,:action,:batch,:version,CAST(:rows AS jsonb)
                )"""),
                {
                    "session": gate.session_id,
                    "digest": gate.digest,
                    "limits": list(gate.limits),
                    "org": organization,
                    "action": action,
                    "batch": batch,
                    "version": version,
                    "rows": rows,
                },
            ).scalar_one()
        if result is None:
            raise AccessDenied
        return cast(dict[str, object], result)
