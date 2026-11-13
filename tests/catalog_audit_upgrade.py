"""Exercise the catalog service before and after the mandatory audit upgrade."""

import sys
from collections import Counter
from uuid import uuid4

from academic_catalog_checks import ADMIN, ORG, OTHER, OUTSIDER, role, seed
from sqlalchemy import text
from veriq.academic_catalog import (
    AcademicCatalog,
    CatalogArchive,
    CatalogEdit,
    CatalogInput,
    CatalogKind,
    CatalogRestore,
)
from veriq.auth_credentials import CredentialVerifier
from veriq.database import create_database_engine
from veriq.sessions import Sessions


def main() -> None:
    owner = create_database_engine()
    if sys.argv[1:] == ["seed"]:
        seed(owner)
    sessions = Sessions(role("veriq_api"), issuer=role("veriq_session_issuer"))
    verifier = CredentialVerifier(role("veriq_credential_verifier"))
    catalog = AcademicCatalog(sessions)
    for org, user in ((ORG, ADMIN), (OTHER, OUTSIDER)):
        actor = sessions.issue(
            verifier.confirm(user, 1, mfa_level=1, organization_id=org)
        )
        for kind in CatalogKind:
            item = uuid4()
            for command, action, status, version in (
                (CatalogInput(title="Migration fixture"), "create", "active", 1),
                (CatalogEdit(title="Edited fixture", version=1), "edit", "active", 2),
                (CatalogArchive(version=2), "archive", "archived", 3),
                (CatalogRestore(version=3), "restore", "active", 4),
            ):
                request = uuid4()
                result = catalog.write(actor, org, kind, item, command, request)
                assert (result.id, result.status, result.version) == (
                    item,
                    status,
                    version,
                )
                with owner.connect() as db:
                    events = db.execute(
                        text("""
                            SELECT action FROM academic_catalog_events
                            WHERE request_id=:request AND actor_id=:user AND organization_id=:org
                              AND coalesce(course_id,group_id)=:item
                        """),
                        {"request": request, "user": user, "org": org, "item": item},
                    ).scalars()
                    assert Counter(events) == {action: 1}
    print(
        "Catalog lifecycle: four objects across two tenants, 16 events, one per operation"
    )


if __name__ == "__main__":
    main()
