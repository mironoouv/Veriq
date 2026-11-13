# PostgreSQL 17.11 audit checks

The dedicated Linux workflow provisions temporary databases with the
repository migration entry point. It checks the catalog against effective
function grants and compares the clean and upgraded schemas' ACLs. The
upgrade path seeds synthetic tenant data and issues a session at 0015,
then runs the catalog integration suite at head. Runtime denial probes
connect as the provisioned API and worker logins.

Run the PostgreSQL security audit workflow on the branch to reproduce.
Foundation CI covers the existing HTTPS, session, tenant and worker suites
separately. The additional role probes cover representative forbidden
operations. A passing run does not certify each function body or exclude
authorization defects in every call path.

## Auth verifier and issuer contract

The CI inventory in tests/auth_issuer_acl.py records exact signatures.
Every listed routine is SECURITY DEFINER, owned by veriq_session_store,
uses search_path pg_catalog, pg_temp, and excludes PUBLIC EXECUTE.
Apart from the owner and superusers, the allowed callers are:

| Function | Callers | Use |
|---|---|---|
| veriq_auth_confirm | veriq_credential_verifier | Trusted credential proof |
| veriq_auth_issue | veriq_session_issuer, veriq_mfa_verifier | Proof consumption and issuance |
| veriq_password_candidate | veriq_password_verifier | Browser password lookup |
| veriq_password_confirm | veriq_password_verifier | Confirm password verification |
| veriq_browser_issue | veriq_browser_issuer | Browser session issuance |
| veriq_session_issue | None | Internal session-store helper |
| veriq_mfa_confirm | veriq_mfa_verifier | Create MFA proof after factor verification |

API, worker and browser/MFA roles use provisioned test logins. Legacy
NOLOGIN verifier and issuer roles are exercised through transaction-local
SET ROLE. Raw SQL proof rejection creates no session or success event.
The HTTP adapter owns attempt auditing. Registration, recovery, MFA
administration, session rotation and other definer families remain outside
this matrix.
