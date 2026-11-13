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

## Registration and password recovery contract

The exact signatures and expected callers are recorded in
tests/auth_recovery_acl.py. Signup and mail-outbox routines are owned by
veriq_signup_store. The password routines are owned by veriq_session_store.
The entry points are SECURITY DEFINER. The internal password-apply helper
is SECURITY INVOKER. All use pg_catalog, pg_temp and have no PUBLIC EXECUTE. API handles signup and reset, the password
verifier handles session-bound password change, and worker handles outbox
delivery and notices. The internal password-apply routine has no runtime
caller. CI checks the same allowlist on clean and upgraded PostgreSQL 17.11
databases. Proofs in these flows are bound to a global account, not to a
caller-provided tenant. The SQL lifecycle checks rejection of a mismatched
email, expiry, replay and stale credential versions.

## MFA and independent recovery contract

The signature inventory and exact runtime EXECUTE allowlists are in
tests/auth_mfa_acl.py. All listed routines are owned by veriq_session_store
with pg_catalog, pg_temp as search_path and no PUBLIC EXECUTE. Internal
session policy and recovery authorization helpers include invoker functions.
MFA verifier uses SQL functions plus direct factor table access for
application-level verification and enrollment. Its DB credential is
therefore part of the trusted MFA boundary. This matrix does not establish
row-level isolation for a compromised MFA verifier. The recovery authority
trigger and key rotation are outside the new call matrix. Existing
Foundation integration tests cover application enrollment, replay, session
policy and recovery transitions.

## Session management contract

tests/auth_session_acl.py checks five session-management signatures on both
PostgreSQL databases. All are SECURITY DEFINER, owned by veriq_session_store,
with pg_catalog, pg_temp search_path and no PUBLIC EXECUTE.
API may call session use, current, browser rotation and audited revocation.
MFA verifier may also call session use and the catalog auditor may check
session current. The raw revoke helper has no runtime caller.
Refresh rotates the existing session credential. Revoke-all includes the
current session, and there is no keep-current variant in this contract.
