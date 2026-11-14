# SEC-MFA-01 cutover

Stage 4 is an isolated test slice. Public Auth remains NOT READY.

| Path | Current entry point and boundary | Target |
|---|---|---|
| Initial enrollment | `veriq.mfa_admin` calls `Mfa.prepare_enrollment` using the verifier role and keyring. It writes pending factors directly. | Trusted enrollment after an independently authorized operator decision |
| Login challenge | `/auth/login`, `Mfa.begin_login` and `veriq_mfa_primary` validate the primary proof and write a challenge under the verifier role. | API initiates and trusted service verifies |
| Factor confirmation and login | `/auth/mfa/challenge`, `Mfa.finish` and `_consume_factor` read and update factors, use the keyring, consume the challenge and audit. | Trusted cryptographic verification and narrow SQL consumption |
| Step-up and freshness | `/auth/mfa/step-up`, `Mfa.begin_step_up`, `finish` and `require_fresh` bind assurance to session and purpose. The verifier writes assurance and checks it via `veriq_mfa_fresh`. | Trusted proof issuance and PostgreSQL authorization |
| Backup codes | `Mfa._activate` inserts codes and `_consume_factor` atomically marks one used under the verifier role. | Trusted verification and narrow SQL consumption |
| Disable | `/auth/mfa/disable`, `Mfa.disable` checks session, freshness and policy, deletes factors under the verifier role, revokes sessions and audits. | Trusted TOTP verification and atomic SQL disable |
| Password reset and session revocation | `/auth/password-reset/request` and `/auth/password-reset/confirm` use `PasswordRecovery`. Reset revokes sessions and leaves MFA factors intact. | Preserve separation |
| Independent recovery | `/auth/mfa/recovery` and case action, enrollment and complete routes use `MfaRecovery` and narrow `veriq_recovery_*` functions. Recovery enrollment and completion require the keyring and approved case. | Separate review of operator authorization, verification and completion |
| Keyring | `main.py` loads the existing test Auth keyring. The isolated process loads its own private file. | Remove obsolete access at cutover and plan rotation separately |

The new internal adapter has no HTTP route. The service registers the disable command only with explicit test opt-in and a configured database. One transaction verifies the replay counter, records the proof, consumes it, deletes the factor, revokes sessions and writes audit. A timeout is a denial at the adapter, with unknown commit status if the response was lost. There is no legacy fallback.

## Trust and migration gates

- A compromised API process or permitted local IPC client could submit requests with live user data. UID checks authenticate processes. The service validates the session and TOTP and PostgreSQL rechecks authorization.
- The old verifier retains broad factor, challenge and assurance access until cutover. The test adapter does not remove that exposure.
- Trusted SQL credentials remain inside the trusted boundary. Compromise with valid session proof can bypass cryptographic verification via the SQL interface. Merely revoking direct attest is insufficient while another callable SQL operation can attest based on a caller-supplied counter.
- Keyring compromise threatens factor confidentiality. It is independently sensitive from trusted SQL credentials.

Before cutover, require a separate reviewed migration that enforces cryptographic authorization independent of SQL login possession, for example by verifying a short-lived scoped signature from an isolated signing key on every attestation entry point. Bind the signature to session, factor, account, organization, operation and counter. Preserve single use and transactionally check current state. Review enrollment and recovery separately. Prepare isolated credentials and run upgrade and rollback drills, stop legacy Auth writers, then apply the reviewed changes and revoke legacy grants together. Keep Public Auth disabled pending the production gate.
