# Trusted MFA fixture service

This opt-in Linux service validates one provisioned synthetic encrypted factor.
Its result is diagnostic and cannot authorize an Auth operation. Do not mount
the current Auth keyring here. Use distinct synthetic keys. The existing API
and worker configuration is unchanged. SEC-MFA-01 remains open.

Build the two images using the commands in the IPC workflow. Prepare a
socket directory owned by UID 10002 and shared with the client through
GID 10002 (mode 0750). The client uses UID 10001, joins GID 10002 and mounts
only the socket directory. The socket is mode 0660 and the service checks
peer UID even when another process can reach the socket. Keep the private
directory outside client mounts. Its three files must be regular files
owned by UID 10002 with mode 0600. The database password file is validated
at startup as preparation for future provisioning. There is no database
connection or active database role in this slice.

Start the isolated overlay with the two directory environment variables
declared in its Compose file. Health uses a newline-terminated JSON
request with operation health and empty arguments from the allowed UID.
For reproduction use the dedicated Linux workflow, which generates all
fixtures in a temporary directory and launches separate Linux processes.

A graceful stop removes the socket. After an unclean stop, an operator
must verify the process is gone before removing a stale socket. This
fixture transport has no replay ledger and must remain disconnected
from user-facing Auth. Trusted SQL authorization, proofs and atomic
cutover belong to later stages.

## PostgreSQL stage (0022)

The disabled-by-default veriq_mfa_trusted login may execute only the staged
factor-disable attestation and consumption entry points. The session-store
role owns both routines. It checks the live session, factor identity,
account-wide disable policy, credential version and recovery authority
revision. The 30-second attestation is single-use. Consumption, factor
deletion, session revocation and audit commit together.

Only the trusted process may attest after independently verifying TOTP.
PostgreSQL does not verify TOTP in this slice. Do not provision this login
outside isolated tests until that process and its authorization are wired.
Enrollment and recovery are deliberately outside these entry points.
Cutover requires wiring those paths, then revoking legacy grants and
removing the legacy keyring mount in the same maintenance transition.
The legacy path still works, so SEC-MFA-01 remains open.

PostgreSQL does not validate TOTP. The right to call attest is reserved
for the trusted process after it independently verifies the cryptographic
proof. Keep the login disabled outside disposable tests until integration
and atomic legacy cutover. The current IPC fixture does not call SQL.

## PostgreSQL-backed verification (0023)

For isolated integration, set VERIQ_TRUSTED_DB_HOST and
VERIQ_TRUSTED_DB_NAME and provision a dedicated password for
veriq_mfa_trusted through the database administrator. Keep the password
file and keyring readable only by the service UID. The existing
network-disabled fixture Compose file remains for the synthetic IPC test.
A database-backed deployment requires a private database network and no
published ports.

The attest_disable IPC operation accepts the account, factor, session,
organization, raw session token and TOTP. The service resolves the token
digest, reads only a session-bound factor through a database function and
decrypts it locally. PostgreSQL compares and advances the replay counter
and issues the factor-disable attestation in one transaction. The service
returns only the attestation ID. Database errors fail the operation and
do not switch to the fixture handler.

The SQL login remains trusted to submit a verified counter. The existing
0022 entry points remain available to that login for the staged SQL suite.
Legacy Auth still runs separately and must be cut over before claiming
SEC-MFA-01 closed.
