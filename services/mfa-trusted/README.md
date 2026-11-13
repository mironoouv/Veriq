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
