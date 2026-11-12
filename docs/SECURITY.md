# SECURITY — Veriq Security Design

## Identity
- Argon2id calibrated, password breach blocking, email verification, brute-force IP/account rate limits, privacy-preserving auth error messages.
- MFA mandatory for Superadmin, Org Admin, Technician; optional/policy mandatory for Teacher/Proctor/Student. Highest required assurance applies to users with multiple roles.
- TOTP + single-use recovery codes; WebAuthn/passkeys recommended after PoC. Encrypt TOTP seed at rest with managed key; recovery codes store salted one-way hash only.
- Recovery: codes OR independently verified recovery, audit, cooldown, separate approver for privileged roles; **no self-approval**. Revoke relevant sessions and factor enrollments; strong step-up on sensitive operations.
- Browser sessions: secure/httpOnly/sameSite cookies, CSRF, rotation, idle+absolute TTL, revoke all, list active devices, multi-tab attempt lease independent of login session.

## Tenant isolation
- Membership required, scope never derived from arbitrary client-provided org; choose tenant after server membership verification.
- Authorization: permission + org + resource relationship + action-specific policy, server side. Superadmin has infrastructure management, not silent universal answer/screen access; exceptional break-glass audited, time limited, approved where possible.
- Deny by default; RLS/tenant composite FK; automated cross-tenant IDOR tests for all CRUD/websocket/media endpoints, including attachments.
- Slice B stores platform and organization grants separately. A Superadmin assignment alone yields no organization permissions. Internal grant readers check live membership state and expect an already verified subject. Resource authorization remains a separate check. Slice B exposes no public or user-context role writer. A future writer must reject self-elevation and verify the actor, target, scope, step-up and audit before exposure.

## Agent security
- Agent service has device identity; initial deployment token limited to org, TTL and quota, admin approval. Key generated per device; protect at rest (Windows machine key store/DPAPI) and pin server trust with ordinary certificate validation, no bypass TLS.
- C# desktop in user session, service in Session 0, restricted named pipe ACL. Stop capture on logout/end. No keylogging, covert capture, arbitrary remote code execution, personal file scraping.
- Local browser bridge only loopback; check Origin exact allowlist and Host; restrict CORS; nonce + short-lived grant, anti-replay; no elevated local HTTP handler; rate limit. Test Chrome LNA permissions and custom protocol activation in supported Edge/Chrome.
- Command allowlist and schema validation, TTL, admin scope, agent-side validation, audit; no PowerShell shell command injection. Signed updates and rollback.

## Media / privacy
- Capture only on exam approved session with visible indicator, information notice to students; live-only media, no recording, archive, screenshots, snapshots or logs storing frames. Media access requires tenant-scoped authorization and explicit active exam; tokens expire quickly and are revoked on completion.
- Audit viewer join/leave. Monitor operator with screen capture software cannot technically be prevented from external recording: organizational policy/training required.
- Protect incidental personal data visible on screen; transparency, least privilege, access logs and retention. Legal basis/notice and student/employee privacy requirements require jurisdiction-specific counsel before production.

## Judge security
- Untrusted code must never run inside API or same trust domain as prod secret stores, DB, Docker socket. Dedicated isolated host/VM/sandbox with no external network, no privileged mode, CPU/memory/process/time/IO/output restrictions, immutable test fixture, distinct SQL instance. Test hostile workloads.

## Audit
- Append-only account/grade/org/device/command/media/approval logs; no secrets or video frames. Partitioned retention with non-modifiable integrity digest or external WORM stream. Distinguish failed access and successful actions.
- Alerts for privilege elevation, mass data export, recovery, backup deletion, many device enrollment attempts; operations that mutate a user's role or audit config require step-up and approvals.
- Separate TTL for incidents, audit, student results. Retention policy changes logged and future/enforced purge jobs; delete from backups per documented lifecycle, no resurrection without re-running purge.

## Threat scenarios & mitigations
| Threat | Main control | Test |
|---|---|---|
| Student modifies JS timer | server deadline | skew clock 1 day |
| Two attempts concurrently | transactional uniqueness | parallel 50 starts |
| Other organization ID access | tenant scope/RLS | swap UUIDs |
| Forged agent on localhost | one-time grant + device proof | replay/evil origin |
| Stolen proctor media token | narrow scope/TTL/active revoke | revoke while watching |
| Hidden grader tests exposed | store only server-side | browser network inspection |
| SQL jailbreak from answer | ephemeral DB/low privileges | DDL/DML/connect escape |
| Sandbox mining/fork bomb | strong isolation/cgroups/timeouts | malicious test corpus |
| Backup deletion impacts PITR | chain dependency guard | deny last backup/WAL deletion |
| MFA admin recovery abuse | approval step-up/audit | self-request and self-approve |

## Security gate
Threat model + SAST/DAST/dependency and image scan, secret scan, pentest scope, preprod restores, kill-session revocation, unauthorized monitor access checks, tested telemetry sanitization. Any unresolved critical risk blocks production.
