# AGENT_SPEC — Windows Veriq Agent

## Required outcomes
One install per shared Windows PC; students never log into agent. During exam, website user login pairs attempt temporarily with device, service applies exam policy, desktop indicates active capture, optional WebRTC live stream. Outside exam, status/management only, no screen collection.

## Components
- `Agent.Service` .NET10 Windows Service: device enrollment/identity, secure persistent outbound control connection, policy revisions/acks, heartbeat, update scheduling, restricted IPC to Desktop. Run least privileged account; avoid SYSTEM where not needed; guarded update helper elevated only when necessary.
- `Agent.Desktop` .NET10 WPF in interactive user session: explicit status, pairing activation, Windows Graphics Capture, encode/WebRTC, monitor configuration, avoid capture of privacy screens if OS API indicates restricted content.
- `Agent.Bridge` local loopback listener or protocol launcher, not admin; input one-time codes and local status only. Bridge has no endpoint to execute arbitrary commands.
- `Agent.Core` contracts, crypto, state transitions, validation, telemetry.

## Device lifecycle
`uninstalled → enrollment_requested → pending_admin_approval → ready → paired → monitoring → ready` and `suspended/revoked/offline/update_pending` overlays. Device identity belongs to tenant; regenerate on reinstallation or explicit key rotation; do not rely only on MAC/hostname (mutable, spoofable). Enroll one device manually or package many with quota/expiry and central approval. Enrollment secrets not embedded forever into public installer.

## Pairing protocol (proposed, validate in PoC)
1. Student authenticated browser begins assignment and receives attempt-scoped 60s pairing nonce (TTL configuration target, not fixed guarantee).
2. User presses “Connect Agent”; browser initiates permitted local loopback call or `veriq://pair?code=<opaque-noncredential-code>` after validating browser allowlist and LNA permissions. Never put login cookies/API access token in scheme URL.
3. Desktop/Service confirms which Windows session is active, signs challenge using approved device key and sends one-time code to FastAPI HTTPS.
4. API checks attempt, tenant, session status, device approval, code TTL/single-use, device currently free and policy; binds atomically.
5. Desktop displays “monitoring active” and connected exam ID/person; explicitly stops on server end, logout or failure. Server requires heartbeat + media state for required-monitoring preflight.
6. Replay, cross-tenant pairing and multiple active attempts on same device rejected.

## Supported events (metadata, no screenshot)
`agent.started`, `device.online/offline`, `pairing.started/succeeded/failed`, `desktop.missing`, `capture.started/stopped`, `stream.degraded`, `display.topology_changed`, `focus.changed`, `forbidden_app.observed`, `agent.version_changed`, `policy.applied`, `update.failed`, `control.command_ack`.
Avoid logging application window titles containing secrets; prefer generic process identifiers or approved allowlist IDs only. Whitelist-based window monitoring must be clearly declared.

## Profiles
- Basic: live screen (if required by policy), technical status and connection log.
- Standard: Basic + active window events, allowlist app policy, monitor topology.
- Strict: Standard + OS-managed restricted examination environment; detect non-compliance and fail safe, **do not promise ordinary WPF can block Task Manager, Alt+Tab, all other apps on unmanaged Windows**.
- Agent policy merge = platform ceilings + org rules + group/device specifics + exam selection, conflict => most restrictive mandatory control; versioned config hashed/signed, rollback. Teacher cannot loosen org policies.

## Commands
`config.refresh`, `diagnostics.collect_minimal`, `service.health_check`, `stream.adjust`, `session.stop`, `update.schedule`, `update.rollback`, `agent.restart_when_idle` only. Commands signed/validated and routed by back end with command id, TTL, scope. No generic execute/download URL/registry edits.

## Updates
Build signed Windows MSI candidate WiX; channels stable/beta/internal. Package integrity verified by publisher signature and trusted update feed manifest, staged pilot rollout, pause during exams, rollback if healthcheck failed; no self-update if device is exam busy except critical centrally approved maintenance with explicit instructor awareness. Compatible protocol capabilities; if agent too old, block required exam preflight with clear remediation.

## Media
Screen capture via Windows Graphics Capture in interactive desktop; hardware encoder if available, graceful software fallback with CPU budget. Multi-monitor policy decides capture scope; indicate active monitors and any unsupported case. WebRTC to SFU; 480p/720p/1080p adaptive max 2–30 FPS **configurable upper bounds**, test bandwidth/CPU. Viewers only through API-scoped media tokens.

## Windows-specific acceptance
- Windows 10/11 supported matrix must be verified; WGC capture permissions on actual OS/build.
- Session 0 service never attempts desktop capture; IPC ACL, UAC, Fast User Switching, lock/unlock, RDP, monitor unplug/hotplug, sleep/hibernate, restart, Windows Update.
- Running service while no student logged in does not capture anything; tray indicator consistent when capture active.
- Uninstall/reinstall does not silently rejoin a tenant as approved device.
