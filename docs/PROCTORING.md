# PROCTORING & MONITOR — политика и спецификация

## Approved policy
No video recording, screenshots, frame archive, time-shift buffer persisted to disk, media egress recording. Only live viewing by authorized staff during active attempt. System logs metadata and incidents, not screen contents. Explain monitoring to student before starting.

## Configurable profiles
`basic`, `standard`, `strict`; teacher selects profile and limited overrides within organization policy. Organization may disable particular capability. Per-exam `agent_requirement = disabled|required` independent of profile availability; if disabled, no desktop capture.

## Event → reaction
Event policy maps `event_type → threshold/window → severity → actions`: `log`, `student_warning`, `teacher_notification`, `technical_pause` (for objectively verified technical prerequisites). Ambiguous events are reviewed by human; no auto grade penalty or automatic accusation. Repeated focus changes may have configurable threshold/debounce.

## Live Monitor UI
List or tile views, filter class/exam/status/incident, selected high-quality stream, active viewers, student progress, time remaining, agent connectivity and last heartbeat, timeline incidents, teacher actions pause/resume/extend/force-submit (step-up for destructive operations). If video unavailable, show explicit reason and fallback text status; never silently show outdated thumbnail as live.

## Media authorization
- Room/track organization/exam/attempt binding, minimal subscribe-only viewer token.
- viewer authorization checked on every join + revoke listener on role/assignment/session changes; closing session disconnects users from SFU, not merely JWT expiry.
- Media infrastructure must not enable recording/egress bots; client code no canvas screenshots, download frame feature or DVR. External OS screen recording not technically preventable: compliance policy.

## Incident record
Fields: `org_id, attempt_id, device_id, event_id, event_type, severity, occurred_at_client(optional_untrusted), received_at_server, metadata_allowlisted, policy_revision, status, reviewer_id, decision_note, purge_after`. Deduplicate event IDs; order by server receipt and display uncertainty in client-reported occurrence. Incident resolution `technical`, `confirmed_rule_violation`, `insufficient_evidence`; status `new/reviewing/closed`. Audit all reviews.

## Retention
Organization has incident retention configuration and automatic purge. Policy for audit is separate; do not retain full screen or window titles in incident metadata. Cleanup worker executes with policy, shows purge results, obeys documented holds only when authorized, separately handles backup reappearance.

## User notices
Show preflight disclosure: monitored data categories, viewers, beginning/end, no video retention, troubleshooting and appeal/contact. Badge in agent and web while capture active; if consent/legal requirements apply, enrollment and processing must comply, not assume checkbox alone gives valid legal basis.

## PoC exit criteria
Windows capture publisher to self-hosted SFU; 30 agents with 6-cell previews, full-screen switching, 2 observers, screen stop on finish, immediate revoke, network drops/reconnect, no persisted frames, realistic 1080p CPU/bandwidth measurement, TURN fallback tested.
