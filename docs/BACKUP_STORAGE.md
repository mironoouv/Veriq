# BACKUP_STORAGE — Veriq Storage & Backup Manager

## Decision
Increased reliability: Postgres WAL archiving, separated encrypted backups, regular restore drills. **Targets only:** RPO ≤5m, RTO ≤1h. Not guaranteed without tests + suitable external infrastructure. Candidate PostgreSQL tool `pgBackRest` (full/diff/incremental/retention/PITR).

## Backup strategy (candidate baseline)
Weekly full, daily differential, continuous WAL archival; at least 2 full recovery chains protected. External repository independent failure domain; object/files backup consistent with DB snapshots (manifest of object versions). Encrypt in transit/rest, rotate credentials, offline/immutable copy option. Backup retention with dependencies, restore to staging sandbox and verify logical integrity.

## Storage dashboard
Show actual production and backup storage targets separately: used/total/free, postgres data, WAL, backups, uploaded attachments, temporary files, logs, growth rate, last backup/restore validation, last WAL archived at, projected capacity and alerts. Percentages must use real metric source and timestamp; do not show successful badge if stale/unhealthy.

## Cleanup flow
`candidate_scan → dry_run estimate → dependency check (retention/legal holds/last chain) → admin step-up MFA → approval if destructive → queued cleanup job → recheck before delete → audited result`. Accept predefined categories only; no arbitrary path input, shell commands, removal of active WAL or current data. Prefer pgBackRest's expiration command, not raw unlink. Always re-evaluate because data may change after preview.

## Retention & deletion
Incidents auto-purged per organization; audit/results different retention, backup expiration across chain may lag until protected backup lifetimes expire. Deleted records in snapshots may remain until backup expiry; restoration runs post-restore erasure reconciliation. Document restoration of deleted data and legal holds.

## Disaster recovery exercises
- Loss of DB pod/container, backup media corrupt, accidental table delete (PITR), loss of primary storage, interrupted backup, restore to clean Linux host.
- Prove real RPO by comparing last committed LSN/event to recovered state; RTO measure incident start until end-to-end login + attempts + attachments work, not merely Postgres accepting connections.
- Document downtime exam policy: students get safe banner, local confirmed saves, teacher can issue new deadline/cancel; never silently prolong exam automatically after prolonged outage.

## Storage alert thresholds
Targets: information 70%, warning 85%, critical 95%, configurable per volume; capacity planner requires growth rate and free space for WAL during backups. No auto-deletion of protected recovery chain on high usage.

## Responsibilities
Backup manager uses minimal repository credentials; backup encryption keys stored out of repo and recoverable via authorized break-glass. Org Admin may view tenant usage and manage tenant-retention policy, but only platform infra admins can delete physical backup sets shared by tenants. Tenant-scoped UI must not expose backup metadata from other organizations.
