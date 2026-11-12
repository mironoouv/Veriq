# ROADMAP — план релизов по этапам

| Этап | Цель | Exit gate |
|---|---|---|
| 0 Design Freeze | ADR, UI flows, threat model, infra PoC plan | owners approve design and risks |
| 1 Foundation | monorepo, dev Docker, API Vue, DB migration, lint/type/check CI | from zero start with documented commands |
| 2 Auth + tenancy | org/membership, roles, MFA, onboarding | tenant negative tests pass |
| 3 Academic & Studio | courses/groups, bank versions, assessments/publish, assignments, schedule | preview→publish→assign E2E |
| 4 Exam Engine | attempts, lease, timer, save, crash recovery, graded policy | concurrency/offline test matrix pass |
| 5 Judge | isolated code/SQL grading separate pool | hostile corpus pass before student traffic |
| 6 Agent management | MSI, enrollment, policy, local pairing, config, update | Windows lab 5 PC reliability pass |
| 7 Live Monitor | SFU PoC, incident center, reactions, live-only | 30 PCs load/revocation/no record pass |
| 8 Admin ops | audit, approvals, storage, pgBackRest, backups | restore RPO/RTO demonstrated |
| 9 Production | pilot, security/a11y/perf, runbooks, rollback | signed release and acceptance report |

**Parallelism:** UI tokens/components can progress during foundation; media and judge PoCs can be run concurrently, but cannot be declared finished before results. Never ship mock services behind real feature flags claiming production ready.
