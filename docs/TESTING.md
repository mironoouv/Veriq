# TESTING — матрица тестов и релизные гейты

## Test pyramid
- Backend pytest unit/property/integration with real PostgreSQL and Redis; migrations upgrade and rollback practices.
- Frontend Vitest + Vue Testing Library, Playwright E2E Chrome/Edge; i18n snapshots.
- .NET xUnit/NUnit, Windows integration in VM and real machines; device service IPC tests.
- Infra backups restore drills, network chaos, media load and sandbox penetration tests.

## Functional suites
1. Registration (email, invites TTL, group codes, applications, CSV/XLSX duplicate/invalid file, multi-tenant).
2. RBAC/ABAC matrix positive and cross-tenant negative for every endpoint and websocket channel.
3. Studio: personal/shared banks, permission levels, version snapshot invariant, random variants deterministic seed.
4. Schedule: UTC/local timezone & DST duplicate/nonexistent local times, calendar/list same assignment.
5. Attempt: concurrency duplicate starts, limits, idempotent save/submit, tab takeover, pause/resume races, clock spoof, deadline at exact boundary.
6. Offline: 0/10s/2m outages, IndexedDB write failure/eviction, browser crash, stale client operations, late work not auto trusted.
7. Scoring: partial credit, manual grades, 5-point/custom scale boundaries, regrade audit, publication time gating.
8. Agent: bulk/manual enrollment approvals, revocation, spoof/replay of pairing, LNA denied, protocol fallback, user switching/logoff, Windows standby, policy revision.
9. Media: multiple streams, viewer auth, revocation during view, no recording, UDP blocked/TURN fallback, multi-monitor.
10. Judge: sandbox hostile corpus, no network/privileges, SQL independent ephemeral instance, hidden test secret nonexposure, worker crash/retry.
11. Admin: approval center, audit immutability, cleanup dry-run no data loss, pgBackRest chain, MFA recovery.

## Nonfunctional thresholds (initial **targets**, to benchmark)
- Minimum 30 concurrent exam sessions + screen feeds in target lab topology, 2 observers, p95 answer-save latency < 1s at normal network, no confirmed answer loss.
- Under 5s typical agent disconnect detected (adjust after network tests; do not interpret as cheating), reconnect measured, teacher sees honest status.
- Accessibility keyboard navigation, WCAG 2.2 AA target; translated RU/EN critical flows.
- RPO≤5min/RTO≤1h measured in restore drill; backup/retention dashboard includes freshness.
- All Critical and High security findings resolved before production.

## Release gates
A. no hard-coded secrets or debug bypass. B. Two tenant isolation proven. C. no untrusted code on API host. D. no media recording. E. one active writer per attempt. F. 2FA enforced by role. G. recover test passed. H. windows agent signed packages and clean uninstall. I. security/legal student disclosure reviewed. J. user flows E2E test reproducible in CI.

## Foundation 1d browser smoke

Playwright закреплён в `apps/web/package-lock.json`. На Windows с Docker
Desktop из корня проекта установите зависимости и браузер:

```powershell
npm.cmd --prefix apps/web ci
npm.cmd --prefix apps/web exec -- playwright install chromium
pwsh -NoProfile -File tests/run_production_smoke.ps1
```

Тест использует отдельный постоянный Compose project `veriq-prod-smoke`.
Linux CI использует `veriq-prod-ci`. Проверяются Chromium, статические ресурсы,
RU/EN, прямой маршрут и fallback, живость Nginx при остановке API,
различие liveness/readiness при остановке Redis и восстановление по повторной
проверке. Браузер не должен обращаться к другим origin. Ожидаемые HTTP 50x
для health-проб во время остановки допускаются. Ошибки JS и прочие ошибки
консоли приводят к отказу. Сетевые вызовы и остановки реальны.

Тесты восстанавливают остановленные сервисы и выполняют `down` без удаления
томов. Trace, видео и скриншоты отключены. Проверки контейнеров и логов не
печатают значения секретов. Browser smoke не заменяет продуктовые E2E.
