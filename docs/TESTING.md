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


## Auth Slice 1 smoke

В выделенном dev Compose-проекте `tests/memberships_smoke.py` проверяет чистую установку и обновление через `0007 → 0008`. После TEN-01 Redis-проба проверяет конкурентные лимиты, раздельные категории, непрозрачные ключи и подмену forwarded IP. Затем она проверяет безопасный отказ с остановленным Redis. PostgreSQL smoke выполняет проверки сессий и Auth при остановленном Redis. Используются отдельные роли verifier, issuer, API и worker. Сценарии включают повтор и истечение proof, конкурирующие выпуск и массовый отзыв, неизменяемость аудита, параллельную вставку одного события, аренду outbox, повторную доставку после истечения аренды и повтор ack. Redis восстанавливается в `finally`.


## Auth Slice 2 smoke

`tests/memberships_smoke.py` проверяет чистую миграцию и переход `0008 → 0009`, затем запускает `registration_checks.py` на отдельном loopback HTTP-сервере внутри API-контейнера. API использует штатную DB-роль. Тестовый процесс отдельно использует владельца временной БД для проверки состояния и имитации истечения срока. Проверяются гонки регистрации и погашения, ограничения DB-ролей, Argon2id, блоклист, единообразные ответы, повтор, отказ локального транспорта, отказ Redis и отсутствие выдачи сессии. Проверка production Compose сохраняется отдельно.

## Auth Slice 3 smoke

Регрессионный сценарий поднимает loopback HTTPS с одноразовым тестовым сертификатом. Проверяются ограниченные DB-роли, одинаковый отказ для неизвестного адреса и неверного пароля, блокировка неподтверждённого и отключённого аккаунта, действующее членство и обязательная MFA, Origin и CSRF, атрибуты cookie, ротация, повтор старого токена и logout. Тесты Sessions отдельно проверяют idle/absolute timeout и конкурентные операции. Production Playwright проверяет инфраструктурные регрессии независимо.


Регрессия ревью проверяет старый профиль Argon2id и rehash при успешном HTTPS-входе. Отдельный PostgreSQL-тест удерживает блокировку аккаунта во время смены пароля и запускает подтверждение старого хеша параллельно. После фиксации замены старое подтверждение отклоняется, новый хеш сохраняется, proof не создаётся. Тесты слотов проверяют отказ под нагрузкой, отмену и восстановление после ошибки. Интеграция проверяет пары событий выпуска и MFA-отказа с общим request/correlation ID и одну запись успешной ротации.


## Auth Slice 4 smoke

Тесты используют векторы RFC 6238, реальный PostgreSQL и HTTPS. Они проверяют enrollment, TOTP replay/expiry, одновременное погашение одного резервного кода и одного challenge, политику двух организаций, Superadmin/Org Admin/Technician, переходы области, свежесть и абсолютный срок step-up, Redis outage, CSRF, cookie и права DB-ролей. Изолированный Chromium проверяет браузерный переход от challenge к полноценной сессии. Production Playwright выполняется отдельно.


## Auth Slice 5 smoke

Проверки используют PostgreSQL и ограниченные DB-роли. Они покрывают гонки смены с выпуском сессии и двух подтверждений reset, сохранение действующего proof при конкурентном resend, истечение, повтор, отказ почтового транспорта, уведомление, отсутствие и истечение step-up, сохранение MFA после reset. HTTPS-интеграция проверяет Origin, CSRF, одинаковый ответ для существующего и неизвестного адреса, безопасный GET и отказ Redis. Отдельный Chromium проверяет путь от локального mailbox до POST формы, очистку cookie и повторный вход.
