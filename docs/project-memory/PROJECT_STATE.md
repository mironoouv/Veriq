# Состояние проекта

Обновлено 2026-11-12.

- Foundation 1a принят. PR [#1](https://github.com/mironoouv/Veriq/pull/1) объединён в `0a423d0dae913c86188f10278e87e6e682c34f32`.
- Foundation 1b принят владельцем после повторного технического ревью. [PR #2](https://github.com/mironoouv/Veriq/pull/2) из `feature/foundation-1b-redis-worker` объединён в `main` коммитом `b59bf0fef795822200ea00cd3b70ee75646e11b2`. Локальный `main` сверили с `origin/main`.
- Коммит исправлений, проверенный на Windows через Compose — `bf8952d7e08adcfc726732c74bdbd98f467ec5a0`. Статус CI для актуального HEAD указан в [проверках PR #2](https://github.com/mironoouv/Veriq/pull/2/checks). [CI базовой ревизии 1b](https://github.com/mironoouv/Veriq/actions/runs/43185393180) прошёл отдельно.
- HEAD PR на момент приёмки — `68d3bc420001f0670929f0334969005c4be955a6`. [GitHub Actions](https://github.com/mironoouv/Veriq/actions/runs/43187504265) прошёл. Финальный HEAD после уточнения документации — `14274a696468434c2a9a2587849c2a02028abc23`. Оба запуска CI прошли: [PR](https://github.com/mironoouv/Veriq/actions/runs/43188281490) и [push](https://github.com/mironoouv/Veriq/actions/runs/43188271770).
- Foundation 1c: [план](../../planning/FOUNDATION_1C.md) одобрен. Slice A принят и [PR #4](https://github.com/mironoouv/Veriq/pull/4) объединён в main коммитом `10b98db1d59a2eb57d5cf3daca218734ff61614b`.
- Slice B принят. [PR #5](https://github.com/mironoouv/Veriq/pull/5) объединён squash-коммитом `61cc22a05107606bcbcda7d904864948147683af`. Локальный main обновлён, ревизия `0005` подтверждена.
- Slice C принят. [PR #6](https://github.com/mironoouv/Veriq/pull/6) объединён squash-коммитом `4825b1cc3ed1001681025b62ddb38215414dff00` после зелёного CI. Локальный main обновлён и содержит `0006`. Границы RLS и `VerifiedSubject` описаны в [SECURITY](../SECURITY.md#tenant-transaction-boundary-slice-c).
- Slice D принят. [PR #7](https://github.com/mironoouv/Veriq/pull/7) объединён squash-коммитом `d3e7ed7a84b72744cad8f10589f0d85c4f69e7f9` после зелёного CI. Локальный main обновлён и содержит `0007`. Foundation 1c завершён. Публичный вход, MFA, cookies, CSRF и подключение доверенного издателя сессий остаются для Auth.
- Foundation 1d принят. [PR #8](https://github.com/mironoouv/Veriq/pull/8) объединён squash-коммитом `fbd647caa641dc2f826c5887b9dd60e5de46420f`. Локальный main обновлён, миграция `0007` подтверждена. Foundation 1a–1d завершены. [Overlay, откат и ограничения Nginx](../DEPLOYMENT.md), [Playwright smoke](../TESTING.md#foundation-1d-browser-smoke).
- [PR #9](https://github.com/mironoouv/Veriq/pull/9) с планом Auth объединён squash-коммитом `339ce4dd2436335b7224ef524e1e48a64b238a67` после успешного CI. Локальный main обновлён. План одобрен с уточнениями.
- Проверки Slice 1 на Windows Docker Desktop: установка и обновление до `0008`, TEN-01, Sessions, PostgreSQL Auth, Redis rate limit и отказ Redis, production Compose и три Playwright smoke. Статус Linux CI проверяется по актуальному HEAD PR.
- Auth Slice 1 принят. PR [#10](https://github.com/mironoouv/Veriq/pull/10) объединён squash-коммитом `34e6ac731a1eaa2eab59d36c534b2963f6f0569b`. Локальный main обновлён, ревизия `0008` подтверждена, [CI на main](https://github.com/mironoouv/Veriq/actions/runs/43241774119) прошёл.
- Проверки Slice 2 на Windows Docker Desktop: переход `0008 → 0009`, чистая миграция, регистрация и её негативные сценарии с PostgreSQL и Redis, TEN-01, Sessions, отдельный test overlay с локальной доставкой и production Playwright 3/3. Linux CI отслеживается по актуальному HEAD PR.
- Auth Slice 2 принят. PR [#11](https://github.com/mironoouv/Veriq/pull/11) объединён squash-коммитом `bafe4bc739d0c79b7979f027d2c7c34fc63ca65e` после зелёного CI. [CI на main](https://github.com/mironoouv/Veriq/actions/runs/43245749658) прошёл. Resend сохраняет действующий proof, production-политика блоклиста и SMTP остаются открытыми.
- Auth Slice 3 в ветке `feature/auth-03-login-sessions`: ревизия `0010`, password-only verifier, отдельный issuer и HTTPS-адаптер входа. Публичная активация и второй фактор ждут следующих согласованных срезов.
- Windows Docker Desktop: миграция `0010`, HTTPS-интеграция, Sessions, TEN-01, worker и production Playwright 3/3. Отдельный Chromium на loopback HTTPS проверил CSRF, cookie, ротацию и logout. CI сверяется на HEAD PR.
- Доработка PR #12 перед повторным ревью: Argon2id проверяет ограниченные старые профили и обновляет хеш по прежнему PHC и версии credentials. Лимит вычислений на процесс сохраняется при отмене HTTP. Аудит разделяет проверку пароля, выпуск, отказ по MFA и ротацию. Slice 4 ожидает согласования.
- Проверки доработки на Windows: старый профиль и rehash, гонка со сменой пароля, контракт событий, слоты при отмене и ошибке, отдельный HTTPS Chromium и production Playwright 3/3. CI проверяется на актуальном HEAD PR #12.
- Auth Slice 3 принят. [PR #12](https://github.com/mironoouv/Veriq/pull/12) объединён squash-коммитом `8939d40c3b8614d374d722469deec12b72c74432`. Main синхронизирован, ревизия `0010` присутствует. [CI на main](https://github.com/mironoouv/Veriq/actions/runs/43275082273) прошёл.
- Auth Slice 4, ветка `feature/auth-04-mfa-step-up`: ревизия `0011`, TOTP, одноразовые резервные коды, политика организации и step-up в тестовом HTTPS. Публичное включение, production KMS, passkeys и независимое восстановление остаются открытыми. Slice 5 ждёт технического ревью.
- Windows Docker Desktop: чистая миграция и `0010 → 0011`, гонки challenge и резервного кода, MFA HTTPS, политики, step-up, Redis outage, TEN-01 и Sessions. Изолированный Chromium enrollment и production Playwright 3/3 прошли. CI сверяется на HEAD PR.
- Auth Slice 4 принят в тестовом объёме. [PR #13](https://github.com/mironoouv/Veriq/pull/13) объединён squash-коммитом `c25745abe0b9458c84b9d26f0a71e09a0428f9d5`. Main синхронизирован, ревизия `0011` подтверждена. [CI на main](https://github.com/mironoouv/Veriq/actions/runs/43278987381) прошёл. Первичное enrollment требует оператора, ротация сохраняет старые ключи до переноса факторов, step-up привязан к назначению.
- Windows Docker Desktop: миграция `0011 → 0012` и чистая установка, гонки выпуска и смены и двух reset confirm, устойчивость resend, отказ Redis/почты, проверка step-up и сохранности MFA. HTTPS Chromium и production Playwright 3/3 прошли. Linux CI сверяется на HEAD PR.
- Auth Slice 5 принят. [PR #14](https://github.com/mironoouv/Veriq/pull/14) объединён squash-коммитом `67fa50d11f3778ee49597431e3856a2b1934defd`. Main синхронизирован с origin/main, ревизия `0012` подтверждена, [CI на main](https://github.com/mironoouv/Veriq/actions/runs/43282742806) прошёл. Password reset не восстанавливает и не отключает MFA и не выдаёт сессию.
- Auth Slice 6 — [проект независимого восстановления MFA](../../planning/AUTH_MFA_RECOVERY.md) одобрен с уточнениями. Разрешена обычная процедура, офлайн-процедура закрыта, Slice 7 ждёт разрешения.
- Архитектура Auth Slice 6 в [PR #15](https://github.com/mironoouv/Veriq/pull/15) объединена squash-коммитом `1bbb0fcac57f129e54d227e4725aef9707bcd050` после зелёного CI. Обычная процедура в ветке `feature/auth-06-mfa-recovery`, ревизия `0013`. Offline Superadmin утверждён только как архитектура. Ключи, манифест, исполнитель и учение не реализованы. Slice 7 ждёт ревью.
- [CI на main после PR #15](https://github.com/mironoouv/Veriq/actions/runs/43286484866) прошёл. Windows PostgreSQL и Chromium проверили обычный процесс, отсутствие обхода по email/паролю, scope и свежесть, гонки и hold. CI реализации сверяется по актуальному HEAD.

- Auth Slice 6 принят в тестовом объёме. [PR #16](https://github.com/mironoouv/Veriq/pull/16) объединён squash-коммитом `895fdd4a5b495469d64c5a7177fca0855383578e`. Main синхронизирован с origin/main, миграция `0013` присутствует. [CI на main](https://github.com/mironoouv/Veriq/actions/runs/43291385459) прошёл.
- Открытые ограничения Slice 6: независимая ручная проверка личности, эксплуатация офлайн-кворума Superadmin и отдельный аудит SQL SECURITY DEFINER. Публичный Auth и MFA recovery выключены в production.
- Auth Slice 7 начат в `feature/auth-07-organization-joining`. [Проект правил вступления](../../planning/AUTH_ORGANIZATION_JOINING.md) фиксирует утверждённую политику членства и границы реализации. Ревизия 0014, транзакционные переходы и тестовый HTTPS API реализованы. Политика вступления не выдаёт ролей. Коды классов, отправка приглашений и production-включение остаются вне текущего объёма. CI сверяется по HEAD PR.
- Windows Docker Desktop для Slice 7: чистая миграция и 0013 → 0014 с синтетическими данными, TEN-01, Sessions и обе процедуры восстановления, PostgreSQL-проверки приглашений и заявок, HTTPS Chromium для CSRF, Origin, cookies и отказа Redis. Linux CI сверяется на HEAD PR.

- Auth Slice 7 принят. [PR #17](https://github.com/mironoouv/Veriq/pull/17) объединён squash-коммитом `4797d81b3ad4c1a22467dd8931d5e4836c04c991`. Main синхронизирован, ревизия `0014` присутствует, [CI main](https://github.com/mironoouv/Veriq/actions/runs/43295861189) прошёл. Новым ролям Org Admin требуется явно выдать `organization.join.manage`. Глобальная advisory-блокировка остаётся предметом нагрузочной проверки.
- Auth Slice 8 в ветке `feature/auth-08-bulk-import`, ревизия `0015`. Ограниченный CSV/XLSX импорт с preview, подтверждением, JSON-отчётом и истечением staging. Импорт не создаёт аккаунтов, ролей или сессий. Входящий пользователь проходит обычное подтверждение email перед claim. Публичный production Auth выключен. Slice 9 ждёт отдельного ревью.
- Windows для Slice 8: чистая миграция и обновление 0014 → 0015 с синтетическими данными, конкурентные импорт и отзыв полномочий, проверка tenant, claim после подтверждения email и удаление истёкших строк. HTTPS Chromium проверил preview/confirm, Origin, CSRF, лимит файла и отказ Redis. Production Playwright 3/3. Linux CI сверяется на HEAD PR.
- Повторное ревью PR #18: SQL импорта использует только членства текущей организации для предпросмотра. Адреса вне организации имеют единое состояние pending_onboarding; подтверждение делает партию доступной для claim и не создаёт членств. Даже ранее подтверждённый аккаунт получает pending membership только после собственного claim. Новая заявка видна в отчёте после этого действия.

- Auth Slice 8 принят. [PR #18](https://github.com/mironoouv/Veriq/pull/18) объединён squash-коммитом `034df5ad61b1e54b3d878123738469b640bc162a`. Локальный main синхронизирован, ревизия `0015` подтверждена, [CI на main](https://github.com/mironoouv/Veriq/actions/runs/43300660179) прошёл. Расширенный timing-анализ, нагрузка и production-политики остаются открытыми.
- Slice 9 в ветке `feature/auth-09-security-e2e`: воспроизводимый HTTPS Chromium, проверка закрытых Auth-маршрутов production и [Security Validation Report](../AUTH_SECURITY_VALIDATION.md). Production Auth — NOT READY. Следующие продуктовые этапы ждут ревью.

- Auth Slice 1–9 завершены в согласованном тестовом объёме. [PR #19](https://github.com/mironoouv/Veriq/pull/19) объединён squash-коммитом `d4f6365b6178b336af8c22666d2e1a5517a70a7d`. Main синхронизирован, миграция `0015` присутствует. [CI на main](https://github.com/mironoouv/Veriq/actions/runs/43304633627).
- Public Auth = NOT READY. Публичные Auth endpoints выключены. [Открытые задачи](KNOWN_ISSUES.md) и [Security Validation Report](../AUTH_SECURITY_VALIDATION.md).
- Следующий этап по ROADMAP — Academic & Studio. [План](../../planning/ACADEMIC_STUDIO.md) имеет статус PROPOSED. Код новой подсистемы ждёт архитектурного ревью.

- [PR #20](https://github.com/mironoouv/Veriq/pull/20) принят с уточнениями и объединён squash-коммитом `9b7cd769984288980ea903d732410cff06c2ee09`. Локальный main обновлён. [План Academic & Studio](../../planning/ACADEMIC_STUDIO.md) APPROVED для Slice 1. [CI PR #20](https://github.com/mironoouv/Veriq/actions/runs/43306043556) прошёл.
- Slice 1 в ветке `feature/academic-01-catalog`: ревизия `0016`, изолированный каталог courses и study_groups, архив и тестовый HTTPS API/Vue. Slice 2 ждёт ревью. Public Auth остаётся NOT READY.

- PR #21 returned for changes after independent review. Revision 0017 adds catalog restoration, with a version check and an audit event. Acceptance awaits repeat independent review.

- SEC-ACA-01 is under review: revision 0018 requires a current session proof for catalog DML and records audit in the database transaction. Direct SQL read isolation remains a separate audit topic.

## Academic & Studio Slice 2 — схема назначений Teacher

- Владелец утвердил контракт PR #38 на main `0c1e206db0b5b8b6201721ba395140f238f7c916`. Подготовлена ревизия 0024 с составными tenant FK, grant_epoch, историей назначения и FORCE RLS без runtime-доступа. Проверка актуальности эпохи и роли относится к будущим серверным операциям.
- Добавлен локальный сценарий для двух пустых изолированных БД. Из каталога apps/api запустить `python ../../tests/academic_group_teacher_schema_checks.py clean` и `python ../../tests/academic_group_teacher_schema_checks.py upgrade` на разных БД с настроенными параметрами подключения и `PYTHONPATH` на каталог API. На Docker Desktop Linux в изолированном Compose с PostgreSQL 17.11 прошли оба режима. Проверены сохранность каталога и аудита при обновлении, составные tenant FK, история назначения, ENABLE/FORCE RLS и отказ прямого DML и чтения под veriq_api. CI на HEAD нового PR ещё не подтверждён.
- Полная TEN-01 приёмка рабочих HTTPS-операций и гонок отзыва относится к следующим PR Slice 2. SEC-MFA-01 — OPEN. Public Auth — NOT READY.

## Academic & Studio Slice 2 — политика назначений Teacher

- Изолированный серверный модуль принимает проверенные снимки сессии, членства, разрешений и ресурса. Выдача требует активной группы и активного Teacher того же tenant. Отзыв привязан к открытому назначению и доступен уполномоченному Org Admin после утраты целью роли или активности.
- В отдельном Linux Compose прошли Ruff, mypy, 46 тестов API и отдельный прогон 17 тестов политики на синтетических организациях A/B. Это проверка решений политики для TEN-01. Транзакционная перепроверка полномочий, аудит, гонки отзыва и проверки PostgreSQL/HTTPS остаются для интеграции. CI нового PR ещё не подтверждён.

## Academic & Studio Slice 2 — история состава групп

- Ревизия 0025 добавляет `group_memberships` с составными tenant FK, ENABLE/FORCE RLS и закрытым прямым доступом runtime. Ограничение GiST с `btree_gist` запрещает пересечения полуоткрытых интервалов для одного членства в одной группе. Открытый конец представлен NULL.
- В отдельном Linux Compose с PostgreSQL 17.11 прошли чистая установка и обновление заполненной БД 0024 → 0025. Проверены сохранность каталога, аудита и истории назначений Teacher, смежные интервалы, параллельное участие в разных группах, конфликт конкурентных вставок, смешанные tenant FK и отказ чтения и DML под veriq_api. Полный memberships_smoke.py прошёл до 0025 с отдельными проверками отказов downgrade 0022 и 0024. CI нового PR ожидает публикации контроллером.
- Транзакционная авторизация, аудит изменений состава, атомарный перевод и полная приёмка TEN-01 через HTTPS относятся к следующим PR. SEC-MFA-01 — OPEN. Public Auth — NOT READY.

## Academic & Studio Slice 2 — допуск к переводу

- Изолированная политика проверяет сессию, членство и эпоху вызывающего, tenant, разрешение на обе группы и назначения Teacher. Исходный открытый интервал должен принадлежать действующему Student, а целевая группа должна быть активной.
- На Docker Desktop Linux в отдельном Compose прошли сборка API checks (Ruff, mypy и pytest) и все 20 целевых тестов политики. GitHub CI ожидает публикации контроллером.
- Повторная проверка в транзакции, конкурентный отзыв, атомарная запись интервалов и аудита и полная приёмка TEN-01 через PostgreSQL и HTTPS остаются для интеграции.

## Academic & Studio Slice 2 — сверка отзыва полномочий

- Сверены SQL-пути сессий, членств, ролей и разрешений, назначений Teacher и архивирования. Триггер 0013 покрывает организационные полномочия. Одиночный logout блокирует строку без 7007. Для блокировки аккаунта и назначений Teacher участие в протоколе ещё не подтверждено. Каталог блокирует строку до аудиторского shared 670013.
- Транзакционная граница остаётся PROPOSED. Нужны решение владельца по пробелам, подтверждение эффективных прав и прогоны обоих порядков фиксации по TEN-01 и AUD-01. SEC-MFA-01 — OPEN. Public Auth — NOT READY.

## Academic & Studio Slice 2 — эффективные ACL

- На PostgreSQL 17.11 с миграцией 0025 проверены `group_memberships` и `academic_group_teacher_assignments`. Отдельные подключения veriq_api и veriq_worker подтвердили ENABLE/FORCE RLS, отсутствие владения и членства в роли владельца, BYPASSRLS и эффективных прав на таблицы и столбцы. SELECT, INSERT, UPDATE и DELETE отклонены с SQLSTATE 42501. Строки синтетических организаций A/B сохранились.
- Локальный прогон на Docker Desktop Linux прошёл в проекте `veriq-slice2-acl-b3c4900c`. Для повтора из корня репозитория задать три разные временные переменные `VERIQ_DB_PASSWORD`, `VERIQ_API_DB_PASSWORD`, `VERIQ_WORKER_DB_PASSWORD` и уникальное имя проекта в PowerShell:
  ```powershell
  $p = 'veriq-slice2-acl-' + [guid]::NewGuid().ToString('N').Substring(0,8)
  docker --context desktop-linux compose -p $p up -d --wait postgres
  docker --context desktop-linux compose -p $p run --build --rm --no-deps -T migrate
  docker --context desktop-linux compose -p $p run --rm --no-deps -T -e PYTHONPATH=/app -v "${PWD}/tests:/fixtures:ro" migrate python /fixtures/academic_slice2_acl_checks.py
  docker --context desktop-linux compose -p $p down --volumes
  ```
- CI на HEAD будущего PR ожидает публикации контроллером. ACL будущей команды перевода, гонки отзыва, AUD-01 и полная TEN-01 через HTTPS остаются открытыми. SEC-MFA-01 — OPEN. Public Auth — NOT READY.

## Academic & Studio Slice 2 — блокировка сессии при переводе

- PROPOSED: после ключей аккаунтов и 670013 будущая команда перевода блокирует строку сессии FOR NO KEY UPDATE NOWAIT, затем ресурсы и исходный интервал. Проект описывает повторную проверку и сценарии TEN-01/AUD-01 для обоих порядков фиксации с logout и занятой строки.
- Реализация и PostgreSQL/HTTPS-приёмка ждут отдельного допуска. Блокировка аккаунта, отзыв назначения Teacher и эффективные ACL будущей команды остаются открытыми. SEC-MFA-01 — OPEN. Public Auth — NOT READY.

## Academic & Studio Slice 2 — блокировка аккаунтов при переводе

- PROPOSED: после строки сессии и перед группами блокировать строки вызывающего и студента в users по UUID через FOR NO KEY UPDATE NOWAIT, затем повторно проверить disabled_at обоих аккаунтов. Проект описывает оба порядка фиксации и конфликт занятой строки.
- Реализация требует отдельного допуска. Открыты проверка обслуживания, отзыв назначения Teacher, эффективные ACL будущей команды и приёмка PostgreSQL/HTTPS по TEN-01 и AUD-01. SEC-MFA-01 — OPEN. Public Auth — NOT READY.


## Academic & Studio Slice 2 — отзыв назначения Teacher при переводе

- PROPOSED: писатель назначения берёт exclusive 670013 после ключей 7007 и до блокировок строк. Перевод удерживает shared 670013 и повторно проверяет назначения и grant_epoch на обеих группах. Предусмотрена остановка переводов перед обслуживающим DML, если участие писателя в протоколе нельзя подтвердить.
- Реализация требует отдельного допуска. Открыты эффективные ACL будущих команд и PostgreSQL/HTTPS-приёмка TEN-01 и AUD-01 для обоих порядков фиксации и конфликта. SEC-MFA-01 — OPEN. Public Auth — NOT READY.


## Academic & Studio Slice 2 — тест блокировок перевода

- Ревьюер в авторежиме (approved_by=reviewer) допустил только тест протокола из main 4966755 на одноразовой PostgreSQL. На PostgreSQL 17.11 (0025) в Docker Desktop Linux, проект veriq-transfer-locks-fc98c85f, проверены одиночный logout через veriq_auth_revoke, UPDATE статуса обеих строк аккаунта и модель отзыва назначения на каждой группе. PostgreSQL подтвердил ожидание писателя, видимость отзыва после фиксации и конфликты NOWAIT/try-lock.
- Для повтора из корня в PowerShell задать три разных временных пароля Compose (VERIQ_DB_PASSWORD, VERIQ_API_DB_PASSWORD, VERIQ_WORKER_DB_PASSWORD):
  ```powershell
  $p = 'veriq-transfer-locks-' + [guid]::NewGuid().ToString('N').Substring(0,8)
  docker --context desktop-linux compose -p $p up -d --wait postgres
  docker --context desktop-linux compose -p $p run --build --rm --no-deps -T migrate
  docker --context desktop-linux compose -p $p run --rm --no-deps -T -e PYTHONPATH=/app -v "${PWD}/tests:/fixtures:ro" migrate python /fixtures/academic_slice2_transfer_lock_checks.py
  docker --context desktop-linux compose -p $p down --volumes
  ```
- Checks, production, process и postgres-audit на HEAD нового PR ожидают публикации контроллером. Атомарность интервалов и аудита, ACL рабочих команд и полная TEN-01/AUD-01 через HTTPS открыты.


## Academic & Studio Slice 2 — атомарность перевода

- На PostgreSQL 17.11 (0025) в Docker Desktop Linux, проект veriq-transfer-atomic-6c9fbcc6, проверены успешная фиксация двух интервалов и одного события с общим серверным временем, сохранность tenant B, повтор после успеха, отказ при пересечении и откат при принудительном отказе тестового аудита. Состояние сверялось через независимое соединение.
- Для повтора из корня в PowerShell задать три разные синтетические переменные VERIQ_DB_PASSWORD, VERIQ_API_DB_PASSWORD и VERIQ_WORKER_DB_PASSWORD:
  ```powershell
  $p = 'veriq-transfer-atomic-' + [guid]::NewGuid().ToString('N').Substring(0,8)
  docker --context desktop-linux compose -p $p up -d --wait postgres
  docker --context desktop-linux compose -p $p run --build --rm --no-deps -T migrate
  docker --context desktop-linux compose -p $p run --rm --no-deps -T -e PYTHONPATH=/app -v "${PWD}/tests:/fixtures:ro" migrate python /fixtures/academic_slice2_transfer_atomicity_checks.py
  docker --context desktop-linux compose -p $p down --volumes
  ```
- Checks, production, process и postgres-audit на новом HEAD ожидают публикации контроллером. Рабочие ACL, транзакционная авторизация, аудит рабочей команды и полная TEN-01/AUD-01 через HTTPS остаются открытыми. SEC-MFA-01 — OPEN. Public Auth — NOT READY.


## Academic & Studio Slice 2 — SQL-полномочия перевода

- PROPOSED: определены будущие полномочия команды и двух помощников. Открыты проверка минимальных столбцовых UPDATE для блокирующих SELECT, граница первоначального чтения сессии, FORCE RLS, эффективные EXECUTE и интеграционная приёмка TEN-01/AUD-01 с рабочим аудитом. Отдельный допуск владельца требуется для реализации, выдачи прав и включения. SEC-MFA-01 — OPEN. Public Auth — NOT READY.


## Academic & Studio Slice 2 — ACL блокировки сессии

- На PostgreSQL 17.11 в Compose-проекте veriq-session-lock-acl-857bbf82 роль veriq_session_store подтвердила эффективные столбцовые права и блокировку по ID и доказательству. Конкурентный NOWAIT вернул 55P03, несовпадающее доказательство не вернуло и не заблокировало строку tenant B. Каталог подтвердил, что RLS и FORCE RLS на auth_sessions выключены. Отказ в этом чтении обеспечивает предикат, а изоляция будущего помощника требует отдельной проверки.
- Для повтора из корня задать три разные временные переменные VERIQ_DB_PASSWORD, VERIQ_API_DB_PASSWORD и VERIQ_WORKER_DB_PASSWORD, затем выполнить в PowerShell:
  ```powershell
  $p = 'veriq-session-lock-acl-' + [guid]::NewGuid().ToString('N').Substring(0,8)
  docker --context desktop-linux compose -p $p up -d --wait postgres
  docker --context desktop-linux compose -p $p run --build --rm --no-deps -T migrate
  docker --context desktop-linux compose -p $p run --rm --no-deps -T -e PYTHONPATH=/app -v "${PWD}/tests:/fixtures:ro" migrate python /fixtures/academic_slice2_session_lock_acl_checks.py
  docker --context desktop-linux compose -p $p down --volumes
  ```
- Checks, production, process и postgres-audit ожидают публикации контроллером. ACL будущего помощника, транзакционная авторизация, рабочий аудит и полная TEN-01/AUD-01 через HTTPS открыты. SEC-MFA-01 — OPEN. Public Auth — NOT READY.


## Academic & Studio Slice 2 — первое чтение сессии

- PROPOSED: доказательство связывается с аккаунтом, tenant и эпохой до выбора ключей; привязка и действительность перепроверяются под блокировками перед записью. Открыты эффективный EXECUTE, транзакционная авторизация, рабочий аудит и HTTPS-приёмка TEN-01/AUD-01. Реализация требует отдельного допуска. SEC-MFA-01 — OPEN. Public Auth — NOT READY.

## Academic & Studio Slice 2 — ACL блокировки аккаунтов

- На PostgreSQL 17.11 в Compose-проекте `veriq-account-lock-7cc88201b` роль `veriq_session_store` прочитала `users.id` и `users.disabled_at` и заблокировала обе синтетические строки через `FOR NO KEY UPDATE NOWAIT`. Миграция 0007 даёт SELECT на эти столбцы. Эффективный UPDATE действует на `credential_version`, `password_hash` и `updated_at` по миграциям 0008, 0010 и 0012. Этого достаточно для блокирующего чтения при отсутствии UPDATE на `disabled_at`. Независимое соединение получило 55P03. Снимки статусов и состава A/B совпали.
- Для повтора из корня задать разные временные синтетические значения `VERIQ_DB_PASSWORD`, `VERIQ_API_DB_PASSWORD` и `VERIQ_WORKER_DB_PASSWORD`:
  ```powershell
  docker --context desktop-linux info
  $p = 'veriq-account-lock-' + [guid]::NewGuid().ToString('N').Substring(0,8)
  docker --context desktop-linux compose -p $p up -d --wait postgres
  docker --context desktop-linux compose -p $p run --build --rm --no-deps -T migrate
  docker --context desktop-linux compose -p $p run --rm --no-deps -T -e PYTHONPATH=/app -v "${PWD}/tests:/fixtures:ro" migrate python /fixtures/academic_slice2_account_lock_acl_checks.py
  docker --context desktop-linux compose -p $p down --volumes
  ```
- CI на проверенном HEAD PR #55 `12618d68728ba5bc54b7aab44888e912e36d3cac`:
  - checks — успешно. [GitHub Actions](https://github.com/mironoouv/Veriq/actions/runs/43734046333)
  - production — успешно. [GitHub Actions](https://github.com/mironoouv/Veriq/actions/runs/43734046333)
  - process — успешно. [GitHub Actions](https://github.com/mironoouv/Veriq/actions/runs/43734046407)
  - postgres-audit — успешно. [GitHub Actions](https://github.com/mironoouv/Veriq/actions/runs/43734046345)
- Матрица остаётся PROPOSED. Открыты привязка аккаунтов к tenant под FORCE RLS, эффективный EXECUTE будущих помощников, транзакционная авторизация, рабочий аудит и полная приёмка TEN-01/AUD-01 через HTTPS. SEC-MFA-01 — OPEN. Public Auth — NOT READY. Риск прежних полномочий доверенной SQL-роли сохраняется.

## Academic & Studio Slice 2 — FORCE RLS привязки аккаунта

- В профильном плане описаны проектные SELECT-политики для владельца помощника, составное соединение интервала с активным членством, повторная сверка привязки перед блокировкой и восстановление tenant-контекста. Добавлена будущая матрица PostgreSQL TEN-01 для синтетических A/B. Шаг документальный, матрица остаётся PROPOSED. Эффективные EXECUTE и FORCE RLS будущих ролей, транзакционная авторизация, рабочий аудит и полная приёмка TEN-01/AUD-01 через HTTPS остаются открытыми.

- На PostgreSQL 17.11 в Compose-проекте `veriq-binding-8c66b7b0-final` тестовая роль NOLOGIN без BYPASSRLS и владения таблицами получила только указанные столбцовые SELECT. На обеих таблицах подтверждён FORCE RLS. Отсутствующий и пустой контекст скрыли все строки. Установка A или B открыла строки соответствующего tenant. Поиск из A вернул UUID для открытого интервала с активным членством A и пустой результат для чужого, закрытого или неактивного случая. После фиксации изменённой привязки на независимом соединении повторное чтение выявило несовпадение.
- Для повтора из корня задать разные временные синтетические значения `VERIQ_DB_PASSWORD`, `VERIQ_API_DB_PASSWORD` и `VERIQ_WORKER_DB_PASSWORD`:
  ```powershell
  docker --context desktop-linux info
  $p = 'veriq-binding-' + [guid]::NewGuid().ToString('N').Substring(0,8)
  docker --context desktop-linux compose -p $p up -d --wait postgres
  docker --context desktop-linux compose -p $p run --build --rm --no-deps -T migrate
  docker --context desktop-linux compose -p $p run --rm --no-deps -T -e PYTHONPATH=/app -v "${PWD}/tests:/fixtures:ro" migrate python /fixtures/academic_slice2_account_binding_rls_checks.py
  docker --context desktop-linux compose -p $p down --volumes
  ```
- CI на проверенном HEAD PR #57 `dfff7394b846452ebe10b8f0537efa48ae81e0e0`:
  - checks — успешно. [GitHub Actions](https://github.com/mironoouv/Veriq/actions/runs/43740093588)
  - production — успешно. [GitHub Actions](https://github.com/mironoouv/Veriq/actions/runs/43740093588)
  - process — успешно. [GitHub Actions](https://github.com/mironoouv/Veriq/actions/runs/43740093521)
  - postgres-audit — успешно. [GitHub Actions](https://github.com/mironoouv/Veriq/actions/runs/43740093571)
- Для рабочей команды открыты доверенное происхождение и восстановление tenant-контекста, эффективный EXECUTE, отсутствие чужой блокировки, транзакционная авторизация, рабочий аудит и приёмка TEN-01/AUD-01 через HTTPS.

## Academic & Studio Slice 2 — HTTPS-контракт перевода

- Добавлены 22 автономных сценария совместной проверки classify_transfer и create_transfer_router для Org Admin и Teacher. Синтетическая команда проверяет действующую чистую политику и возвращает её категорию. Покрыты успех, недействительная сессия, устаревшая эпоха, чужие ссылки, отсутствие разрешения на каждой группе, закрытый источник до/после допуска, архивная цель и приоритет отказа доступа. Ответы не содержат доказательства, UUID актёра/студента и ключ команды.
- В окружении uv sync --frozen прошёл 121 целевой pytest, включая прежние тесты политики, допуска, HTTP и OpenAPI. Ruff, mypy --strict и git diff --check прошли. Docker для автономных тестов не запускался. Регистрация рабочего маршрута отсутствует. CI опубликованного HEAD требует отдельной сверки. Получение доверенных снимков, транзакционная авторизация, блокировки, права, рабочий аудит и полная HTTPS-приёмка TEN-01/AUD-01 открыты.

- Уточнены отрицательные тесты чистой политики: каждый сценарий явно задаёт ожидаемый TransferFailure вместо допуска любого статуса 401/404/409. Проверка совместимости authorize_transfer через AccessDenied сохранена. В окружении uv sync --frozen прошли 64 целевых pytest, Ruff и mypy --strict. git diff --check прошёл. Docker для модульной правки не запускался. CI нового HEAD требует сверки после публикации контроллером.

- Добавлена чистая classify_transfer с категориями TransferFailure по доверенным снимкам. Проверка текущих полномочий предшествует конфликтам состояния. Закрытый источник скрывается по умолчанию, конфликт после предварительного допуска требует отдельного доверенного серверного признака и сохранения текущих полномочий. authorize_transfer сохраняет прежний интерфейс и отказы.
- В окружении uv sync --frozen прошли 64 целевых pytest, Ruff и mypy --strict. Docker для чистой политики не запускался. CI опубликованного HEAD требует отдельной сверки. Получение снимков, рабочая транзакционная авторизация, блокировки, права, аудит и HTTPS-приёмка TEN-01/AUD-01 остаются открытыми.

- Изолированный адаптер описывает OpenAPI для обязательного UUID заголовка, тела из двух UUID, минимального ответа 201 и шести кодов отказа с безопасным envelope. Описаны Origin/CSRF и no-store. Автономный тест проверяет сгенерированную схему через /openapi.json, обязательность и точный набор полей.
- В окружении uv sync --frozen прошли 77 целевых pytest, Ruff и mypy --strict. Существующие проверки HTTP и допуска сохранены. Docker для автономного шага не запускался. Регистрация в рабочем приложении отсутствует. Checks, production, process и postgres-audit опубликованного HEAD требуют отдельной сверки. Рабочие авторизация, права, аудит и полная HTTPS-приёмка TEN-01/AUD-01 открыты.

- Добавлена автономная create_transfer_admission с обязательными Sessions и серверной проверкой Origin/CSRF. Используются SessionToken, SessionGate и Sessions.resolve. Допуск создаётся только для подтверждённого непустого tenant, совпадающего с путём. Тестовая сессионная граница синтетическая, PostgreSQL в этих проверках не используется.
- В окружении uv sync --frozen прошли 76 целевых pytest, Ruff и mypy --strict. Подтверждены успешный допуск, отказы Origin/CSRF, недействительной сессии, отсутствующего и чужого tenant, отсутствие вызова команды при отказах и скрытие доказательства в ответах. Docker для автономного шага не запускался. Регистрация маршрута отсутствует. CI опубликованного HEAD требует отдельной сверки. Авторизация обеих групп, транзакционная повторная проверка, права, рабочий аудит и HTTPS-приёмка TEN-01/AUD-01 открыты.

- В TransferAdmission вместо одного session_id передаётся обязательный серверный SessionGate с digest и ограничениями сроков для будущей повторной транзакционной проверки. Поле скрыто из repr. Тесты подтверждают передачу того же синтетического доказательства команде, отсутствие его в ответах и представлении и сохранение отказов до вызова команды.
- В окружении uv sync --frozen прошли 69 целевых pytest, Ruff и mypy --strict. Docker для автономной правки не запускался. CI на новом HEAD требует отдельной проверки после публикации контроллером. Рабочая авторизация, права, аудит и HTTPS-приёмка остаются открытыми.

- Добавлен самостоятельный create_transfer_router с обязательными типизированными зависимостями допуска и команды. Повторно использованы модели, проверка UUID ключа и безопасные отказы. Адаптер генерирует диагностический контекст, сверяет tenant допуска, скрывает исключения зависимостей. Тестовый обработчик заменён адаптером с синтетическими зависимостями. В main.py и browser_login.py регистрация отсутствует.
- В окружении uv sync --frozen прошли 68 целевых pytest, Ruff, mypy --strict и git diff --check. Подтверждены отсутствие вызова команды при неверном запросе или отказе допуска, передача аргументов и контекста, ответы 201/отказы и маршрутизация. Docker для автономного шага не запускался. Checks, production, process и postgres-audit будущего HEAD требуют сверки после публикации. Рабочая интеграция, Origin/CSRF и сессия, транзакционная авторизация, права, аудит и полная HTTPS-приёмка TEN-01/AUD-01 остаются открытыми.

- Автономный TestClient проверил совместное использование моделей, UUID Idempotency-Key и безопасных ответов. Покрыты точный 201 с no-store, 422 для тела/заголовка, шесть категорий отказов и оба порядка регистрации academic-roster/transfers и academic/{kind}. Обработчики существуют только в тестовом приложении и возвращают синтетические ответы.
- В локальном окружении, созданном через uv sync --frozen из apps/api/uv.lock, прошли 58 целевых pytest (16 HTTP-сценариев и 42 прежних проверки), Ruff и mypy --strict. Docker для автономных тестов не требовался. Checks, production, process и postgres-audit будущего HEAD требуют сверки после публикации контроллером. Рабочая авторизация, права, аудит и HTTPS-приёмка TEN-01/AUD-01 остаются открытыми.

- Добавлены автономные TransferFailure и transfer_error_response с шестью фиксированными категориями, нейтральным сообщением, диагностическим request_id, пустыми details и no-store. Категоризацию после авторизации должна выполнять будущая команда. Подключение к маршруту остаётся PROPOSED.
- Локально прошли 42 целевых pytest и mypy --strict. Ruff и git diff --check проверены после правки импортов. Версии инструментов соответствуют uv.lock. Docker для автономного формирования ответов не запускался. Checks, production, process и postgres-audit будущего HEAD требуют сверки после публикации. Рабочая авторизация, права, аудит и HTTPS-приёмка TEN-01/AUD-01 открыты.

- Добавлена автономная parse_transfer_idempotency_key для обязательного UUID заголовка. Отсутствующие, пустые и неверные значения дают нейтральный ValueError без отражения входа. Назначение UUID команды отделено от диагностического request_id. Подключение к маршруту остаётся PROPOSED.
- Локально прошли 35 целевых pytest, включая прежние проверки моделей, Ruff и mypy --strict. Docker для автономной проверки заголовка не запускался. Checks, production, process и postgres-audit требуют проверки на опубликованном HEAD. Рабочая авторизация, права, аудит и HTTPS-приёмка TEN-01/AUD-01 открыты.

- Добавлены автономные GroupTransferRequest и GroupTransferResult. Запрос требует два UUID и запрещает дополнительные поля. Результат требует фиксированный result=transferred и UUID целевого интервала. Подключение к маршруту остаётся PROPOSED.
- Локально прошли 28 целевых pytest, Ruff и mypy --strict для двух новых файлов. Проверены положительные значения, обязательность полей, неверные UUID, лишние поля, сериализация и JSON Schema. PostgreSQL и Docker для автономных моделей не требуются. Checks, production, process и postgres-audit будущего HEAD ожидают публикации контроллером.

- PROPOSED. В API_CONTRACTS.md описаны маршрут academic-roster/transfers, два UUID-поля запроса, обязательный Idempotency-Key, минимальный ответ 201 и серверная проверка обеих групп. Закрытый источник при предварительном поиске и повтор после фиксации дают нейтральный HTTP 404. Закрытие после подтверждения доступа даёт 409 при сохранении полномочий. Добавлены будущие проверки маршрутизации и отказов без изменения интервалов и аудита. Определены нейтральные отказы без раскрытия чужих ресурсов и будущие HTTPS-сценарии TEN-01/AUD-01 с проверкой отката через PostgreSQL.
- Результат документальный. Рабочая команда, транзакционная авторизация, эффективные права, рабочий аудит и полная приёмка открыты. PR #61 требует разрешения расхождения CI. SEC-MFA-01 — OPEN. Public Auth — NOT READY. Риск прежних полномочий доверенной SQL-роли сохраняется.

## Academic & Studio Slice 2 — контракт аудита перевода

- PROPOSED. В профильном плане сопоставлены общая модель audit_events, действующие auth_audit_events и academic_catalog_events. Предложен отдельный типизированный журнал перевода с tenant-ссылками, request ID, актёром, студентом, двумя интервалами и общим серверным временем. Описаны закрытый просмотр, append-only права и будущие проверки повторов, изоляции и отката при отказе аудита.
- Результат документальный. Рабочий аудит, транзакционная авторизация, эффективные права и полная приёмка TEN-01/AUD-01 через HTTPS открыты. Отложенная проверка архивирования требует отдельного прогона после восстановления Docker. SEC-MFA-01 — OPEN. Public Auth — NOT READY. Риск прежних полномочий доверенной SQL-роли сохраняется.

## Academic & Studio Slice 2 — модель EXECUTE цепочки перевода

- В отдельном Compose-проекте `veriq-execute-dbb2d172` на мигрированной PostgreSQL 17.11 прошла проверка четырёх тестовых SECURITY DEFINER-функций и пяти NOLOGIN-ролей. Проверены эффективные EXECUTE по полным сигнатурам, отсутствие PUBLIC EXECUTE, ожидаемые владельцы и последовательность вложенных переходов команды к сессионному помощнику и помощнику аккаунтов, затем к внутреннему чтению сессии. API-аналог вызывает только команду, worker-аналог получает 42501 для всех функций. Прямые вызовы помощников из неподходящих ролей возвращают 42501. Владельцы сохраняют собственный EXECUTE.
- Для повтора из корня задать разные временные синтетические значения `VERIQ_DB_PASSWORD`, `VERIQ_API_DB_PASSWORD` и `VERIQ_WORKER_DB_PASSWORD`:
  ```powershell
  docker --context desktop-linux info
  $p = 'veriq-execute-' + [guid]::NewGuid().ToString('N').Substring(0,8)
  docker --context desktop-linux compose -p $p up -d --wait postgres
  docker --context desktop-linux compose -p $p run --build --rm --no-deps -T migrate
  docker --context desktop-linux compose -p $p run --rm --no-deps -T -e PYTHONPATH=/app -v "${PWD}/tests:/fixtures:ro" migrate python /fixtures/academic_slice2_transfer_execute_acl_checks.py
  docker --context desktop-linux compose -p $p down --volumes
  ```
- Проверенный локальный исходный SHA — `9c3ff7510e8d46a82cdd181bc707d1576c2b3403` с правками этого шага.
- CI на проверенном HEAD PR #59 `1cb77f2c0a36a0b868228ad00c6e0cd64c0b191f`:
  - checks — успешно. [GitHub Actions](https://github.com/mironoouv/Veriq/actions/runs/44880672694)
  - production — успешно. [GitHub Actions](https://github.com/mironoouv/Veriq/actions/runs/44880672694)
  - process — успешно. [GitHub Actions](https://github.com/mironoouv/Veriq/actions/runs/44880672665)
  - postgres-audit — успешно. [GitHub Actions](https://github.com/mironoouv/Veriq/actions/runs/44880672686)
- Подтверждена модель прав на тестовых функциях, возвращающих синтетические маркеры ролей. Рабочие функции остаются PROPOSED. Открыты их эффективные права, доверенное происхождение и восстановление tenant-контекста, отсутствие чужой блокировки, транзакционная авторизация, рабочий аудит и HTTPS-приёмка TEN-01/AUD-01. SEC-MFA-01 — OPEN. Public Auth — NOT READY. Риск прежних полномочий доверенной SQL-роли сохраняется.

## Academic & Studio Slice 2 — восстановление tenant-контекста

- PostgreSQL 17.11, Compose-проект `veriq-context-7f0df431`, база мигрирована из `14fd4ab2f6ea439a41896370602528f47bc779ec`. Тестовый вызывающий подставляет доверенный tenant A. Функциональный SET очистил входной GUC, а локальный A открыл под FORCE RLS только строки состава и членства A. В той же транзакции исходные B и пустой GUC восстановились после возврата и после SQLSTATE P7501 с откатом до точки сохранения.
- Для повтора из корня задать разные временные синтетические значения `VERIQ_DB_PASSWORD`, `VERIQ_API_DB_PASSWORD` и `VERIQ_WORKER_DB_PASSWORD`:
  ```powershell
  docker --context desktop-linux info
  $p = 'veriq-context-' + [guid]::NewGuid().ToString('N').Substring(0,8)
  docker --context desktop-linux compose -p $p up -d --wait postgres
  docker --context desktop-linux compose -p $p run --build --rm --no-deps -T migrate
  docker --context desktop-linux compose -p $p run --rm --no-deps -T -e PYTHONPATH=/app -v "${PWD}/tests:/fixtures:ro" migrate python /fixtures/academic_slice2_tenant_context_checks.py
  docker --context desktop-linux compose -p $p down --volumes
  ```
- CI на проверенном HEAD PR #58 `d4299b3c96b22e3ac9a738952c069abaf040cd66`:
  - checks — успешно. [GitHub Actions](https://github.com/mironoouv/Veriq/actions/runs/43742562510)
  - production — успешно. [GitHub Actions](https://github.com/mironoouv/Veriq/actions/runs/43742562510)
  - process — успешно. [GitHub Actions](https://github.com/mironoouv/Veriq/actions/runs/43742562570)
  - postgres-audit — успешно. [GitHub Actions](https://github.com/mironoouv/Veriq/actions/runs/43742562580)
- Рабочий помощник остаётся PROPOSED. Открыты доверенное происхождение и восстановление tenant в рабочем помощнике, эффективный EXECUTE, отсутствие чужой блокировки, транзакционная авторизация, рабочий аудит и полная HTTPS-приёмка TEN-01/AUD-01.
