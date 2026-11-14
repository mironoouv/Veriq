# Известные ограничения

- Durable lease, heartbeat, fencing and recovery are implemented in 0020 for short SQL handlers. External side effects can repeat. Connection loss during heartbeat and shutdown during active work still need broader fault testing.
- Queue retention (0021): terminal jobs expire after 168 hours. UUID deduplication keys remain indefinitely. Monitor key growth before adding external handlers.
- API tests use pinned httpx2 for Starlette TestClient and check a synthetic GET with warnings treated as errors. Decision 76: on 2026-11-15 the [GitHub branch rules endpoint](https://api.github.com/repos/mironoouv/Veriq/rules/branches/main) listed required checks, production, process and postgres-audit for main. Separately, all eight jobs passed on [PR #36 HEAD](https://github.com/mironoouv/Veriq/pull/36/checks), and push workflows passed on squash commit c4c9d6153c5c9772532e0eee67064d62e1c2be11: [Foundation](https://github.com/mironoouv/Veriq/actions/runs/43645271448), [Trusted MFA IPC](https://github.com/mironoouv/Veriq/actions/runs/43645271304), [PostgreSQL Security Audit](https://github.com/mironoouv/Veriq/actions/runs/43645271394).

## Public Auth — NOT READY

Все задачи ниже открыты. Основание — [Security Validation Report](../AUTH_SECURITY_VALIDATION.md).

| Задача | Подтверждение для закрытия |
|---|---|
| Аудит PostgreSQL SECURITY DEFINER и EXECUTE | Полный инвентарь функций, владельцев и грантов, негативные вызовы реальными runtime-ролями |
| Расширенный timing-анализ и нагрузка | Повторные измерения через согласованный edge, тесты Argon2id, Redis и глобальной advisory-блокировки |
| Production SMTP и уведомления | Доставка, повторы, отказ транспорта и отсутствие секретов в логах на стенде |
| Проверка скомпрометированных паролей | Согласованный источник, обновление, проверка отказа и защита приватности |
| Production MFA key management | Проверенный доступ к ключам, ротация и восстановление |
| Независимое MFA recovery | Операционный регламент проверки личности, передачи секрета и учение с независимыми сотрудниками |
| Офлайн-кворум последнего Superadmin | Ключи, состав кворума, исполнитель и учение по утверждённой процедуре |
| TLS, trusted proxy и секреты | Внешняя цепочка TLS, проверка forwarded headers, хранение и ротация секретов, отключение маршрутов |
| Резервные копии и восстановление | Реальный restore БД и ключей с измеренными RPO/RTO |
| Мониторинг, алерты и эксплуатация | Проверенные оповещения об отказах Auth, Redis, SMTP и worker, эксплуатационный runbook и учение |
