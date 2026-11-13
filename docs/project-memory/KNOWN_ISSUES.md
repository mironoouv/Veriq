# Известные ограничения

- [PR #2](https://github.com/mironoouv/Veriq/pull/2). Worker рассчитан на короткую доверенную SQL-пробу. Lease и восстановление длительных задач описаны как предложение.
- Queue retention (0021): terminal jobs expire after 168 hours. UUID deduplication keys remain indefinitely. Monitor key growth and establish a separate policy before adding external handlers.
- [PR #2](https://github.com/mironoouv/Veriq/pull/2). Starlette предупреждает об устаревающей интеграции `httpx` в тестах. Браузерный E2E запланирован отдельно.

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
