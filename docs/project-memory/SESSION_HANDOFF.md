# Передача контекста

Veriq — мультиарендная платформа для экзаменов с серверным состоянием, опциональным Windows Agent и отдельным Judge. Требования в [VERIQ_SPEC](../VERIQ_SPEC.md), утверждённые решения в [реестре и ADR](DECISIONS.md), порядок работ в [ROADMAP](../../planning/ROADMAP.md).

Foundation 1b принят и объединён в `main`. Он добавил PostgreSQL-очередь системных задач, внутренний Redis и worker с короткой SQL-пробой. См. [результат слияния и проверенные ревизии](PROJECT_STATE.md). При продолжении сверь Git и PR, затем загрузи нужную область из [индекса](CONTEXT_INDEX.md).

Foundation 1a–1d завершены. Доступны внутренние сессии, tenant-изоляция, [Compose overlay](../DEPLOYMENT.md) и [браузерный smoke](../TESTING.md#foundation-1d-browser-smoke). [План Auth & Account Security](../../planning/AUTH_ACCOUNT_SECURITY.md) одобрен. Slice 1–5 приняты. Текущая работа — [проект независимого восстановления MFA (PROPOSED)](../../planning/AUTH_MFA_RECOVERY.md). Password reset сохраняет MFA. Реализация Slice 6, переход к Slice 7 и изменения ADR требуют отдельного согласования. Сохранность Docker-данных проверяй без удаления томов.
