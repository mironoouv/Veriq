# Передача контекста

Veriq — мультиарендная платформа для экзаменов с серверным состоянием, опциональным Windows Agent и отдельным Judge. Требования в [VERIQ_SPEC](../VERIQ_SPEC.md), утверждённые решения в [реестре и ADR](DECISIONS.md), порядок работ в [ROADMAP](../../planning/ROADMAP.md).

Foundation 1b принят и объединён в `main`. Он добавил PostgreSQL-очередь системных задач, внутренний Redis и worker с короткой SQL-пробой. См. [результат слияния и проверенные ревизии](PROJECT_STATE.md). При продолжении сверь Git и PR, затем загрузи нужную область из [индекса](CONTEXT_INDEX.md).

Foundation 1a–1d завершены. Доступны внутренние сессии, tenant-изоляция, [Compose overlay](../DEPLOYMENT.md) и [браузерный smoke](../TESTING.md#foundation-1d-browser-smoke). [План Auth & Account Security](../../planning/AUTH_ACCOUNT_SECURITY.md) одобрен. Auth Slice 1–9 приняты в тестовом объёме, миграция 0015. Public Auth = NOT READY, открытые задачи в [KNOWN_ISSUES](KNOWN_ISSUES.md). Текущая работа — [план Academic & Studio](../../planning/ACADEMIC_STUDIO.md) со статусом PROPOSED. Реализация ждёт архитектурного ревью. Сохранность Docker-данных проверяй без удаления томов.
