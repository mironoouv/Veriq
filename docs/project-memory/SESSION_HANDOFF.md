# Передача контекста

Veriq — мультиарендная платформа для экзаменов с серверным состоянием, опциональным Windows Agent и отдельным Judge. Требования в [VERIQ_SPEC](../VERIQ_SPEC.md), утверждённые решения в [реестре и ADR](DECISIONS.md), порядок работ в [ROADMAP](../../planning/ROADMAP.md).

Foundation 1b принят и объединён в `main`. Он добавил PostgreSQL-очередь системных задач, внутренний Redis и worker с короткой SQL-пробой. См. [результат слияния и проверенные ревизии](PROJECT_STATE.md). При продолжении сверь Git и PR, затем загрузи нужную область из [индекса](CONTEXT_INDEX.md).

[Foundation 1c](../../planning/FOUNDATION_1C.md) завершён с внутренними сессиями и tenant-изоляцией. Текущий срез 1d — [Compose overlay](../DEPLOYMENT.md) и [браузерный smoke](../TESTING.md#foundation-1d-browser-smoke). Публичный Auth и изменения утверждённых ADR требуют отдельного согласования. Сохранность Docker-данных проверяй без удаления томов.
