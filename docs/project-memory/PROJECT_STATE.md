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
- Следующий этап — Auth & Account Security. [Технический план](../../planning/AUTH_ACCOUNT_SECURITY.md) имеет статус PROPOSED. Реализация ждёт согласования. Публичный Auth, MFA, Exam Engine и эксплуатационный аудит ещё не реализованы.
