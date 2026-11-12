# Veriq v1.0 — полный пакет проектной документации

**Дата проекта документации:** 2026-11-12. **Язык:** русский. **Статус:** начальная реализация Foundation.

**Цель:** мультиарендная образовательная платформа для экзаменов, контрольных, самостоятельных и практических работ с автоматическим/ручным оцениванием, опциональным прокторингом Windows Agent и централизованным управлением.

**URL:** `https://veriq.void-rp.ru` (планируемое развёртывание, DNS/TLS ещё не настраивались этим пакетом).

## Навигация по пакету

| Файл | Назначение |
|---|---|
| `docs/VERIQ_SPEC.md` | Основное функциональное ТЗ, требования и состояния |
| `docs/ARCHITECTURE.md` | Компоненты, потоки данных, масштабирование, решения |
| `docs/DATABASE.md` | Логическая модель, ограничения и миграции |
| `docs/API_CONTRACTS.md` | REST/WebSocket, ошибки и примеры протокола |
| `docs/SECURITY.md` | Tenant isolation, RBAC/ABAC, MFA, аудит, privacy |
| `docs/AGENT_SPEC.md` | Служба Windows, Desktop, Bridge, provisioning |
| `docs/PROCTORING.md` | Профили, инциденты, трансляции, отсутствие записи |
| `docs/JUDGE_SPEC.md` | Безопасный Code/SQL Judge |
| `docs/DESIGN_SYSTEM.md` | UX, экраны, принципы дизайна |
| `docs/DEPLOYMENT.md` | Windows Docker dev → Linux production |
| `docs/BACKUP_STORAGE.md` | Backup/WAL/PITR, RPO/RTO, управление очисткой |
| `docs/TESTING.md` | Полный план тестирования и критерии выпуска |
| `docs/ACCEPTANCE.md` | Трассируемые критерии приёмки |
| `docs/DECISIONS.md` | Все подтверждённые проектные решения |
| `docs/OPEN_QUESTIONS.md` | Не утверждённые детали, прототипы, риски |
| `docs/adr/` | ADR-001—ADR-016 |
| `planning/ROADMAP.md` | Очередность реализации и контрольные точки |
| `planning/IMPLEMENTATION.md` | Технический план, архитектурные риски и предложения для ADR |
| `planning/TASKS.md` | Задачи первого спринта, готовые для агента |
| `AGENTS.md` | Правила поведения ИИ-агента |
| `schemas/` | Пример структурной модели и OpenAPI-заготовка |
| `examples/` | Неисполняемые образцы окружения и политик |

## Как работать с документами

1. Прочитать `AGENTS.md`, `docs/DECISIONS.md`, `docs/OPEN_QUESTIONS.md`.
2. Выполнять поэтапно `planning/ROADMAP.md`; не объявлять production-ready без проверок из `docs/TESTING.md`.
3. **Не запускать потенциально опасную функцию на основании заглушек**: sandbox, pairing и WebRTC обязательны реальные тесты.
4. Архитектурные предложения (например, LiveKit, pgBackRest, WiX, WPF) — рекомендованные реализации, а не все окончательно утверждённые решения. Всё это помечено `PROPOSED` где требуется проверка.
5. Документы — ТЗ и проектные контракты, **не** готовые исходники и не завершённая настройка сервера.

## Референсы и проверка актуальности
- Docker Desktop / WSL2: https://docs.docker.com/desktop/features/wsl/
- Chrome Local Network Access: https://developer.chrome.com/docs/modern-web-guidance/guides/security/local-network-access
- LiveKit self-host: https://docs.livekit.io/transport/self-hosting/deployment/
- .NET lifecycle: https://learn.microsoft.com/en-us/dotnet/core/releases-and-support
- pgBackRest: https://pgbackrest.org/user-guide.html

**ВНИМАНИЕ:** версии зависимостей и точные параметры портов фиксируются на этапе внедрения с security review; в примерах нет реальных секретов.

## Локальный запуск Foundation 1a

Требуются Docker Desktop с Linux Engine, Docker Compose v2 или новее и Python 3.11
для генерации локального пароля и запуска проверок. В PowerShell из корня проекта
один раз создайте `.env`, сохранив уже существующий файл:

```powershell
if (-not (Test-Path .env)) {
    $veriqDbPassword = python -c "import secrets; print(secrets.token_hex(32))"
    if ($LASTEXITCODE -ne 0 -or -not $veriqDbPassword) { throw "Password generation failed" }
    "VERIQ_DB_PASSWORD=$veriqDbPassword" | Set-Content -Encoding ascii .env
    Remove-Variable veriqDbPassword
}
docker compose -f compose.yaml -f compose.dev.yaml up --build --wait
python tests/smoke.py
```

Откройте [Veriq](http://localhost:5173). Страница проверяет доступность API и
PostgreSQL. В локальном режиме доступна [OpenAPI](http://localhost:5173/api/v1/docs).
Для нестандартного порта укажите `VERIQ_WEB_PORT` в `.env` и в окружении
перед запуском `tests/smoke.py`.

API стартует после выполнения `alembic upgrade head`. При ошибке миграции
посмотрите `docker compose -f compose.yaml -f compose.dev.yaml logs migrate postgres`,
исправьте причину и повторите запуск. Для остановки используйте
`docker compose -f compose.yaml -f compose.dev.yaml down`: именованный том PostgreSQL
сохраняется. PostgreSQL применяет исходный пароль при создании тома. Для существующего
тома храните согласованный пароль или явно смените его в БД и в `.env`.

Для проверки исходников установите uv и Node.js 24:

```powershell
uv sync --project apps/api --locked
uv run --project apps/api --locked ruff format --check apps/api
uv run --project apps/api --locked ruff check apps/api
uv run --project apps/api --locked mypy apps/api
uv run --project apps/api --locked pytest apps/api/tests
npm --prefix apps/web ci
npm --prefix apps/web run check:format
npm --prefix apps/web run check:types
npm --prefix apps/web run build
```

Публикуется только веб-порт на loopback. Compose предназначен для разработки.
Его роль PostgreSQL используется для локальной инициализации, миграций и проверки
доступности. Конфигурация с отдельными ролями БД и production overlay запланированы
в следующих срезах Foundation.

## Статус разработки

Foundation 1a включает Vue 3 / TypeScript, FastAPI, SQLAlchemy, Alembic и PostgreSQL.
Веб-интерфейс обращается к API через Vite proxy. Миграции и переход готовности API
при отключении и восстановлении PostgreSQL проверены на Windows с PostgreSQL 17.11.

Известное ограничение: Docker Desktop Linux Engine на проверенной Windows-машине
возвращал HTTP 500. Проверка конфигурации Compose прошла, полный запуск через
Docker Compose ещё предстоит подтвердить. Foundation остаётся открытым.
