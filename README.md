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
| `docs/project-memory/PROJECT_STATE.md` | Текущее состояние, ревью и вход в проектный контекст |
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

## Локальный запуск Foundation

Требуются Docker Desktop в режиме Linux Containers с WSL 2, Docker Compose v2
или новее и Python 3.11 для генерации локального пароля и запуска проверок.
Перед запуском проверьте, что `docker info --format '{{.OSType}}'` возвращает
`linux`, а `docker compose version` выводит версию Compose.

На компьютере с отдельным диском для разработки рекомендуем `E:\DockerData`.
Расположение образа диска задаётся в Docker Desktop через **Settings → Resources →
Advanced → Disk image location**. После **Apply & Restart** проверьте доступность
Engine через `docker info`, наличие файла образа диска в выбранном каталоге и
состав контейнеров, образов и томов. [Документация Docker Desktop](https://docs.docker.com/desktop/features/wsl/)

В PowerShell из корня проекта один раз создайте `.env`, сохранив существующий файл:

```powershell
if (-not (Test-Path .env)) {
    New-Item -ItemType File .env | Out-Null
}
foreach ($name in 'VERIQ_DB_PASSWORD', 'VERIQ_API_DB_PASSWORD', 'VERIQ_WORKER_DB_PASSWORD') {
    if (-not (Select-String -Path .env -Pattern "^\s*$name\s*=" -Quiet)) {
        $veriqDbPassword = python -c "import secrets; print(secrets.token_hex(32))"
        if ($LASTEXITCODE -ne 0 -or -not $veriqDbPassword) { throw "Password generation failed" }
        Add-Content -Encoding ascii .env "$name=$veriqDbPassword"
        Remove-Variable veriqDbPassword
    }
}
docker compose -f compose.yaml -f compose.dev.yaml up --build --wait
docker compose -f compose.yaml -f compose.dev.yaml ps --all
docker compose -f compose.yaml -f compose.dev.yaml run --no-deps --rm -T migrate alembic current --check-heads
python tests/smoke.py
```

Откройте [Veriq](http://localhost:5173). Страница проверяет доступность API,
PostgreSQL и Redis. В локальном режиме доступна [OpenAPI](http://localhost:5173/api/v1/docs).
Для нестандартного порта укажите `VERIQ_WEB_PORT` в `.env` и в окружении
перед запуском `tests/smoke.py`.

Для существующего тома сохраните `VERIQ_DB_PASSWORD`. Если значения уже присутствуют в
`.env` и пусты, заполните их отдельными случайными паролями. API стартует после
миграций и настройки отдельных учётных данных API и worker. При ошибке миграции
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
Локальная административная роль PostgreSQL используется для инициализации и
миграций. API и worker подключаются с отдельными ограниченными ролями.
Production overlay запланирован для следующего этапа Foundation.

## Статус разработки

Foundation 1b добавляет Redis и отдельный процесс фоновых задач. См. [устройство очереди и проверку восстановления](services/worker/README.md).

Foundation 1a включает Vue 3 / TypeScript, FastAPI, SQLAlchemy, Alembic и PostgreSQL.
Веб-интерфейс обращается к API через Vite proxy. Миграции и переход готовности API
при отключении и восстановлении PostgreSQL проверены на Windows с PostgreSQL 17.11.

При HTTP 500 от Docker Engine проверьте состояние Docker Desktop и дождитесь
готовности Linux Engine. До успешного выполнения команд запуска и smoke-проверки
окружение считается непроверенным.
