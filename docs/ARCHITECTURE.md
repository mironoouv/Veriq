# ARCHITECTURE — проектное решение

## Стек
- Dev: Windows 11 + Docker Desktop Linux containers/WSL2; производительные bind mounts предпочтительно в файловой системе WSL при WSL2 backend; согласовать с выбранным Docker Desktop backend.
- Prod: Ubuntu/Linux + Docker Compose + Nginx/HTTPS, один домен `veriq.void-rp.ru` и пути `/api`, `/ws`; медиасервис имеет отдельные адреса и UDP/TURN в зависимости от инфраструктуры.
- Python FastAPI + Pydantic + SQLAlchemy 2 + Alembic; PostgreSQL; Redis для ephemeral/pubsub/jobs (истина — PostgreSQL); worker; Vue3/TS/Vite/Tailwind4/daisyUI5/Vue I18n/Pinia/Router; Agent C#/.NET10/WPF service+desktop; media WebRTC SFU кандидат LiveKit; separate sandbox judge.
- Общая архитектура **modular monolith**, а не микросервисы для каждой таблицы. Отдельно media, worker, judge из-за границ доверия и вычислений.

## Контексты backend (модули)
`identity, organizations, memberships, academic, question_banks, assessments, assignments, attempts, grading, judge_orchestration, devices, proctoring, incidents, auditing, storage, notifications`.
Каждый модуль владеет сервисным API и ORM-моделями; cross-module вызовы через явно определённый application service, без циклических импортов.

## Границы доверия
1. Internet browser (untrusted) → TLS Nginx → application auth & validation.
2. Local bridge (untrusted browser request) → origin allowlist + one-time pairing + proof-of-device to backend.
3. Device control (mutual/device signed auth) → restricted command schema, no general shell.
4. WebRTC publisher/subscriber → scoped tokens, room auth, actual disconnect/revocation.
5. Judge (actively malicious user code) → physically/VM-level separated executor host; **не** в обычном app worker/docker with prod secrets.
6. Backup storage (sensitive) → separate credentials, encryption, no arbitrary deletion.

## Event flows
### Экзамен
`Student login` → `assignment availability` → `attempt reservation transaction` → `preflight` → optional `agent pairing` → `start` → `autosave revisions` → `submit or deadline job` → `judge and manual check` → `publish according policy`.

### Прокторинг
`Approved device heartbeat` → `candidate exam pair code` → `device exchange proof` → `explicit active session` → `live screen SFU` → `proctor token with scope` → `end: stop + revoke room grants`.

### Админ-команда
`Admin session+step-up` → `server RBAC/tenant` → `command persisted with TTL/config revision` → `signed/encrypted control-channel delivery` → `agent verifies allowlist/scope/freshness` → `result ack audit`.

## Принцип «server is authority»
Postgres — authoritative state. Redis leases ephemeral и восстановимы. У attempt отдельные `status`, `deadline_at`, `pause_remain`, `version`, `active_control_token_hash` (или lease version), server clock UTC. Worker должен idempotently завершать overdue attempts даже при рестартах.

## Медиа
LiveKit candidate PoC: Windows screen capture + encoding + .NET publisher SDK compatibility + mediaserver; SFU on separate node/network as necessary, room per exam OR attempt according isolation/perf PoC. Журнал просмотра фиксирует viewer-id/attempt-id/start/end, реально отзыв на SFU. No recording plugin, no egress to file storage; prohibit production snapshots of screen in telemetry.

## Масштабирование
Первоначальная цель нагрузочного профиля: 30 одновременных студентов + 1–3 наблюдателя в классе; затем 100/300 в ступенчатом тесте. Метрики: API p95, save durability, PostgreSQL CPU/IOPS, media uplink/downlink, decoder CPU, reconnect time, judge queue delay. Нельзя утверждать гарантированную ёмкость без тестов на конкретном железе.

## Совместимость и выпуск
API `/api/v1`; агент указывает supported protocol versions and capabilities; backward compatibility N-1 релиз минимум (target, подтвердить). DB backward-compatible expand/migrate/contract. Feature flags на профили и Judge языки.

## Данные
UTC timestamps с offset/timestamptz; soft archive where needed, deletion policies. Attachments object store or dedicated volume (не в Docker image); signed short-term download URLs. Версии экзаменов immutable and referentially protected.
