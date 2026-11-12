# Первая очередь задач для ИИ-разработчика (без попытки сделать всё одним коммитом)

## Sprint 0 — artifacts
- [ ] Прочитать все docs, собрать dependency graph and risk register, статус APPROVED/PROPOSED.
- [ ] Выбрать pinned versions with justification; generate architecture diagram and ADR deltas if needed.
- [ ] Прототип Local Network Access Chrome/Edge, `veriq://` fallback and LiveKit .NET publisher independently; preserve findings.

## Sprint 1 — foundation
- [ ] Init monorepo: `apps/web`, `apps/api`, `apps/agent`, `services/worker`, `services/media`, `services/judge`, `infra`, `docs`, `tests`.
- [ ] Create production-conscious `compose.yaml`, `compose.dev.yaml`, `compose.prod.yaml`, `.env.example`, `.gitignore`, README quickstart. Docker container healthcheck and start dependencies.
- [ ] Scaffold FastAPI application (`/health/live`, `/health/ready`, OpenAPI protected in prod), SQLAlchemy+Alembic bootstrap, PostgreSQL, Redis, worker.
- [ ] Scaffold Vue3 TS/Vite, Tailwind4/daisyUI5, i18n RU/EN, Pinia/Router, layouts with accessible nav, basic theme tokens.
- [ ] Build initial migrations org/users/memberships/roles/permissions/session; seed **only** dev fixture with safe random credentials generated at run.
- [ ] CI formatting/lint/test/type checks and secret scanner, reproducible fresh compose startup.
- [ ] Test compose → migrations → API ready → Vue loads; negative cross-tenant test baseline.

## Required output for each task
1. Summary + files changed; 2. exact commands/tests executed and results; 3. unresolved risks; 4. docs updated; 5. no screenshots of student data; 6. next atomic task. Flag incomplete/untested explicitly.

## Forbidden sprint 1 shortcuts
Never put production credentials in repo; do not run SQL/code judge inside API; do not implement mock auth as real auth; do not assume local Agent pairing simply by `fetch('/health')`; do not implement insecure all-org superadmin data access; no persistent video frames.
