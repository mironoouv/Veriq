# DEPLOYMENT — Windows Docker → Linux server

## Dev
Windows 11 + Docker Desktop Linux containers. Prefer project files inside WSL2 Linux filesystem where supported for bind performance. `.env.example` only template; copy to `.env` ignored by git, generate random passwords locally. Agent itself is a Windows app (not containerized). On dev host use local HTTPS staging domain for loopback pairing tests, browser Chrome/Edge permissions tested.

## Foundation 1d — локальная проверка production overlay

Базовый `compose.yaml` объединяется с `compose.prod.yaml`. Vue собирается
через `npm ci` и `vite build` в отдельном слое. В финальном веб-образе только
Nginx и статические файлы. `/status` и неизвестные маршруты отдают SPA,
отсутствующий файл в `/assets/` получает 404. Nginx проксирует `/api/`
без смены origin, а API отключает OpenAPI UI.

1. На согласованном Docker-хосте используйте отдельный проект `veriq-prod`.
   Скопируйте `.env.prod.example` в `.env.prod`, ограничьте права файла
   владельцем и заполните три разных случайных пароля. Для существующего
   тома сохраните исходный пароль PostgreSQL. Dev использует отдельный `.env`.
   Продакшн-ориентированный overlay требует `VERIQ_PROD_WEB_PORT`, который
   задаётся в `.env.prod`. Переменные процесса Compose имеют приоритет,
   поэтому не наследуйте dev-пароли из оболочки.
2. Из проверенной ревизии выполните:

   ```sh
   docker compose --env-file .env.prod -p veriq-prod -f compose.yaml -f compose.prod.yaml config --quiet
   docker compose --env-file .env.prod -p veriq-prod -f compose.yaml -f compose.prod.yaml up --build --wait --wait-timeout 120
   docker compose --env-file .env.prod -p veriq-prod -f compose.yaml -f compose.prod.yaml run --no-deps --rm -T migrate alembic current --check-heads
   ```

3. Проверьте через `127.0.0.1` главную страницу и три пробы.
   `/_health/live` проверяет Nginx независимо от API, `/api/v1/health/live`
   проверяет процесс API, а `/api/v1/health/ready` проверяет PostgreSQL и Redis.
   `migrate` должен завершиться с кодом 0 до запуска API и worker.
4. Для остановки используйте ту же команду Compose с `down` без
   `--volumes`. Перед обновлением сохраните проверяемую копию БД и запишите
   Git SHA, digest образов и ревизию Alembic. При откате остановите запись.
   Если схема совместима, восстановите прошлые образы или соберите их из
   зафиксированного SHA и запустите тот же проект с тем же томом и секретами.
   Если схема несовместима, согласуйте восстановление в отдельный том из
   проверенной копии и проверьте миграции и smoke перед переключением.
   Не понижайте ревизию автоматически и не удаляйте старый том.

PostgreSQL, Redis, API и worker не публикуют порты. Единственный внешний
интерфейс Compose — веб-порт на loopback. Сети `database`, `queue` и `app`
внутренние. Для будущего публичного развёртывания нужен отдельно согласованный
TLS-edge. Runtime-контейнеры работают без root, Linux capabilities и повышения
привилегий. Файловая система read-only, кроме назначенных томов и tmpfs.
API и worker подключаются под `veriq_api` и `veriq_worker`; миграции отдельно.
Контейнерный администратор может читать runtime environment. Ограничьте доступ
к Docker и не публикуйте вывод `config` или `inspect` с переменными окружения.

### Политика digest

Production overlay закрепляет PostgreSQL и Redis как `tag@sha256`. Dockerfile
закрепляет Node, Python, uv и Nginx тем же способом. Теги показывают версию, а
digest фиксирует проверенное содержимое. Для обновления сверить upstream-релиз,
поддержку нужной архитектуры и security advisories, получить digest из реестра
издателя, обновить tag и digest в одном PR и прогнать CI и smoke. Не менять
major PostgreSQL без плана миграции данных. При публикации собственных release-
образов фиксировать исходный Git SHA и digest в реестре и деплоить по digest.
Образы Foundation 1d пока собираются локально и в CI.

Foundation 1d готовит инфраструктуру к следующему этапу. TLS/DNS, поставка
секретов на сервер, резервное копирование с восстановлением и операционный
мониторинг требуют отдельной настройки. Публичный Auth, MFA, Exam Engine и
аудит для образовательной эксплуатации ещё не реализованы.

## Compose topology
`nginx`, `api`, `postgres`, `redis`, `worker`, `frontend-build/static`, `object-storage` candidate, `media/livekit` candidate (dedicated network ports), `judge-scheduler` (not sandbox executor), `metrics`, `backup-manager` with least privilege. Never mount Docker socket in API/Judge. Secrets/production DB not mounted into malicious code executor.

## Networking
Browser HTTPS to Nginx at `veriq.void-rp.ru`; API/websocket via same origin to avoid unnecessary CORS. WebRTC SFU typically needs public address UDP port-range or UDP mux + TURN; TLS reverse proxy alone insufficient. Separate media DNS if needed, firewall allowlist admin endpoints, TURN credential rotation. Do not assume Docker bridge NAT works from all student PCs.

## Linux production
- Pin images by digest/release, separate named volumes/storage; health/readiness probes.
- Postgres private network, backup repo isolated, Redis no public bind, no direct Judge prod network.
- Let's Encrypt / ACME certificate issuance and renewal at Nginx / edge. HTTP→HTTPS, HSTS after validation, secure headers, rate limits, body size limits and WebSocket timeouts.
- Observability: Prometheus/OpenTelemetry candidate for metrics, structured logs with request_id, disk/backup alerts, judge and agent SLO.
- Deployment: database snapshot/backup, migration checks, expand/contract, rollout with smoke tests and rollback plan.

## Nginx notes
Forward `Upgrade` headers for WebSocket, proper proxy timeouts, keepalive, request size for uploads, error handling. SFU UDP/TURN bypasses ordinary Nginx HTTP path and must be exposed separately.

## Production operational checks
- Verify SMTP for registration/2FA recovery, malware scan uploads, object storage rights/retention, agent MSI signing, cron/worker retention health.
- Real performance tests on 30 clients and exercises for large files/timeout.
- Security/legal review before handling real student records.
