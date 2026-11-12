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
Foundation 1d обслуживает короткие HTTP-запросы и health-пробы. Перед
WebSocket отдельно согласуйте forwarding заголовков Upgrade/Connection,
таймауты и повторную проверку доступа. Для загрузок отдельно задайте лимиты
тела, buffering, временное хранилище и обработку отмены. Для длительных HTTP
операций согласуйте upstream/client timeouts, поведение при отмене и выбор
между синхронным запросом и worker. Текущие короткие таймауты health-пути
не являются настройками для этих будущих сценариев.

Forward `Upgrade` headers for WebSocket, proper proxy timeouts, keepalive, request size for uploads, error handling. SFU UDP/TURN bypasses ordinary Nginx HTTP path and must be exposed separately.

## Production operational checks
- Verify SMTP for registration/2FA recovery, malware scan uploads, object storage rights/retention, agent MSI signing, cron/worker retention health.
- Real performance tests on 30 clients and exercises for large files/timeout.
- Security/legal review before handling real student records.


## Локальная регистрация и почта

Используйте отдельный Compose-проект и тестовые адреса. Подготовьте выделенные пароли БД по стандартной инструкции, локальный файл SHA-256 блоклиста, случайный отдельный Fernet-ключ и 32-байтный HMAC-ключ в hex. Передайте `VERIQ_TEST_PASSWORD_BLOCKLIST`, `VERIQ_TEST_MAIL_KEY` и `VERIQ_TEST_AUTH_HMAC_KEY` через локальное окружение. Файл блоклиста должен быть читаем пользователем контейнера. Ключи хранятся вне Git и не выводятся в логи. Тестовый overlay публикует API только на `127.0.0.1:18000` и хранит письма в закрытом tmpfs worker.

```powershell
docker compose -p veriq-registration-test -f compose.yaml -f compose.registration-test.yaml config --quiet
docker compose -p veriq-registration-test -f compose.yaml -f compose.registration-test.yaml up --build --wait
```

Найдите тестовый JSON по UUID в `/run/veriq/mailbox` внутри worker. Для ручной проверки открывайте его только в приватном локальном окружении. При открытии пути из сообщения добавьте origin `http://127.0.0.1:18000`. Содержимое mailbox исчезает при остановке контейнера. Тестовый транспорт не отправляет писем во внешние системы. Для остановки используйте `down` с теми же параметрами проекта.

До включения настоящей доставки по OQ-12 согласуйте провайдера, TLS с проверкой сертификата, исходящий порт, аутентификацию через secret store, домен отправителя и SPF/DKIM/DMARC. Закрепите отдельный доверенный HTTPS origin для ссылок, выключите click tracking, согласуйте таймауты и повторы, ключ идемпотентности и ротацию ключей конвертов. Перед публичным включением требуется пройти остальные этапы Auth и оценить тайминги перечисления аккаунтов и злоупотребление resend.


## Тестовый браузерный вход

`compose.login-test.yaml` запускает API с TLS на loopback. Используйте выделенный тестовый проект и БД с подтверждёнными синтетическими аккаунтами. Передайте `VERIQ_TEST_TLS_CERT` и `VERIQ_TEST_TLS_KEY` вне Git. Сертификат должен быть доверен на тестовой машине, включать SAN `127.0.0.1` и быть читаем пользователем контейнера. Настройте отдельные `VERIQ_TEST_LOGIN_VERIFIER_PASSWORD` и `VERIQ_TEST_LOGIN_ISSUER_PASSWORD`, а также независимые 32-байтные hex-ключи `VERIQ_TEST_AUTH_HMAC_KEY` и `VERIQ_TEST_CSRF_KEY`.

```powershell
docker compose -p veriq-login-test -f compose.yaml -f compose.login-test.yaml config --quiet
docker compose -p veriq-login-test -f compose.yaml -f compose.login-test.yaml up --build --wait
```

Локальный HTTP остаётся пригодным для регистрации Slice 2. Вход и браузерные сессии требуют HTTPS также локально. Production overlay не получает параметры тестовых DB-ролей и не регистрирует маршруты входа.
