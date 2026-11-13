# Worker

Foundation 1b запускает отдельный процесс из того же образа, что и API.
Миграция `0002` добавляет системную таблицу `background_jobs`. Состояние задач,
счётчик попыток и уникальные идентификаторы хранятся в PostgreSQL. Redis хранит
ограниченную очередь сигналов пробуждения. При потере Redis worker опрашивает
PostgreSQL и автоматически восстанавливает работу с Redis. Redis не публикует порт.

## Хранение и очистка — PROPOSED

Готовая к выборке задача и задача с отложенным повтором хранятся как `pending`
с разным `available_at`. Активная задача в 1b удерживает блокировку строки,
поэтому в таблице остаётся `pending`. В модели lease активность будет
фиксироваться явно. `succeeded` и `failed` — терминальные состояния.

Будущая очистка должна опираться на отдельный `finished_at`, согласованные
сроки для успехов и ошибок, исключать pending, активные lease и записи
под удержанием. Предусмотреть dry-run, повторную проверку условий, ограниченные
пакеты и аудит. Срок хранения ключей дедупликации должен покрывать допустимое
окно повторной доставки, даже если данные задачи архивируются раньше.
Автоматическая очистка в 1b не включена.

## Локальный Compose-тест и обслуживание

Из корня в PowerShell выполните `./tests/run_worker_smoke.ps1` в одной сессии.
Скрипт использует фиксированные проект `veriq-worker-smoke-local` и порт 15174.
Повторные прогоны переиспользуют теги образов, сборочный кэш и отдельный
именованный том. Сгенерированный пароль остаётся в игнорируемом `.cache`.
В конце скрипт останавливает только свой проект через `down` без `--volumes`.
Тест временно останавливает Redis и worker и проверяет код выхода worker.

Перед обслуживанием используйте `docker system df -v`, `docker volume ls`,
`docker image ls` и `docker compose ps -a` для нужного проекта. Проверяйте
владельца ресурсов по меткам Compose. Старые smoke-тома считайте данными
до проверки содержимого и согласования удаления. Для обычного прогона
глобальная очистка Docker не требуется.

## Historical queue contract (0019)

Revision 0019 replaces worker table access with enqueue, claim and finish
functions. Enqueue only creates probe jobs. Claim locks an available row
and records the current PostgreSQL transaction ID. Finish only accepts a
pending row claimed by that transaction and computes status, attempts and
retry delay in PostgreSQL. Existing queue records keep their values.

This queue is shared: any worker can claim available work, and a worker
can report the outcome of its own claim. A concurrent transaction cannot
finish that claim. Rollback releases the row for redelivery. There is no
durable worker identity, lease or fencing for external side effects. A
committed unfinished claim can be reclaimed by a later transaction.
Use a forward migration for recovery; downgrade would restore broad DML.

## Current queue contract (0020)

Claim commits a running row with a 12-second lease. The worker renews it
every 3 seconds using another connection, leaving room for the 3-second
SQL statement timeout and transient scheduling delays. PostgreSQL owns
the expiry clock. Redis only wakes polling workers.

Each claim consumes one of three attempts and uses that number as a
per-job fencing token. Job UUIDs remain stable and must not be reused.
A failed handler retries after 2 or 4 seconds. After a crash, expiry plus
the same backoff makes the job eligible again. A poll finalizes an expired
third attempt as failed. Success is terminal. A worker that loses its
lease cannot commit handler SQL: finish and handler effects share a
transaction, and the current bounded SQL statement can finish before rollback.

Delivery is at least once. The worker UUID identifies a process
incarnation, not a separate database principal. External effects can
repeat across crashes and require receiver-side idempotency or fencing.
SMTP and other existing queues retain their own delivery semantics.
Drain old worker processes before applying 0020, then restart on the new
code. Downgrade is refused because it would discard leases.

## Queue history retention (0021)

Each worker attempts one batch of up to 100 terminal rows per minute in a
separate transaction with a two-second statement timeout. The cutoff is
168 hours from finished_at, inclusive. A status-transition trigger stamps
both explicit finish and recovery of exhausted attempts. Legacy terminal
rows receive the migration timestamp because their original completion time
was not recorded. Locked rows are skipped and reconsidered on later runs.

The dedicated non-login purger can delete only through the fixed worker
command. Cleanup logs count, duration and failure. Pending and running
jobs and all security audit tables are outside the retention rule.
UUID-only keys survive deletion to preserve enqueue idempotency and prevent
reuse of fencing identities. Their storage grows with the number of distinct
jobs. External handlers still need their own idempotency contracts.

### Applying 0021 to an existing queue

Schedule a maintenance window and rehearse on a representative copy.
Pause all queue producers and stop old workers gracefully before migration.
Confirm no queue transactions remain open. Check backup and restore readiness
and available space for the backfill, indexes and WAL. Revision 0021 holds
ACCESS EXCLUSIVE through commit, blocking reads and writes to the queue.
A five-second lock timeout bounds the wait for locks. It does not bound
the work after acquisition. If migration fails, confirm the revision and
queue are unchanged, resolve the blocker and retry during maintenance.
After commit verify revision 0021, queue counts and deduplication keys,
then start workers and resume producers. Use forward repair or a verified
restore if required. The CI timing includes container startup and is not
an estimate for production hardware or queues larger than the fixture.
