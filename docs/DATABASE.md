# DATABASE — модель PostgreSQL (проект; не готовые миграции)

## Общие правила
- UUID primary keys, `created_at`, `updated_at`, versions for mutable records, timestamptz UTC.
- Все tenant-owned таблицы содержат `organization_id` NOT NULL и правильные composite FK для исключения cross-tenant relations. Индексы начинаются с `organization_id` для типичных tenant queries.
- Global `users` tenant_id не имеет, но доступ через memberships. В таблицах audit и exam попыток сохраняется историческая информация о роли/назначении на момент события.
- RLS — defense in depth, не замена application auth; tenant scope устанавливается **SET LOCAL** только внутри транзакции; service-role bypass и background jobs отдельно протестировать.
- На уровне сервиса нет произвольного удаления оценок или журналов без policy.

## Identity / Academic
`users(id,email_normalized unique,email_verified_at,password_hash,disabled_at,...)`
`auth_sessions(id,user_id,token_hash,organization_id,grant_epoch,mfa_level,authenticated_at,created_at,last_seen_at,idle_expires_at,absolute_expires_at,revoked_at,revoke_reason)`
`mfa_factors(id,user_id,kind,encrypted_secret,created_at,last_used_at)`; `recovery_codes(id,user_id,code_hash,used_at)`
`organizations(id,slug unique,display_name,timezone,retention_policy_id,status)`
`organization_memberships(id,organization_id,user_id,status,joined_at,unique(org,user))`

Ревизия `0003` (Foundation 1c Slice A) добавляет эту таблицу, сохраняя данные
`organizations`, `users` и `background_jobs`. Пара `(organization_id, user_id)`
уникальна во всех состояниях, а ключ `(organization_id, id)` предусмотрен для
будущих составных FK. Ссылки на организацию и аккаунт обязательны, удаление
ссылаемых строк ограничено `RESTRICT`. Индекс `user_id` поддерживает поиск
членств по глобальному аккаунту.

Статусы — `pending` по умолчанию, `active`, `suspended`, `revoked`.
SQLAlchemy-модель отличает активное членство и увеличивает версию при ORM-обновлении.
`joined_at` означает момент первого подтверждённого вступления. Его выставляет
будущая операция вступления. Приостановка и отзыв сохраняют дату. Старый
`NULL` означает отсутствие зафиксированной даты и остаётся без backfill.
`updated_at` получает время PostgreSQL при вставке и при изменении строки через
ORM. При прямом SQL за обновление метки отвечает пишущий код. Назначение роли
не меняет строку членства. Метка не заменяет аудит. Статус проверяется на момент
доступа. Аудит изменений и сохранение исторических ссылок обязательны для
будущих операций. Срез A добавляет схему и модель без маршрутов членства.

### Роли и разрешения

Ревизия `0004` (Slice B) добавляет таблицы без изменения данных `0003`.

| Таблица | Ключи и назначение |
|---|---|
| `permissions` | `(scope, code)` — каталог разрешений области platform или organization |
| `platform_roles`, `platform_role_assignments` | UUID роли и назначение по `(user_id, role_id)`. Платформенный код — `superadmin` |
| `platform_role_permissions` | Роль и разрешение области platform |
| `organization_roles` | `(organization_id, id)`, уникальный код внутри организации. Коды `org_admin`, `teacher`, `proctor`, `student`, `technician` |
| `organization_role_permissions` | Составной FK на роль организации и FK на разрешение области organization |
| `membership_roles` | `(organization_id, membership_id, role_id)`. Два составных FK, чтобы членство и роль относились к одной организации |

Раздельные таблицы назначений позволяют выразить границы области обязательными
FK. Разрешения задаются явными связями. Миграция создаёт пустые каталоги.
Ревизия `0005` связывает назначение с эпохой `grant_epoch` членства. При
вставке PostgreSQL берёт блокировку строки членства, проверяет `active` и сам
устанавливает эпоху назначения. Ключ `(organization_id, membership_id,
grant_epoch, role_id)` исключает дубликаты в текущей эпохе и сохраняет строки
предыдущих назначений. Изменение строки назначения отклоняется.

Переход в `revoked` увеличивает эпоху в той же транзакции, а `suspended`
временно скрывает разрешения без смены эпохи. Чтение требует совпадения эпох,
активных членства и организации и действующего аккаунта. Повторная активация
после отзыва требует явного нового назначения. Исторические строки сохраняются.
Эпоха позволяет отозвать весь набор одним изменением строки членства и
сериализовать отзыв с назначением на той же строке.

При обновлении с `0004` все прежние организационные назначения становятся
историческими: прежняя схема не фиксировала отзыв. Действующие роли следует
подтвердить отдельными назначениями. Downgrade к `0004` разрешён только для
пустой таблицы назначений, чтобы история не превратилась обратно в полномочия.

### Другие таблицы Identity и Academic

`invites(id,organization_id,token_hash,scope,expires_at,uses_left,invited_email_hash,created_by)`
`join_requests(id,organization_id,user_id,status,reviewed_by,...)`
`group_join_codes(id,organization_id,group_id,code_hash,expires_at,uses_left,approval_required)`
`study_groups(id,organization_id,name,academic_year,status)`
`group_memberships(id,organization_id,group_id,membership_id,start_at,end_at)`
`courses(id,organization_id,title)`; `course_teachers(organization_id,course_id,membership_id)`
`imports(id,organization_id,source_filename,checksum,status,preview_summary,created_by)`; `import_rows(id,import_id,row_hash,status,error_codes)`

## Question banks / Exam
`question_banks(id,organization_id,owner_membership_id,title,visibility)`
`bank_acl(id,organization_id,bank_id,subject_membership_id nullable,subject_role nullable,permission)`
`questions(id,organization_id,bank_id,type,current_version_id)`
`question_versions(id,organization_id,question_id,version,body_json,max_points,grading_policy_json,answer_key_encrypted,immutable_at)`
`assessments(id,organization_id,owner_membership_id,kind,status,title,course_id)`
`assessment_drafts(id,organization_id,assessment_id,editable_content,revision)`
`assessment_publications(id,organization_id,assessment_id,version,content_hash,policy_snapshot_json,published_at)`
`assessment_items(id,organization_id,publication_id,question_version_id,section,ordinal,weight,selection_rule)`
`assignments(id,organization_id,publication_id,opens_at,closes_at,time_limit_seconds,attempt_limit,timezone,agent_requirement,connectivity_policy,results_policy,status)`
`assignment_targets(id,organization_id,assignment_id,group_id nullable,membership_id nullable)`
`calendar_events(id,organization_id,assignment_id nullable,event_kind,starts_at,ends_at,location,...)`
`attempts(id,organization_id,assignment_id,student_membership_id,status,attempt_number,started_at,deadline_at,paused_at,remaining_seconds,version,lease_version,submitted_at,grade_status)`
`attempt_variants(id,organization_id,attempt_id,seed,immutable_variant_json,hash)`
`answers(id,organization_id,attempt_id,item_id,answer_payload,revision,server_confirmed_at)`
`answer_operations(id,organization_id,attempt_id,client_operation_id,answer_id,expected_revision,status,unique(attempt_id,client_operation_id))`
`grade_entries(id,organization_id,attempt_id,item_id,points,grader_kind,grader_membership_id,reason,revision)`
`grade_revisions(id,organization_id,attempt_id,old_grade,new_grade,actor_id,reason,created_at)`
`result_publications(id,organization_id,attempt_id,visibility,visible_from)`

## Agent / Monitoring
`agent_devices(id,organization_id,device_public_key,hardware_hint_hash,approved_at,revoked_at,group_id,current_version,last_seen_at)`
`agent_enrollments(id,organization_id,token_hash,expires_at,allowed_count,used_count,requested_by)`
`agent_enrollment_requests(id,organization_id,device_id,status,approved_by)`
`agent_device_groups(id,organization_id,name)`
`agent_config_revisions(id,organization_id,device_id nullable,group_id nullable,revision,config_json,created_by)`
`agent_commands(id,organization_id,device_id,command_kind,payload_json,nonce,expires_at,status,created_by,ack_at)`
`agent_update_rollouts(id,organization_id,channel,version,cohort,status,schedule)`
`agent_heartbeats(id,organization_id,device_id,received_at,status)` — partition/TTL; raw heartbeat frequency not 1 row per second indefinitely
`agent_pairings(id,organization_id,attempt_id,device_id,grant_hash,created_at,expires_at,redeemed_at,revoked_at)`
`proctoring_sessions(id,organization_id,attempt_id,device_id,status,started_at,ended_at,policy_snapshot_json)`
`proctoring_viewers(id,organization_id,session_id,viewer_membership_id,joined_at,left_at)`
`proctoring_incidents(id,organization_id,attempt_id,device_id,event_type,severity,occurred_at,received_at,metadata_json,status,reviewed_by,reviewed_at,resolution_note,purge_after)`

## Audit / Storage / Judge
`audit_events(id,organization_id nullable,actor_user_id,actor_membership_id,action,resource_type,resource_id,request_id,created_at,outcome,reason,old_digest,new_digest,metadata_minimal)` (append-only, partitioning/retention)
`approval_requests(id,organization_id nullable,kind,requested_by,approved_by,status,expires_at,reason)`
`judge_submissions(id,organization_id,attempt_id,item_id,source_blob_ref,language,source_hash,status,created_at)`
`judge_runs(id,organization_id,submission_id,runner_version,test_suite_version,resource_usage_json,result_json,status,finished_at)`
`files(id,organization_id,blob_key,sha256,size,mime,owner,virus_scan_status,retention_at)`
`backup_catalog(id,storage_target,type,start_at,finish_at,size,status,verified_restore_at,chain_id,protected_until)`
`storage_cleanup_jobs(id,scope,requested_by,dry_run_report,approved_by,status,bytes_freed,created_at)`
`retention_policies(id,organization_id,incident_days,technical_days,audit_days,...)`

## Database invariants/constraints
- `unique(organization_id, student_membership_id, assignment_id, attempt_number)` and transactional attempt reservation.
- `CHECK` (submitted_at >= started_at) where appropriate; `CHECK` grade <= max_points, no negative points unless explicit penalty policy.
- Attempt status transitions validated in domain service and guarded by optimistic `version`/row locks.
- `question_versions` and `assessment_publications` immutable once published. Do not modify frozen reference even after bank deletion.
- No device can have two `active` proctoring sessions; DB partial unique index with status active, plus heartbeat expiry reconciliation.
- Tokens (`invites`, `enrollments`, `pairings`) stored only as hashes. Never reuse credential across organizations.
- Automatically purge expired incident partitions/records according to policy; audit purge policy separate.

### Slice C — ревизия `0006`

`ENABLE` и `FORCE ROW LEVEL SECURITY` защищают `organizations`,
`organization_memberships`, `organization_roles`, `organization_role_permissions`
и `membership_roles`. Политика API использует одинаковое условие для
`USING` и `WITH CHECK`: строка относится к текущей организации, а проверенный
субъект имеет там активное членство. Пустой или неверный контекст не допускает строки.
В этом срезе API получает SELECT. Тесты DML временно выдают дополнительные
права только на одноразовой БД и проверяют политику под ролью API.

| Роль БД | Назначение |
|---|---|
| `veriq_dev` | Локальный PostgreSQL bootstrap и миграции, отдельные учётные данные |
| `veriq_api` | Чтение tenant-таблиц под RLS и вызов проверки членства |
| `veriq_worker` | SELECT, INSERT, UPDATE очереди `background_jobs` |
| `veriq_identity_lookup` | NOLOGIN, владелец только функции проверки членства, SELECT минимального набора identity-колонок |

Ревизия не меняет существующие строки. Роли PostgreSQL общие для кластера.
При откате удаляются политики и права в этой БД. Роли могут использоваться другими
БД кластера и не удаляются. Параметры логина выдаёт процесс `migrate` после
успешного Alembic upgrade, с отдельными паролями для API и worker.

### Slice D — ревизия `0007`

Таблица `auth_sessions` хранит UUID и уникальный 32-байтный SHA-256 хеш
токена. Составной FK `(organization_id, user_id)` допускает выбор только
собственного членства. При отсутствии выбора оба поля контекста
`organization_id` и `grant_epoch` равны NULL. При проверке сессии актуальный
статус и эпоха членства сверяются с сохранёнными.

Сроки по умолчанию: привилегированные 30 минут / 8 часов, обычные 2 часа /
12 часов (idle / absolute). Настройка процесса — целое число секунд в
`VERIQ_SESSION_PRIVILEGED_IDLE_SECONDS`, `VERIQ_SESSION_PRIVILEGED_ABSOLUTE_SECONDS`,
`VERIQ_SESSION_ORDINARY_IDLE_SECONDS`, `VERIQ_SESSION_ORDINARY_ABSOLUTE_SECONDS`
или объект `SessionPolicy`. Idle обновляется только у действительной сессии.
Ротация атомарно отзывает старую строку и создаёт новую, сохраняя первоначальное
`authenticated_at` и не продлевая абсолютный предел. Смена организации
использует ротацию. Сессии не управляют временем или состоянием попытки экзамена.

`veriq_session_store` — роль NOLOGIN и владелец фиксированных функций
сессий, с точечным чтением identity-колонок и записью в `auth_sessions`.
У неё нет владения таблицами, BYPASSRLS или DELETE. Функции задают
`search_path = pg_catalog, pg_temp`, используют квалифицированные имена
и закрыты для PUBLIC. `veriq_api` может проверять, ротировать и отзывать
сессию по UUID и хешу, но не читает таблицу напрямую. Выпуск доступен
отдельной роли NOLOGIN `veriq_session_issuer`. Тесты принимают её в
одноразовой БД, production-подключение доверенного Auth будет спроектировано
отдельно. Worker не вызывает функции сессий.

Миграция не меняет существующие записи. Downgrade блокируется, если таблица
сессий непуста. Срок хранения и удаление истории сессий требуют отдельной
политики. Публичный вход, MFA и CSRF не добавлены.

## Migration sequence

1. identity, membership, organization RBAC; 2. academic; 3. banks/questions; 4. publications/assignments; 5. attempts/answers/grading; 6. agent/proctoring; 7. judge; 8. audit and backup catalogs; 9. indexes, RLS hardening. All migrations tested fresh DB and upgrade from previous revision.

Foundation 1a включает ревизию Alembic `0001` с базовыми таблицами
`organizations` и `users`. Связь с политикой хранения, memberships, роли,
разрешения и сессии добавляются отдельными ревизиями. Downgrade в `base`
удаляет обе таблицы и предназначен для проверок на одноразовой БД.

Foundation 1b добавляет ревизию `0002` с системной таблицей `background_jobs`.
В ней хранятся служебные идентификаторы, состояние и расписание повторов.
Текущая системная проба не связана с организациями. Задачи с данными
организаций потребуют собственного tenant scope и серверной авторизации.


## Auth Slice 1 — ревизия `0008`

- `users.credential_version` начинается с 1. Массовый отзыв увеличивает её под блокировкой аккаунта.
- `auth_credential_proofs` хранит UUID, SHA-256 случайного секрета, субъект, версию credentials, контекст MFA/организации и время истечения и погашения. `auth_sessions` остаётся единственным хранилищем сессий.
- `auth_audit_events` хранит UUID события, request/correlation ID, время, тип из ограниченного списка, результат и при наличии UUID actor/target. Повтор идентичного события с тем же UUID идемпотентен. Повтор UUID с другими данными отклоняется. Поля для произвольного текста или секретов отсутствуют.
- `notification_outbox` связывает одну запись с UUID события массового отзыва. Worker арендует запись через `SKIP LOCKED` на 30 секунд, подтверждает доставку действующим claim ID и может безопасно повторить подтверждение. При истечении аренды запись доступна для повтора. Будущий транспорт использует UUID события как ключ идемпотентности. Отправка писем и гарантия дедупликации у провайдера требуют отдельной интеграции.
- `veriq_credential_verifier` и `veriq_session_issuer` вызывают только свои функции подтверждения и выпуска. `veriq_session_store` владеет функциями жизненного цикла и имеет столбцовые права на изменение версии и времени погашения. `veriq_auth_events` владеет функциями аудита и outbox, имеет право вставки событий и обновления только служебных полей outbox. `veriq_api` может добавлять события попыток и отзывать действующую сессию через ограниченные функции, `veriq_worker` может брать и подтверждать уведомления. Runtime-роли не получают прямого доступа к proof, аудиту или outbox.
- Роли подтверждения и выпуска остаются `NOLOGIN`, а Compose не передаёт приложению такие credentials. Подключение доверенного verifier и provisioning его principal требуют следующего согласованного среза. Откат `0008` разрешён на пустой истории Auth. Политики срока хранения и удаления записей следует утвердить до подключения публичного Auth.
