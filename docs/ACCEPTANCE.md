# ACCEPTANCE — requirements traceability

| ID | Проверяемое требование | Проверка |
|---|---|---|
| AUTH-01 | Можно саморегистрироваться и вступить по приглашению/коду/заявке | API+E2E |
| AUTH-02 | MFA принудительная для super/orgadmin/technician | E2E+negative |
| AUTH-03 | MFA recovery через коды либо independent verified flow, audit | E2E+security |
| TEN-01 | Нет cross-tenant доступа на данных/API/media | negative matrix |
| STU-01 | Личные и общие банки, ACL, версии | integration |
| STU-02 | 8 обязательных настроек доступны и применяются сервером | E2E |
| SCH-01 | Назначение календарём и списком использует одну assignment запись | integration |
| EXM-01 | Одна управляющая сессия, свободная навигация, teacher pause | concurrency E2E |
| EXM-02 | Серверный дедлайн, идемпотентный submit, контроль числа попыток | race tests |
| EXM-03 | Strict/limited offline policy корректно применена | network chaos |
| EXM-04 | Ответы подтверждаются server revision, восстанавливаются | crash E2E |
| GRD-01 | Баллы/%/5-балл/зачёт и ручная оценка корректны | boundary tests |
| JUD-01 | Код и SQL исполняются исключительно изолированно | hostile corpus |
| AGT-01 | Агент устанавливается разово без student login | Windows lab |
| AGT-02 | Ручной/массовый enroll + admin approval | end-to-end |
| AGT-03 | Browser pairing one-time, no replay/cross-tenant | security |
| AGT-04 | Central configs, signed updates, no update during exam | Windows lab |
| PRO-01 | Basic/Standard/Strict profiles + override allowed only within org | policy tests |
| PRO-02 | Configurable reactions + human review ambiguous incidents | workflow |
| PRO-03 | Live viewing only; no recording/screenshot/archive, end stops media | media audit |
| PRO-04 | Incident retention per org auto-purge | worker tests |
| AUD-01 | Critical admin actions, grade, viewer access append-only audited | logs tests |
| BAK-01 | WAL and independent recovery chain, restore target measured | restore drill |
| BAK-02 | Storage view + safe dry-run cleanup prevents broken PITR | destructive tests |
| PERF-01 | 30 concurrent monitored exams stable | perf report |
