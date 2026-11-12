# SECURITY — Veriq Security Design

## Identity
- Argon2id calibrated, password breach blocking, email verification, brute-force IP/account rate limits, privacy-preserving auth error messages.
- MFA mandatory for Superadmin, Org Admin, Technician; optional/policy mandatory for Teacher/Proctor/Student. Highest required assurance applies to users with multiple roles.
- TOTP + single-use recovery codes; WebAuthn/passkeys recommended after PoC. Encrypt TOTP seed at rest with managed key; recovery codes store salted one-way hash only.
- Recovery: codes OR independently verified recovery, audit, cooldown, separate approver for privileged roles; **no self-approval**. Revoke relevant sessions and factor enrollments; strong step-up on sensitive operations.
- Browser sessions: secure/httpOnly/sameSite cookies, CSRF, rotation, idle+absolute TTL, revoke all, list active devices, multi-tab attempt lease independent of login session.

## Tenant isolation
- Membership required, scope never derived from arbitrary client-provided org; choose tenant after server membership verification.
- Authorization: permission + org + resource relationship + action-specific policy, server side. Superadmin has infrastructure management, not silent universal answer/screen access; exceptional break-glass audited, time limited, approved where possible.
- Deny by default; RLS/tenant composite FK; automated cross-tenant IDOR tests for all CRUD/websocket/media endpoints, including attachments.
- Slice B stores platform and organization grants separately. A Superadmin assignment alone yields no organization permissions. Internal grant readers check live membership state and expect an already verified subject. Resource authorization remains a separate check. Slice B exposes no public or user-context role writer. A future writer must reject self-elevation and verify the actor, target, scope, step-up and audit before exposure.
- PostgreSQL advances the membership grant epoch when status becomes revoked. Assignment and revocation serialize on the membership row. Current reads require matching epochs, so reactivation requires explicit new assignments. Suspension keeps the epoch and allows restoration on activation. An authorization check must use a current database snapshot. Previous results, including those from an already open snapshot, must not be reused across requests.

### Tenant transaction boundary (Slice C)

The future authentication layer supplies a verified subject. A requested
organization ID is a selector. The server checks the account, organization
and membership before setting the user and organization with
`set_config(..., true)` in the same transaction. Commit and rollback clear
the local settings. Resource policies require a current tenant permission and
can additionally require ownership of a resource loaded by a trusted repository.
Platform grants are excluded from this path. Current database reads recheck
membership status and assignment epoch.

`public.veriq_active_membership(uuid, text)` returns only a boolean for an
explicit account and organization. It is owned by `veriq_identity_lookup`,
a NOLOGIN role with column-level reads and dedicated SELECT policies for the
two scoped tables. It has no table ownership, write grants or BYPASSRLS.
The function uses qualified table names, a fixed `pg_catalog, pg_temp`
search path and no dynamic SQL. PUBLIC execution is revoked, and only API
receives EXECUTE among runtime roles. An API database credential can query the
boolean and set its own PostgreSQL settings. This boundary assumes trusted API
SQL and server-verified subjects. It cannot defend against arbitrary SQL
execution with that credential. Public session resolution is deferred.

Use short transactions at READ COMMITTED for request authorization. RLS uses the
statement's PostgreSQL snapshot. It cannot retract rows already returned or see
a revocation committed after that snapshot. REPEATABLE READ and SERIALIZABLE can
retain older visibility across statements. Never carry a connection, tenant
scope, or authorization decision across requests. `VerifiedSubject` is only a
server-side contract. Its constructor does not authenticate anyone, and request
payloads must never be deserialized into it.

### Session foundation (Slice D)

The internal issuer accepts identity and assurance from trusted authentication.
The login used by API cannot issue sessions. No HTTP auth routes, cookie adapter
or MFA challenge handler exist in this slice. Future browser integration must
use Secure, HttpOnly and appropriate SameSite cookies, CSRF protection on
state-changing requests, and origin checks. Step-up must establish a new trusted
assurance before issuing a replacement session. The client cannot set MFA level
or pass its own subject.

A token consists of a UUID and a 256-bit random secret. Only its SHA-256 digest
and metadata are stored. Never put the bearer in a URL, logs or trace attributes.
Resolve under READ COMMITTED and use the same short transaction for tenant
access. Authorization checks session eligibility and effective grants in a
single statement. The stored tenant and grant epoch bind the token to its
selection. Revoking membership invalidates that selection even after reactivation.
Disabled accounts and inactive memberships are refused on current reads.
Account-disable workflows in Auth must also revoke sessions before re-enabling
an account if old global sessions should stay invalid.

The selected organization determines whether Org Admin or Technician requires
MFA and shorter lifetimes. Platform Superadmin requires MFA independently of
tenant selection and gets no implicit tenant grants. The row lock serializes
touch, single revoke and rotation. An account-level transaction advisory lock
orders issue, rotation and revoke-all. An already running request can finish
before a competing revocation obtains its lock. Recheck at each request and
do not keep transactions open for streams or interactive exam work.

## Agent security
- Agent service has device identity; initial deployment token limited to org, TTL and quota, admin approval. Key generated per device; protect at rest (Windows machine key store/DPAPI) and pin server trust with ordinary certificate validation, no bypass TLS.
- C# desktop in user session, service in Session 0, restricted named pipe ACL. Stop capture on logout/end. No keylogging, covert capture, arbitrary remote code execution, personal file scraping.
- Local browser bridge only loopback; check Origin exact allowlist and Host; restrict CORS; nonce + short-lived grant, anti-replay; no elevated local HTTP handler; rate limit. Test Chrome LNA permissions and custom protocol activation in supported Edge/Chrome.
- Command allowlist and schema validation, TTL, admin scope, agent-side validation, audit; no PowerShell shell command injection. Signed updates and rollback.

## Media / privacy
- Capture only on exam approved session with visible indicator, information notice to students; live-only media, no recording, archive, screenshots, snapshots or logs storing frames. Media access requires tenant-scoped authorization and explicit active exam; tokens expire quickly and are revoked on completion.
- Audit viewer join/leave. Monitor operator with screen capture software cannot technically be prevented from external recording: organizational policy/training required.
- Protect incidental personal data visible on screen; transparency, least privilege, access logs and retention. Legal basis/notice and student/employee privacy requirements require jurisdiction-specific counsel before production.

## Judge security
- Untrusted code must never run inside API or same trust domain as prod secret stores, DB, Docker socket. Dedicated isolated host/VM/sandbox with no external network, no privileged mode, CPU/memory/process/time/IO/output restrictions, immutable test fixture, distinct SQL instance. Test hostile workloads.

## Audit
- Append-only account/grade/org/device/command/media/approval logs; no secrets or video frames. Partitioned retention with non-modifiable integrity digest or external WORM stream. Distinguish failed access and successful actions.
- Alerts for privilege elevation, mass data export, recovery, backup deletion, many device enrollment attempts; operations that mutate a user's role or audit config require step-up and approvals.
- Separate TTL for incidents, audit, student results. Retention policy changes logged and future/enforced purge jobs; delete from backups per documented lifecycle, no resurrection without re-running purge.

## Threat scenarios & mitigations
| Threat | Main control | Test |
|---|---|---|
| Student modifies JS timer | server deadline | skew clock 1 day |
| Two attempts concurrently | transactional uniqueness | parallel 50 starts |
| Other organization ID access | tenant scope/RLS | swap UUIDs |
| Forged agent on localhost | one-time grant + device proof | replay/evil origin |
| Stolen proctor media token | narrow scope/TTL/active revoke | revoke while watching |
| Hidden grader tests exposed | store only server-side | browser network inspection |
| SQL jailbreak from answer | ephemeral DB/low privileges | DDL/DML/connect escape |
| Sandbox mining/fork bomb | strong isolation/cgroups/timeouts | malicious test corpus |
| Backup deletion impacts PITR | chain dependency guard | deny last backup/WAL deletion |
| MFA admin recovery abuse | approval step-up/audit | self-request and self-approve |

## Security gate
Threat model + SAST/DAST/dependency and image scan, secret scan, pentest scope, preprod restores, kill-session revocation, unauthorized monitor access checks, tested telemetry sanitization. Any unresolved critical risk blocks production.


## Auth Slice 1 — граница выпуска сессий

Внутренний verifier после проверки учётных данных и нужного MFA передаёт в PostgreSQL подтверждение с версией credentials, assurance и выбранной организацией. Он хранит случайный секрет подтверждения только в памяти. База хранит SHA-256, проверяет версию и принимает подтверждение в течение 60 секунд. Отдельный issuer погашает его через `Sessions.issue`. Выпуск по одному UUID аккаунта закрыт на уровне SQL. Успешное погашение, выпуск и запись аудита входят в одну транзакцию. Текущие правила выбора организации, MFA, RLS и `grant_epoch` проверяются существующим механизмом сессий.

Выпуск, ротация и массовый отзыв используют одну транзакционную advisory-блокировку аккаунта перед блокировками записей сессий. Выпуск блокирует строку подтверждения после блокировки аккаунта. Массовый отзыв увеличивает `credential_version`, инвалидируя старые подтверждения. Будущие смена и сброс пароля и отключение аккаунта должны брать ту же блокировку, менять версию и отзывать сессии в одной транзакции. Функции работают с ограниченным `search_path` и квалифицированными именами таблиц.

Лимитер Auth использует Redis Lua для проверки и увеличения счётчиков IP и нормализованного идентификатора в одном фиксированном окне. Вызывающий код задаёт бюджет и TTL отдельно для каждой категории и передаёт идентификатор из того же нормализатора, что используется при поиске аккаунта. Лимитер сам к аккаунтам не обращается. IP и идентификатор хешируются HMAC-SHA-256 с отдельным ключом, который хранится вне репозитория. Переполнение даёт `429` с округлённым вверх `Retry-After`. При отказе Redis чувствительные операции получают `503`. Проверка действующих сессий и обработка экзаменационных запросов находятся вне этой границы.

По умолчанию берётся адрес непосредственного соединения. Uvicorn сохраняет адрес сокета, а Nginx перезаписывает `X-Forwarded-For` адресом своего клиента. Будущий HTTP-адаптер должен принимать один forwarded IP только от настроенного прокси, который контролирует этот заголовок. Прямой клиент и прокси вне доверенных CIDR не могут выбрать IP для лимита. До публичного запуска требуется настроить доверенную сеть edge и определить бюджеты, нормализатор и ротацию ключа HMAC.


## Auth Slice 2 — регистрация

Поддерживаются ASCII dot-atom адреса с DNS-доменом. Канонизация удаляет ASCII-пробелы и табуляции по краям, переводит обе части в нижний регистр и сохраняет точки и `+` в локальной части. Адреса SMTPUTF8 и quoted local parts отклоняются, Punycode допускается. Этот контракт предполагает регистронезависимые локальные части. Перед расширением поддержки проверьте политику почтовых провайдеров и существующие адреса.

Пароли нормализуются NFC и проверяются по длине 15–128 символов. Проверка блоклиста использует локальный файл SHA-256 от NFC UTF-8 для распространённых и скомпрометированных значений. При пустом или некорректном списке тестовые маршруты не запускаются. Пароли и хеши паролей не передаются стороннему сервису. В production потребуется согласовать источник, покрытие и обновление списка. Argon2id использует второй профиль RFC 9106 — 64 МиБ, три прохода, четыре линии, 16 байт соли и 32 байта результата. Для тестового HTTP-процесса одновременно работают максимум два хеширования. [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html) · [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html)

Письмо даёт право подтвердить только адрес. Владелец почтового ящика при подтверждении задаёт окончательный пароль, чтобы пароль заранее инициировавшего регистрацию не стал действующим. Регистрация, resend и verify не создают сессию и не дают assurance MFA. API принимает только поля OpenAPI, а сообщения валидации не включают присланные значения. События аудита содержат UUID и результат без email и секретов. Тестовый адаптер использует непосредственный IP и игнорирует forwarded-заголовки.

Конверт шифруется Fernet, срок расшифровки 30 минут. Ключ доступен только тестовым API и worker. PostgreSQL хранит хеш proof и отдельно шифротекст. Изолированная страница не подключает аналитику, ограничивает CSP, убирает фрагмент из истории и выставляет `Referrer-Policy: no-referrer`. [Fernet](https://cryptography.io/en/stable/fernet/)


## Auth Slice 3 — браузерный вход

Вход использует канонизацию Slice 2, точечный поиск кандидата и Argon2id. Для отсутствующего, отключённого, неподтверждённого или неподдерживаемого хеша выполняется проверка случайного Argon2id-хеша того же профиля. HTTP-ошибка едина. Для production требуется измерение распределения таймингов на целевой инфраструктуре. Известные утечки при регистрации по-прежнему проверяются по локальному блоклисту. Источник, покрытие и обновление списка требуют production-политики.

Парольный verifier создаёт только primary proof после проверки пароля. Issuer использует существующий Sessions. Парольный вход Superadmin и вход в организацию с действующей ролью Org Admin или Technician запрещены. Сессия без выбора организации не предоставляет tenant-доступа. Настраиваемая MFA-политика организации и второй фактор остаются в Slice 4.

Обе cookie имеют префикс `__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax` и `Path=/`. CSRF использует HMAC nonce и текущего сессионного значения, сверяет точный Origin и требует HTTPS. Токен CSRF живёт в памяти клиента, сессия передаётся только cookie. Повторное использование старой cookie после ротации или logout блокирует PostgreSQL. [OWASP CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)


### Проверка и обновление Argon2id

Текущий профиль остаётся 64 МиБ, три прохода и четыре линии. Перед вызовом Argon2 проверяются формат PHC, длина записи, Argon2id v19, размеры соли и результата, память до 64 МиБ, до четырёх проходов и четырёх линий и суммарный предел `memory_cost × time_cost ≤ 196608` КиБ-проходов. Неподдерживаемые и повреждённые записи используют проверку dummy-хеша. Поддерживаемый старый профиль проверяется как сохранён. После успешной проверки пароля новый хеш записывается только при совпадении прежнего хеша и `credential_version`. Изменение credentials, выигравшее гонку, блокирует запись и выпуск proof. Rehash сам по себе не меняет пароль или его версию.

Успешное подтверждение пароля записывает `password_verified: succeeded` вместе с proof. Выпуск добавляет `session_issued: succeeded` вместе с записью сессии. Если пароль подтверждён, но для выбранной области требуется второй фактор, вместо события выпуска добавляется `login_mfa_required: denied`. HTTP-ответ остаётся общим `401`. Остальные отказы проверки credentials используют `login_attempt: denied`. Ротация записывает `session_rotated: succeeded` только в транзакции успешной замены. Фазы одного запроса используют одинаковые request/correlation ID. Предварительные отклонения по формату, CSRF, лимитам или загрузке не создают записи об успешной проверке. Payload аудита не содержит пароль, PHC, proof, cookie или токен.


## Auth Slice 4 — MFA и step-up

TOTP использует HMAC-SHA-1, шесть цифр и шаг 30 секунд. Принимаются текущий и предыдущий шаг. Последний принятый счётчик хранится в PostgreSQL и увеличивается под блокировкой фактора. Секрет — 20 случайных байт. Он хранится как AES-256-GCM ciphertext с 96-битным nonce. AAD связывает шифротекст с аккаунтом, фактором и ID ключа. Десять резервных кодов генерируются с энтропией 192 бита каждый, показываются один раз после активации и хранятся как SHA-256 с отдельной случайной солью. Резервный код используется только для входа. [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238.html)

В тестовом окружении оператор подтверждает личность получателя вне приложения и создаёт ожидающий фактор через закрытую команду. После проверки пароля браузер получает трёхминутный challenge в отдельной HttpOnly cookie. Challenge не даёт tenant-доступа. Первый действительный TOTP подтверждает фактор. Активный фактор нельзя заменить через enrollment. Для отключения требуется свежий TOTP step-up назначения `factor_disable`. Действующая обязательная политика в любой организации или платформенная роль блокирует отключение. Независимое восстановление привилегированного фактора и passkeys остаются отдельными задачами.

Сессии проходят максимальное требование из платформенной роли, действующих ролей выбранной организации и её политики. Активный фактор также требует MFA при входе независимо от выбранной области. Переход на более строгую область проверяется существующим Sessions под актуальным `grant_epoch`. Step-up связан с текущим токеном, аккаунтом, областью и назначением. Погашение атомарно вращает сессию и устанавливает свежесть на пять минут без продления абсолютного срока. Последующий переход между областями требует нового step-up для чувствительной операции. Для `factor_disable` и `sensitive` используются разные назначения.

MFA POST проверяют HTTPS, точный Origin и CSRF, привязанный к nonce, сессии и challenge. Redis ограничивает MFA по IP и HMAC от серверного идентификатора аккаунта. При отказе Redis MFA закрывается, действующие сессии продолжают проверяться. В аудит пишется результат, request/correlation ID и разрешённые UUID. TOTP, резервные коды, cookie и ключи отсутствуют в аудите, outbox и артефактах.


## Auth Slice 5 — смена и сброс пароля

Смена требует действующую сессию, текущий пароль и новый пароль по политике регистрации. Сравниваются NFC-значения, поэтому эквивалентная запись текущего пароля отклоняется. Для аккаунтов и областей с обязательной MFA нужен TOTP step-up назначения `password_change` со сроком пять минут. Активный фактор также делает эту проверку обязательной. Общая свежесть `sensitive` и свежесть отключения фактора для смены пароля не подходят. База повторно проверяет сессию, grant epoch, хеш, версию credentials и step-up под блокировкой аккаунта.

Reset использует подтверждённый email и отдельный proof с 256-битным случайным секретом, сроком 30 минут и привязкой к адресу, назначению и версии credentials. Действующая ссылка сохраняет исходный TTL при повторных запросах. Лимиты запроса и подтверждения разделены. GET не меняет состояние, а страница удаляет фрагмент из адресной строки, передаёт proof только в JSON POST, использует CSP без внешних ресурсов, `no-referrer` и `no-store`. Изменяющие запросы требуют точного Origin и CSRF. Reset не выдаёт сессию или assurance и сохраняет факторы, резервные коды и обязательную MFA. После изменения credentials требуется новый вход.

Операторское первичное MFA enrollment остаётся тестовым и требует внешней проверки личности. Старые ключи остаются доступны для чтения до перешифрования всех факторов и согласования хранения резервных копий. Step-up проверяется конкретной чувствительной операцией и не переносится на другой токен или назначение. Независимое восстановление MFA по ADR-015 остаётся отдельным этапом.

Проект независимого восстановления описан в [Auth Slice 6 (PROPOSED)](../planning/AUTH_MFA_RECOVERY.md). Password reset сохраняет обязательную MFA и сам по себе не восстанавливает и не отключает фактор.
