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
