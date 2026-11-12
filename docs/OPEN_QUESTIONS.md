# OPEN_QUESTIONS — не блокируют написание ТЗ, блокируют некоторые реализации

| # | Вопрос/риск | Рекомендуемое действие | Когда принять |
|---|---|---|---|
| OQ-01 | Windows OS editions/builds и браузеры в аудиториях | матрица поддерживаемых Win10/11 + Edge/Chrome + LNA/URL protocol PoC | до Agent implementation |
| OQ-02 | Удалённый экзамен на личных устройствах vs только lab | v1 оптимизировать для lab, расширяемость учесть | до UX permission flow |
| OQ-03 | LiveKit .NET screen publisher viability | прототип WGC → encoder → WebRTC, TURN | до фиксации media tech |
| OQ-04 | Judge sandbox platform (microVM/gVisor/изоляция VM) | threat test; benchmark на отдельном хосте | до запуска student code |
| OQ-05 | Список языков и версии компиляторов | Python/C++/C# target, confirm release test hardware | до Studio code tasks |
| OQ-06 | Object storage local vs external S3 | choose retention, backups, scans and credentials | до uploads |
| OQ-07 | Backup hardware/remote storage capacity | sizing + restore tests, pgBackRest PoC | до production |
| OQ-08 | Student data legal basis, student ages, institution jurisdiction, retention limits | legal review and notices | до real deployment |
| OQ-09 | SSO/OIDC/LDAP интеграции | roadmap after basic auth unless institutions require | during pilot |
| OQ-10 | Строгий Windows режим | MS Assigned Access/MDM supported conditions; no unsupported OS restrictions promise | before Strict release |
| OQ-11 | UX visual identity/logo and theme | iterative design review, no auto-template aesthetics | before UI freeze |
| OQ-12 | SMTP provider and domain DNS/TLS | config separate environment, verify delivery | before beta |
| OQ-13 | Backups for shared storage per tenant | separate global vs tenant admin privileges | before backup UI |
| OQ-14 | Per-organization exact retention numbers | chosen by tenant admin within lawful min/max bounds | on onboarding |

**Policy:** Agent must not guess OQ answers in production code. Either implement safe capability flag, propose ADR, or create isolated PoC; do not quietly narrow requirements.
