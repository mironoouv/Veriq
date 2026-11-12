# AI DEVELOPMENT CONTRACT — VERIQ

You are implementing a multi-tenant, exam-critical security-sensitive platform. Read `README.md`, `docs/DECISIONS.md`, `docs/VERIQ_SPEC.md`, `docs/SECURITY.md`, `docs/OPEN_QUESTIONS.md`, `planning/ROADMAP.md` **before coding**.

## Non-negotiable rules
1. Do not reinterpret APPROVED requirements. For contradictions propose ADR and flag rather than quietly change.
2. Implement in small, reviewable vertical slices with migrations, automated tests, documentation, and negative cases.
3. Every DB/API read and write must be tenant/role/resource authorized. No frontend-only security.
4. Backend owns time/grades/attempt state. Client holds only pending local drafts.
5. Do not run student code/SQL on API host or production DB, not even for MVP.
6. Never record live screens, take snapshots, or leave capture active outside exam sessions.
7. Windows agent: install once; no student login; controlled backend pairing; no generic remote shell.
8. Backups: never rm WAL directly, no blind delete, test restore, preserve chain. RPO/RTO are measured goals.
9. Use package locks/pinned runtime/explicit environments; don't install random packages without checking compatibility/licensing.
10. No claims of tests passing without actually executing them; report missing Windows/remote tests separately.

## Work protocol
- At start: cite relevant spec sections, acceptance IDs, implementation plan and risks.
- At finish: show diff summary, migrations, tests/results, screenshot of mock UI only if requested, security notes, remaining work.
- Follow OpenAPI schemas, type safe TS, strong Python typing, deterministic domain services, .NET idiomatic safe patterns.
- Commit logically; no sweeping refactor without explicit architectural approval.
- External libraries and current docs must be verified; no silent generated production secrets.

## Definition of done
Relevant acceptance tests from `docs/ACCEPTANCE.md` pass, docs and migrations updated, no cross-tenant gaps, all logs redacted, feature works with real backing services, recovery behaviors documented.
