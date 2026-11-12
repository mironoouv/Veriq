# ADR-009 — Proctoring profiles and overrides

**Status:** APPROVED (product); implementation NOT YET COMPLETED. **Date:** 2026-11-12.

## Decision
Basic/Standard/Strict, overrides limited by organization policy.

## Rationale
The owner selected this behavior after discussing Veriq v1.0 workflows. Enforce at backend/device where applicable, preserve organization isolation, audit changes and test failure paths.

## Acceptance
The corresponding items in `docs/ACCEPTANCE.md` and `docs/TESTING.md` must pass before production.

## Notes
Technical provider/library selection is not implicit approval; see `docs/OPEN_QUESTIONS.md`.
