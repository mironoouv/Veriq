# DESIGN_SYSTEM — UX и визуальная концепция

## Цель
Не использовать однотипную «нейросетевую админку». Сделать спокойный, профессиональный продукт для повседневной работы; плотность данных меняется по роли. Переиспользование компонентов, чёткая иерархия, доступность WCAG 2.2 AA target, keyboard navigation, responsive layout.

## Stack
Vue3 + TypeScript + Vite + Tailwind CSS4 + daisyUI5 + Vue I18n RU/EN, Pinia, Vue Router; date/time localize by org IANA TZ. Monaco for code, KaTeX for math, virtualized lists for 30/300 screens, dark/light supported.

## Roles / Navigation
Student: Dashboard / My assessments / Calendar / Results / Profile & Security.
Teacher: Studio / Question banks / Calendar / Assignments / Grading / Monitor / Analytics.
Org Admin: Members / Groups / Courses / Policies / Devices / Approvals / Audit/Storage scopes.
Superadmin: Organizations / System / Security events / Infrastructure / Backup/storage (no silent student answers/media).
Technician: Device groups / Enrollment / Config / Updates / Diagnostics.
Proctor: Assigned Live Monitor / Incident review.

## Key screens
- Exam Studio: sections, question order (drag-and-drop with keyboard alternative), fixed side panel for settings, preview, publish snapshot confirmation.
- Student Exam: clear timer server-derived, autosave indicator `local/syncing/confirmed/error`, question navigation, progress, responsible submit confirm, disconnection banner, agent status, screen monitoring notice.
- Programming: resizable split pane, code editor (left) and task/description/public tests/console (right), fullscreen/accessible shortcuts, no hidden tests revealed.
- Calendar: day/week/month, list of assignments, event creation separate from question editing, color-coded types not sole semantic signal.
- Live Monitor: grid of mini screens, selected stream fullscreen, per-student status, incidents and teacher controls, no screenshot/download controls.
- Agent Admin: devices inventory, filters, enrollment approval, policy editor inheritance, rollout pilot view, storage dashboard/dry-run cleanup.

## Screen references
Four screenshots provided during planning are functional inspirations (schedule week view, event card/create form, code split-pane). Do not copy brand assets or pixel-for-pixel layout. The archive does **not** embed private screenshots; refer to user originals in chat or add with permission.

## Design tokens (starting proposal, not approved brand assets)
Spacing scale 4/8/12/16/24/32; radii 6–12px; focus 2px, accessible contrast, icons Lucide; typography Inter/system sans as candidate; use no typography assets in archive. Palette to be finalized with real visual review.

## UX acceptance
On first-time student exam preflight, missing agent diagnosis actionable; on outage, answer-save state never falsely says “saved”; every dangerous admin operation has clear scope, dry-run and reversible or reasoned irreversible confirmation. Russian labels native quality, English translation parity tests.
