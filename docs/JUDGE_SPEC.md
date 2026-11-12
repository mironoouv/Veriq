# JUDGE_SPEC — безопасный Veriq Judge

## Responsibility
Code and SQL tasks are core v1 features, not optional add-on. FastAPI only accepts/queues submissions and retrieves results. A separately isolated judge environment performs compile/run and scores tests. Never `subprocess` arbitrary student code in FastAPI/container sharing app secrets.

## Judge workers
Separate scheduler/queue, executor supervisor on distinct VM/host, per-run jail or microVM (select via security PoC); cgroups CPU/memory/PIDs, wall time kill, disk/FD/output caps, no outbound network, no host mounts, no Docker socket, no root/privileged, seccomp/AppArmor, immutable base image, ephemeral tmp dir deleted after run.
- Language versions pinned for reproducibility and shown to student. Start Python 3, C++ compiler, C# .NET SDK where measured; support language packages curated, no package installation from Internet during run.
- Input: `job_id`, source ref, task version/hash, compiler profile, test suite version, limits. Output: verdict, per-public-test hints, numeric points, resource usage, limited compiler stdout/stderr; hidden tests never exported to student.
- Status `queued/running/completed/compiler_error/time_limit/memory_limit/runtime_error/system_error/canceled`. Retry infrastructure errors with dedupe, never retry infinite loops without max budget.

## Code grading
Compile if needed, execute public/hidden test cases independently, normalize output only according to task policy, compare with expected or custom checker sandboxed. partial points deterministic, preserve score revisions. Avoid leaked hidden test input in diagnostics; no stdout leak across students.

## SQL grading
Use ephemeral **independent** PostgreSQL instance/database per task attempt, never production DB. Restrict role, prohibit extensions/server-side files, external connections, superuser, CREATE ROLE, COPY PROGRAM, FDW; max query time/statement timeout, row/output limits, schema quotas. Load fixture snapshot with test role, run student query in isolated instance and compare canonical result with expected based on task semantics: order-sensitive only when ORDER BY requirement, floating point tolerance configurable, NULL handling, duplicate rows, column/type interpretation.
For DDL/DML tasks compare state transitions inside sandbox, reset fixture per test. One database per worker instance might be insufficient isolation: dedicated VM/container and role+schema with disposable instance; run hostile SQL tests to prove boundary.

## Security/test corpus
Infinite loops, fork bomb, memory blow, huge output, compiler flags abuse, directory traversal, symlink, requests to `169.254.169.254`, DNS exfiltration, filesystem read, Docker socket, PostgreSQL extensions, COPY, pg_read_file, temp-table spam, transaction lock, deadlocks, extremely deep query. Expected all terminate within limits with no data leaked and no damage outside sandbox.

## Acceptance
- Correct answers graded reproducibly across 100 retries.
- Wrong/hostile code returns bounded verdict and no host resource leak.
- Disabled network verified at packet level on isolated runner.
- Judge failure never corrupts attempt or forces a 0 automatically; status `pending/system_error`, support retry/manual review.
