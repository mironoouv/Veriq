# DEPLOYMENT — Windows Docker → Linux server

## Dev
Windows 11 + Docker Desktop Linux containers. Prefer project files inside WSL2 Linux filesystem where supported for bind performance. `.env.example` only template; copy to `.env` ignored by git, generate random passwords locally. Agent itself is a Windows app (not containerized). On dev host use local HTTPS staging domain for loopback pairing tests, browser Chrome/Edge permissions tested.

## Compose topology (design; compose files to be created by development agent)
`nginx`, `api`, `postgres`, `redis`, `worker`, `frontend-build/static`, `object-storage` candidate, `media/livekit` candidate (dedicated network ports), `judge-scheduler` (not sandbox executor), `metrics`, `backup-manager` with least privilege. Never mount Docker socket in API/Judge. Secrets/production DB not mounted into malicious code executor.

## Networking
Browser HTTPS to Nginx at `veriq.void-rp.ru`; API/websocket via same origin to avoid unnecessary CORS. WebRTC SFU typically needs public address UDP port-range or UDP mux + TURN; TLS reverse proxy alone insufficient. Separate media DNS if needed, firewall allowlist admin endpoints, TURN credential rotation. Do not assume Docker bridge NAT works from all student PCs.

## Linux production
- Pin images by digest/release, separate named volumes/storage; health/readiness probes.
- Postgres private network, backup repo isolated, Redis no public bind, no direct Judge prod network.
- Let's Encrypt / ACME certificate issuance and renewal at Nginx / edge. HTTP→HTTPS, HSTS after validation, secure headers, rate limits, body size limits and WebSocket timeouts.
- Observability: Prometheus/OpenTelemetry candidate for metrics, structured logs with request_id, disk/backup alerts, judge and agent SLO.
- Deployment: database snapshot/backup, migration checks, expand/contract, rollout with smoke tests and rollback plan.

## Nginx notes
Forward `Upgrade` headers for WebSocket, proper proxy timeouts, keepalive, request size for uploads, error handling. SFU UDP/TURN bypasses ordinary Nginx HTTP path and must be exposed separately.

## Production operational checks
- Verify SMTP for registration/2FA recovery, malware scan uploads, object storage rights/retention, agent MSI signing, cron/worker retention health.
- Real performance tests on 30 clients and exercises for large files/timeout.
- Security/legal review before handling real student records.
