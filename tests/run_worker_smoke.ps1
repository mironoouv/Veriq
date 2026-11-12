$ErrorActionPreference = 'Stop'
$project = 'veriq-worker-smoke-local'
$env:COMPOSE_PROJECT_NAME = $project
$env:VERIQ_WEB_PORT = '15174'
$composeFiles = @('-f', 'compose.yaml', '-f', 'compose.dev.yaml')
$credentialFile = '.cache/worker-smoke-password'

function Compose {
    docker compose @composeFiles @args
    if ($LASTEXITCODE) { throw 'Docker Compose failed' }
}

if (-not (Test-Path -LiteralPath $credentialFile)) {
    $volumes = docker volume ls --format '{{.Name}}'
    if ($LASTEXITCODE) { throw 'Cannot inspect Docker volumes' }
    if ($volumes -contains "${project}_postgres-data") {
        throw 'Existing smoke volume requires its original password file.'
    }
    $password = python -c 'import secrets; print(secrets.token_hex(32))'
    if ($LASTEXITCODE -or -not $password) { throw 'Password generation failed' }
    New-Item -ItemType Directory -Force .cache | Out-Null
    Set-Content -LiteralPath $credentialFile -Value $password -Encoding ascii
}
$env:VERIQ_DB_PASSWORD = (Get-Content -LiteralPath $credentialFile -Raw).Trim()
foreach ($name in 'VERIQ_API_DB_PASSWORD', 'VERIQ_WORKER_DB_PASSWORD') {
    $password = python -c 'import secrets; print(secrets.token_hex(32))'
    if ($LASTEXITCODE -or -not $password) { throw 'Runtime password generation failed' }
    Set-Item "Env:$name" $password
}
if (Compose ps -aq) { throw 'The dedicated smoke project already has containers.' }
Compose config --quiet
try {
    Compose up --build --wait --wait-timeout 120
    Compose ps -a
    Compose run --no-deps --rm -T migrate alembic current --check-heads
    python tests/memberships_smoke.py
    if ($LASTEXITCODE) { throw 'Identity and tenant smoke failed' }
    python tests/smoke.py
    if ($LASTEXITCODE) { throw 'API smoke failed' }
    python tests/worker_smoke.py
    if ($LASTEXITCODE) { throw 'Worker smoke failed' }
    $countSql = "SELECT count(*) FROM background_jobs WHERE status = 'succeeded'"
    $before = Compose exec -T postgres psql -U veriq_dev -d veriq -v ON_ERROR_STOP=1 -Atc $countSql
    if ([int]$before -lt 1) { throw 'Expected completed smoke jobs before restart' }
    Compose down
    Compose up --wait --wait-timeout 90
    $after = Compose exec -T postgres psql -U veriq_dev -d veriq -v ON_ERROR_STOP=1 -Atc $countSql
    if ($before -ne $after) { throw 'Completed jobs did not survive Compose down/up' }
    Write-Output "PostgreSQL persistence verified ($after completed jobs)."
} finally {
    Compose down
}
