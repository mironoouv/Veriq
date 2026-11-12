$ErrorActionPreference = 'Stop'
$project = 'veriq-prod-smoke'
$env:COMPOSE_PROJECT_NAME = $project
if (-not $env:VERIQ_PROD_WEB_PORT) { $env:VERIQ_PROD_WEB_PORT = '18080' }
$composeFiles = @('-f', 'compose.yaml', '-f', 'compose.prod.yaml')
$credentialFile = '.cache/production-smoke-password'

function Compose {
    docker compose @composeFiles @args
    if ($LASTEXITCODE) { throw 'Production Compose failed' }
}

function New-SmokePassword {
    $password = python -c 'import secrets; print(secrets.token_hex(32))'
    if ($LASTEXITCODE -or -not $password) { throw 'Password generation failed' }
    return $password
}

if (-not (Test-Path -LiteralPath $credentialFile)) {
    $volumes = docker volume ls --format '{{.Name}}'
    if ($LASTEXITCODE) { throw 'Cannot inspect Docker volumes' }
    if ($volumes -contains "${project}_postgres-data") {
        throw 'Existing smoke volume requires its original password file.'
    }
    New-Item -ItemType Directory -Force .cache | Out-Null
    Set-Content -LiteralPath $credentialFile -Value (New-SmokePassword) -Encoding ascii
}
$env:VERIQ_DB_PASSWORD = (Get-Content -LiteralPath $credentialFile -Raw).Trim()
$env:VERIQ_API_DB_PASSWORD = New-SmokePassword
$env:VERIQ_WORKER_DB_PASSWORD = New-SmokePassword

if (Compose ps -aq) { throw 'The dedicated production smoke project already has containers.' }
Compose config --quiet
try {
    Compose up --build --wait --wait-timeout 120
    Compose run --no-deps --rm -T migrate alembic current --check-heads
    npm.cmd --prefix apps/web run test:e2e
    if ($LASTEXITCODE) { throw 'Browser smoke failed' }
    Compose up --wait --wait-timeout 90
    python tests/production_checks.py
    if ($LASTEXITCODE) { throw 'Production safety checks failed' }
} finally {
    Compose down
}
