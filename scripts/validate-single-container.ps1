param([switch]$TabOnly)
$ErrorActionPreference = 'Stop'
$repository = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
# Dokploy discovers services before resolving Compose includes.
if ([IO.File]::ReadAllText((Join-Path $repository 'compose.dokploy.yaml')) -ne
    [IO.File]::ReadAllText((Join-Path $repository 'docker-compose.yml'))) {
  throw 'Both Dokploy Compose entry points must contain the same direct service definitions.'
}
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$scratch = Join-Path $tempRoot ("iqkb-single-" + [Guid]::NewGuid().ToString('N'))
$project = "iqkb-single-" + [Guid]::NewGuid().ToString('N').Substring(0,12)
New-Item -ItemType Directory -Path $scratch | Out-Null
$composePath = Join-Path $scratch 'compose.yaml'
function Invoke-Compose {
  & rtk proxy docker compose -p $project -f $composePath @args
  if ($LASTEXITCODE -ne 0) { throw 'Disposable single-container Compose command failed.' }
}
function Wait-Healthy {
  for ($attempt = 0; $attempt -lt 60; $attempt++) {
    $health = & rtk proxy docker inspect --format '{{.State.Health.Status}}' $script:container
    if ($LASTEXITCODE -eq 0 -and $health.Trim() -eq 'healthy') { return }
    Start-Sleep -Milliseconds 500
  }
  Invoke-Compose logs --tail 30
  throw 'Single container did not become healthy.'
}
try {
  $dummyEnv = @'
PUBLIC_ORIGIN=https://teams-assistant.example.test
TENANT_ID=12345678-1234-4234-9234-123456789abc
ADMIN_OBJECT_ID=22345678-1234-4234-9234-123456789abc
APP_CLIENT_ID=32345678-1234-4234-9234-123456789abc
BOT_CLIENT_ID=42345678-1234-4234-9234-123456789abc
TEAMS_APP_ID=52345678-1234-4234-9234-123456789abc
APP_CLIENT_SECRET=dummy-app-secret
BOT_CLIENT_SECRET=dummy-bot-secret
BOOTSTRAP_SECRET=dummy-bootstrap-secret
MODEL_API_KEY='dummy-model-$-only'
APP_ENCRYPTION_KEY=1111111111111111111111111111111111111111111111111111111111111111
BRIDGE_HMAC_KEY=2222222222222222222222222222222222222222222222222222222222222222
MSAL_CACHE_KEY_HEX=3333333333333333333333333333333333333333333333333333333333333333
POSTGRES_DSN=postgres://db.example.test:5432/company?sslmode=verify-full
'@
  if ($TabOnly) {
    $dummyEnv = $dummyEnv -replace '(?m)^BOT_CLIENT_ID=.*\r?\n', '' -replace '(?m)^BOT_CLIENT_SECRET=.*\r?\n', '' -replace '(?m)^TEAMS_APP_ID=.*\r?\n', ''
    $dummyEnv += "`nBOT_ENABLED=false`n"
  }
  [IO.File]::WriteAllText((Join-Path $scratch '.env'), $dummyEnv)
  $sourcePath = $repository.Replace('\','/')
  $probePath = (Join-Path $repository 'scripts/single-container-probe.py').Replace('\','/')
  $yaml = [IO.File]::ReadAllText((Join-Path $repository 'docker-compose.yml'))
  $yaml = $yaml.Replace('context: .', "context: '$sourcePath'")
  $yaml = $yaml.Replace('expose: ["8088"]', 'ports: ["127.0.0.1::8088"]')
  $yaml = $yaml.Replace('      - app_data:', "      - '${probePath}:/probe.py:ro'`n      - app_data:")
  [IO.File]::WriteAllText($composePath, $yaml)
  Invoke-Compose config --quiet
  Invoke-Compose build
  Invoke-Compose up -d
  $script:container = (Invoke-Compose ps -q iqkb).Trim()
  Wait-Healthy
  & rtk proxy docker exec $container python /probe.py seed
  if ($LASTEXITCODE -ne 0) { Invoke-Compose logs --tail 80; throw 'Single-container security/workflow probe failed.' }
  Invoke-Compose restart
  Wait-Healthy
  & rtk proxy docker exec $container python /probe.py verify
  if ($LASTEXITCODE -ne 0) { throw 'Single-container persistence/restart probe failed.' }
  & rtk proxy docker exec $container python /probe.py crash-app
  if ($LASTEXITCODE -ne 0) { throw 'Could not simulate a service crash.' }
  $restarted = $false
  for ($attempt = 0; $attempt -lt 60; $attempt++) {
    $count = & rtk proxy docker inspect --format '{{.RestartCount}}' $container
    if ($LASTEXITCODE -eq 0 -and [int]$count -gt 0) { $restarted = $true; break }
    Start-Sleep -Milliseconds 500
  }
  if (-not $restarted) { throw 'Container did not restart after a child crash.' }
  Wait-Healthy
  Write-Host 'Single-container validation passed, including env injection, persistence, and child-crash restart.'
}
finally {
  if (Test-Path -LiteralPath $composePath) {
    $ErrorActionPreference = 'Continue'
    & rtk proxy docker compose -p $project -f $composePath down --volumes --remove-orphans *> $null
    $ErrorActionPreference = 'Stop'
  }
  $resolvedScratch = [IO.Path]::GetFullPath($scratch)
  if ($resolvedScratch.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
    Remove-Item -LiteralPath $resolvedScratch -Recurse -Force
  }
}
