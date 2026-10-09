param([string]$CrmWorkspace = (Join-Path $PSScriptRoot '../../ats-dashboard'))
$ErrorActionPreference = 'Stop'
$crmPath = (Resolve-Path -LiteralPath $CrmWorkspace).Path
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('iqkb-crm-' + [Guid]::NewGuid().ToString('N'))
$containerName = 'iqkb-crm-' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
$previousDsn = $env:IQKB_CRM_TEST_DSN_FILE
New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
try {
  $fixtureSql = Join-Path $PSScriptRoot 'fixtures/crm-permissions.sql'
  & docker run --detach --name $containerName --publish '127.0.0.1::5432' --env 'POSTGRES_PASSWORD=IQKB-crm-admin-only' --env 'POSTGRES_DB=iqkb_crm_fixture' --volume "${fixtureSql}:/docker-entrypoint-initdb.d/crm.sql:ro" postgres:15 | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not start the disposable CRM fixture.' }
  $binding = & docker port $containerName '5432/tcp'
  if ($binding -notmatch '127\.0\.0\.1:(\d+)') { throw 'CRM fixture port not found.' }
  $fixturePort = $Matches[1]
  $ready = $false
  for ($attempt = 0; $attempt -lt 30; $attempt++) {
    & docker exec $containerName pg_isready -U postgres -d iqkb_crm_fixture *> $null
    if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    Start-Sleep -Milliseconds 500
  }
  if (-not $ready) { throw 'CRM fixture did not become ready.' }
  $env:IQKB_CRM_TEST_DSN_FILE = Join-Path $fixtureRoot 'dsn'
  [IO.File]::WriteAllText($env:IQKB_CRM_TEST_DSN_FILE, "postgres://iqkb_bridge_fixture:IQKB-bridge-fixture-only@127.0.0.1:$fixturePort/iqkb_crm_fixture?sslmode=disable")
  Push-Location (Join-Path $crmPath 'backend')
  try {
    & npm test -- --runInBand --coverage=false --runTestsByPath src/api/routes/__tests__/knowledge-permissions.integration.test.js
    if ($LASTEXITCODE -ne 0) { throw 'CRM permission bridge integration tests failed.' }
  } finally { Pop-Location }
} finally {
  $env:IQKB_CRM_TEST_DSN_FILE = $previousDsn
  & docker rm --force $containerName *> $null
  $resolvedFixture = [IO.Path]::GetFullPath($fixtureRoot)
  $resolvedTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
  if (-not $resolvedFixture.StartsWith($resolvedTemp, [StringComparison]::OrdinalIgnoreCase) -or (Split-Path $resolvedFixture -Leaf) -notlike 'iqkb-crm-*') { throw 'Unexpected fixture cleanup path.' }
  Remove-Item -LiteralPath $resolvedFixture -Recurse -Force
}
