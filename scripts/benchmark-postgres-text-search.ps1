$ErrorActionPreference = 'Stop'

$repository = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$containerName = 'iqkb-bench-' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
$benchmarkSQL = Join-Path $repository 'docs/postgres/text-search-benchmark.sql'

try {
  & rtk docker run --detach --name $containerName --env 'POSTGRES_PASSWORD=benchmark-only' postgres:18 *> $null
  if ($LASTEXITCODE -ne 0) { throw 'Could not start disposable PostgreSQL benchmark server.' }

  $ready = $false
  for ($attempt = 0; $attempt -lt 60; $attempt++) {
    & rtk docker exec $containerName pg_isready -U postgres *> $null
    if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    Start-Sleep -Seconds 1
  }
  if (-not $ready) { throw 'Disposable PostgreSQL benchmark server did not become ready.' }

  & rtk docker cp $benchmarkSQL "${containerName}:/tmp/text-search-benchmark.sql"
  if ($LASTEXITCODE -ne 0) { throw 'Could not copy benchmark SQL into disposable PostgreSQL.' }
  & rtk docker exec $containerName psql -U postgres -d postgres -v ON_ERROR_STOP=1 -f /tmp/text-search-benchmark.sql
  if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL text-search benchmark failed.' }
}
finally {
  & rtk docker rm --force --volumes $containerName *> $null
}
