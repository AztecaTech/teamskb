$ErrorActionPreference = 'Stop'

$repository = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$tempRoot = [System.IO.Path]::GetTempPath()
$tempPath = Join-Path $tempRoot ("iqkb-pg-" + [Guid]::NewGuid().ToString('N'))
$containerName = "iqkb-pg-" + [Guid]::NewGuid().ToString('N').Substring(0, 12)
$dsnPath = Join-Path $tempPath 'dsn'
$adminPasswordPath = Join-Path $tempPath 'admin-password'
$alexPasswordPath = Join-Path $tempPath 'alex-password'
$blairPasswordPath = Join-Path $tempPath 'blair-password'
$alexOldPasswordPath = Join-Path $tempPath 'alex-old-password'
$blairOldPasswordPath = Join-Path $tempPath 'blair-old-password'
$caPath = Join-Path $tempPath 'ca.crt'

New-Item -ItemType Directory -Path $tempPath | Out-Null
try {
  # Test credentials are disposable and exist only in this throwaway database.
  [System.IO.File]::WriteAllText($alexPasswordPath, 'IQKB-TEST-ONLY-Alex-1234!')
  [System.IO.File]::WriteAllText($blairPasswordPath, 'IQKB-TEST-ONLY-Blair-5678!')
  [System.IO.File]::WriteAllText($adminPasswordPath, 'IQKB-TEST-ONLY-Admin-9876')

  $certCommand = "openssl req -x509 -newkey rsa:2048 -nodes -keyout /certs/server.key -out /certs/ca.crt -days 2 -subj /CN=localhost -addext 'subjectAltName=DNS:localhost' -addext 'basicConstraints=critical,CA:TRUE'"
  & rtk docker run --rm --volume "${tempPath}:/certs" --entrypoint sh postgres:18 -c $certCommand
  if ($LASTEXITCODE -ne 0) { throw 'Could not create the disposable PostgreSQL TLS certificate.' }

  $fixturePath = Join-Path $repository 'docs/postgres/integration-fixture.sql'
  $fixtureVolume = "${fixturePath}:/docker-entrypoint-initdb.d/10-fixture.sql:ro"
  $startup = 'cp /certs/server.crt /tmp/server.crt 2>/dev/null || cp /certs/ca.crt /tmp/server.crt; cp /certs/server.key /tmp/server.key; chown postgres:postgres /tmp/server.crt /tmp/server.key; chmod 600 /tmp/server.key; exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key'
  & rtk docker run --detach --name $containerName --publish '127.0.0.1::5432' --env 'POSTGRES_PASSWORD=IQKB-TEST-ONLY-Admin-9876' --env 'POSTGRES_DB=iqkb_fixture' --volume "${tempPath}:/certs:ro" --volume $fixtureVolume --entrypoint bash postgres:18 -c $startup
  if ($LASTEXITCODE -ne 0) { throw 'Could not start the disposable PostgreSQL server.' }

  $portBinding = & rtk docker port $containerName '5432/tcp'
  if ($LASTEXITCODE -ne 0 -or $portBinding -notmatch '127\.0\.0\.1:(\d+)') { throw 'Could not discover the disposable PostgreSQL host port.' }
  $hostPort = $Matches[1]

  $ready = $false
  for ($attempt = 0; $attempt -lt 40; $attempt++) {
    try {
      & rtk docker exec -u postgres $containerName pg_isready -U postgres -d iqkb_fixture *> $null
      if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    }
    catch { }
    Start-Sleep -Seconds 1
  }
  if (-not $ready) {
    & rtk docker logs $containerName
    throw 'Disposable PostgreSQL did not become ready.'
  }

  $escapedCA = [Uri]::EscapeDataString($caPath)
  [System.IO.File]::WriteAllText($dsnPath, "postgres://localhost:$hostPort/iqkb_fixture?sslmode=verify-full&sslrootcert=$escapedCA")
  $env:IQKB_PG_INTEGRATION_DSN_FILE = $dsnPath
  $env:IQKB_PG_ADMIN_PASSWORD_FILE = $adminPasswordPath
  $env:IQKB_PG_ALEX_PASSWORD_FILE = $alexPasswordPath
  $env:IQKB_PG_BLAIR_PASSWORD_FILE = $blairPasswordPath
  Push-Location (Join-Path $repository 'app')
  try {
    & rtk go test -p 1 ./internal/postgres ./cmd/iqkb -run 'TestPostgres.*Integration|TestPostgresAskWorkflow'
    if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL integration tests failed.' }

    $alexRotatedPassword = "IQKB-ROTATED-Alex-$([Guid]::NewGuid().ToString('N'))"
    $blairRotatedPassword = "IQKB-ROTATED-Blair-$([Guid]::NewGuid().ToString('N'))"
    [System.IO.File]::WriteAllText($alexOldPasswordPath, [System.IO.File]::ReadAllText($alexPasswordPath))
    [System.IO.File]::WriteAllText($blairOldPasswordPath, [System.IO.File]::ReadAllText($blairPasswordPath))
    $rotationSQL = "ALTER ROLE iqkb_alex_login PASSWORD '$alexRotatedPassword'; ALTER ROLE iqkb_blair_login PASSWORD '$blairRotatedPassword'"
    & rtk docker exec -u postgres $containerName psql -v ON_ERROR_STOP=1 -d iqkb_fixture -c $rotationSQL
    if ($LASTEXITCODE -ne 0) { throw 'Could not rotate disposable PostgreSQL LOGIN passwords.' }
    [System.IO.File]::WriteAllText($alexPasswordPath, $alexRotatedPassword)
    [System.IO.File]::WriteAllText($blairPasswordPath, $blairRotatedPassword)
    $env:IQKB_PG_ALEX_OLD_PASSWORD_FILE = $alexOldPasswordPath
    $env:IQKB_PG_BLAIR_OLD_PASSWORD_FILE = $blairOldPasswordPath
    & rtk go test -p 1 ./internal/postgres ./cmd/iqkb -run 'TestPostgres.*Integration|TestPostgresAskWorkflow'
    if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL password-rotation integration tests failed.' }

    & rtk docker exec -u postgres $containerName psql -v ON_ERROR_STOP=1 -d iqkb_fixture -c 'ALTER ROLE iqkb_alex_login NOLOGIN'
    if ($LASTEXITCODE -ne 0) { throw 'Could not revoke the disposable PostgreSQL LOGIN.' }
    $env:IQKB_PG_REVOKED_ID = 'iqkb_alex_login'
    $env:IQKB_PG_REVOKED_PASSWORD_FILE = $alexPasswordPath
    & rtk go test ./internal/postgres -run '^TestPostgresNoLoginRevocationIntegration$'
    if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL LOGIN revocation integration test failed.' }
  }
  finally {
    Pop-Location
  }
}
finally {
  Remove-Item Env:\IQKB_PG_INTEGRATION_DSN_FILE -ErrorAction SilentlyContinue
  Remove-Item Env:\IQKB_PG_ADMIN_PASSWORD_FILE -ErrorAction SilentlyContinue
  Remove-Item Env:\IQKB_PG_ALEX_PASSWORD_FILE -ErrorAction SilentlyContinue
  Remove-Item Env:\IQKB_PG_BLAIR_PASSWORD_FILE -ErrorAction SilentlyContinue
  Remove-Item Env:\IQKB_PG_ALEX_OLD_PASSWORD_FILE -ErrorAction SilentlyContinue
  Remove-Item Env:\IQKB_PG_BLAIR_OLD_PASSWORD_FILE -ErrorAction SilentlyContinue
  Remove-Item Env:\IQKB_PG_REVOKED_ID -ErrorAction SilentlyContinue
  Remove-Item Env:\IQKB_PG_REVOKED_PASSWORD_FILE -ErrorAction SilentlyContinue
  & rtk docker rm --force --volumes $containerName *> $null
  $resolvedTemp = [System.IO.Path]::GetFullPath($tempPath)
  $resolvedTempRoot = [System.IO.Path]::GetFullPath($tempRoot)
  if ($resolvedTemp.StartsWith($resolvedTempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    Remove-Item -LiteralPath $resolvedTemp -Recurse -Force -ErrorAction SilentlyContinue
  }
}
