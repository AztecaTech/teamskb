$ErrorActionPreference = 'Stop'
$repository = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$fixtureDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ('iqkb-auth-' + [Guid]::NewGuid().ToString('N'))
$containerName = 'iqkb-auth-' + [Guid]::NewGuid().ToString('N').Substring(0,12)
$previousDsnFile = $env:IQKB_AUTH_TEST_DSN_FILE
New-Item -ItemType Directory -Path $fixtureDirectory | Out-Null
try {
  & docker run --rm --volume "${fixtureDirectory}:/certs" --entrypoint sh postgres:15 -c "openssl req -x509 -newkey rsa:2048 -nodes -keyout /certs/server.key -out /certs/server.crt -days 2 -subj /CN=localhost -addext 'subjectAltName=DNS:localhost' -addext 'basicConstraints=critical,CA:TRUE'" *> $null
  if ($LASTEXITCODE -ne 0) { throw 'TLS fixture certificate creation failed.' }
  $fixtureSql = Join-Path $PSScriptRoot 'fixtures/postgres-auth.sql'
  $startup = 'cp /certs/server.crt /tmp/server.crt; cp /certs/server.key /tmp/server.key; chown postgres:postgres /tmp/server.crt /tmp/server.key; chmod 600 /tmp/server.key; exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key'
  & docker run --detach --name $containerName --publish '127.0.0.1::5432' --env 'POSTGRES_PASSWORD=IQKB-test-admin-only' --env 'POSTGRES_DB=iqkb_auth_fixture' --volume "${fixtureDirectory}:/certs:ro" --volume "${fixtureSql}:/docker-entrypoint-initdb.d/auth.sql:ro" --entrypoint bash postgres:15 -c $startup | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Database fixture startup failed.' }
  $binding = & docker port $containerName '5432/tcp'
  if ($binding -notmatch '127\.0\.0\.1:(\d+)') { throw 'Fixture port not found.' }
  $fixturePort = $Matches[1]
  $ready = $false
  for ($attempt=0; $attempt -lt 30; $attempt++) {
    & docker exec $containerName pg_isready -U postgres -d iqkb_auth_fixture *> $null
    if ($LASTEXITCODE -eq 0) { $ready=$true;break }
    Start-Sleep -Milliseconds 500
  }
  if (-not $ready) { throw 'Database fixture readiness failed.' }
  $dsnFile = Join-Path $fixtureDirectory 'dsn'
  $certificate = [Uri]::EscapeDataString((Join-Path $fixtureDirectory 'server.crt'))
  [System.IO.File]::WriteAllText($dsnFile,"postgres://iqkb_service:IQKB-test-service-only@localhost:$fixturePort/iqkb_auth_fixture?sslmode=verify-full&sslrootcert=$certificate")
  $env:IQKB_AUTH_TEST_DSN_FILE = $dsnFile
  Push-Location (Join-Path $repository 'app')
  try {
    & go test -p 1 ./internal/postgres ./cmd/iqkb -run 'TestPostgresAdapter.*Integration' -count=1 -v
    if ($LASTEXITCODE -ne 0) { throw 'Database authorization integration tests failed.' }
  } finally { Pop-Location }
} finally {
  $env:IQKB_AUTH_TEST_DSN_FILE = $previousDsnFile
  & docker rm --force $containerName *> $null
  $resolvedFixture = [System.IO.Path]::GetFullPath($fixtureDirectory)
  $resolvedTemp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
  if (-not $resolvedFixture.StartsWith($resolvedTemp,[System.StringComparison]::OrdinalIgnoreCase) -or (Split-Path $resolvedFixture -Leaf) -notlike 'iqkb-auth-*') { throw 'Unexpected fixture cleanup path.' }
  Remove-Item -LiteralPath $resolvedFixture -Recurse -Force
}
