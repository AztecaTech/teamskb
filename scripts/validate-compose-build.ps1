$ErrorActionPreference = 'Stop'

$repository = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$tempRoot = [System.IO.Path]::GetTempPath()
$tempPath = Join-Path $tempRoot ("iqkb-compose-" + [Guid]::NewGuid().ToString('N'))
$projectName = "iqkb-check-" + [Guid]::NewGuid().ToString('N').Substring(0, 12)
New-Item -ItemType Directory -Path $tempPath | Out-Null

try {
  $env:IQKB_SECRETS_DIR = $tempPath
  $env:PUBLIC_ORIGIN = 'https://teams-assistant.example.test'
  $env:TENANT_ID = '12345678-1234-4234-9234-123456789abc'
  $env:ADMIN_OBJECT_ID = '22345678-1234-4234-9234-123456789abc'
  $env:APP_CLIENT_ID = '32345678-1234-4234-9234-123456789abc'
  $env:BOT_CLIENT_ID = '42345678-1234-4234-9234-123456789abc'
  $env:TEAMS_APP_ID = '52345678-1234-4234-9234-123456789abc'

  foreach ($name in @('app_encryption_key', 'bridge_hmac_key', 'gateway_cache_key')) {
    $key = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($key)
    $rng.Dispose()
    [System.IO.File]::WriteAllBytes((Join-Path $tempPath $name), $key)
  }
  foreach ($name in @('app_client_secret', 'bot_client_secret', 'bootstrap_secret', 'model_api_key')) {
    [System.IO.File]::WriteAllText((Join-Path $tempPath $name), "disposable-$name-value")
  }
  [System.IO.File]::WriteAllText((Join-Path $tempPath 'postgres_dsn'), '')

  Push-Location $repository
  try {
    & rtk docker compose -p $projectName config --quiet
    if ($LASTEXITCODE -ne 0) { throw 'Compose configuration validation failed.' }
    & rtk docker compose -p $projectName build app gateway parser
    if ($LASTEXITCODE -ne 0) { throw 'App, gateway, or parser image build failed.' }
    $parserTests = Join-Path $repository 'parser\test_parser.py'
    & rtk docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 64 --memory 512m --cpus 1 --tmpfs '/tmp:size=64m,noexec,nosuid,nodev' --mount "type=bind,source=$parserTests,target=/srv/test_parser.py,readonly" --entrypoint python iq-kbteams-parser:local -m unittest test_parser
    if ($LASTEXITCODE -ne 0) { throw 'Parser unit tests failed in the freshly built restricted image.' }
    & rtk docker compose -p $projectName up -d app gateway parser
    if ($LASTEXITCODE -ne 0) {
      & rtk docker compose -p $projectName ps
      & rtk docker compose -p $projectName logs gateway
      throw 'Disposable Compose services did not start.'
    }

    $ready = $false
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
      try {
        & rtk docker compose -p $projectName exec -T app /iqkb healthcheck *> $null
        if ($LASTEXITCODE -ne 0) { throw 'App container healthcheck failed.' }
        & rtk docker compose -p $projectName exec -T gateway node -e "fetch('http://app:8080/health/ready').then(async r=>{if(r.status!==200)process.exit(1);const u=await fetch('http://app:8080/api/session');if(u.status!==401)process.exit(2);console.log('ready; unauthenticated session rejected')})" *> $null
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
      }
      catch { }
      Start-Sleep -Seconds 1
    }
    if (-not $ready) { throw 'App readiness or unauthenticated-session check failed.' }

    $expectedResourceLimits = @{
      app = '1610612736|2000000000|128'
      gateway = '536870912|1000000000|64'
      parser = '536870912|1000000000|64'
    }
    foreach ($service in $expectedResourceLimits.Keys) {
      $containerId = & rtk docker compose -p $projectName ps -q $service
      if ($LASTEXITCODE -ne 0 -or -not $containerId) { throw "Could not find $service container for resource-limit check." }
      $actualResourceLimits = (& rtk docker inspect --format '{{.HostConfig.Memory}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}' $containerId).Trim()
      if ($LASTEXITCODE -ne 0 -or $actualResourceLimits -ne $expectedResourceLimits[$service]) {
        throw "$service resource limits were $actualResourceLimits; expected $($expectedResourceLimits[$service])."
      }
    }
    Write-Host 'Compose smoke passed: app is ready and unauthenticated sessions return 401.'
    Write-Host 'Compose resource-limit checks passed for app, gateway, and parser.'
  }
  finally {
    try { & rtk docker compose -p $projectName down --volumes --remove-orphans *> $null } catch { }
    Pop-Location
  }
}
finally {
  foreach ($name in @('IQKB_SECRETS_DIR', 'PUBLIC_ORIGIN', 'TENANT_ID', 'ADMIN_OBJECT_ID', 'APP_CLIENT_ID', 'BOT_CLIENT_ID', 'TEAMS_APP_ID')) {
    Remove-Item "Env:\$name" -ErrorAction SilentlyContinue
  }
  $resolvedTemp = [System.IO.Path]::GetFullPath($tempPath)
  $resolvedTempRoot = [System.IO.Path]::GetFullPath($tempRoot)
  if ($resolvedTemp.StartsWith($resolvedTempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    Remove-Item -LiteralPath $resolvedTemp -Recurse -Force -ErrorAction SilentlyContinue
  }
}
