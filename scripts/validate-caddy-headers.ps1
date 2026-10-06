$ErrorActionPreference = 'Stop'

$repository = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$caddyfile = Join-Path $repository 'Caddyfile'
$containerName = "iqkb-caddy-headers-$([Guid]::NewGuid().ToString('N').Substring(0, 12))"
$backendName = "iqkb-caddy-backend-$([Guid]::NewGuid().ToString('N').Substring(0, 12))"
$networkName = "iqkb-caddy-network-$([Guid]::NewGuid().ToString('N').Substring(0, 12))"
$probePath = Join-Path ([System.IO.Path]::GetTempPath()) "iqkb-caddy-probe-$([Guid]::NewGuid().ToString('N')).py"
$image = 'caddy:2@sha256:13b7fbadd017b042956fddbceedeeea12bb1e560534f9b3df281269dbcc61813'
$pythonImage = 'python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016'
$requestProbePath = (Join-Path $repository 'scripts/caddy-request-probe.py').Replace('\','/')

try {
  & rtk proxy docker network create $networkName | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not create a disposable Caddy probe network.' }
  & rtk proxy docker run --detach --name $backendName --network $networkName --network-alias app --network-alias gateway --mount "type=bind,source=$requestProbePath,target=/probe.py,readonly" $pythonImage python /probe.py serve | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not start the disposable HTTP probe upstream.' }
  & rtk proxy docker run --detach --name $containerName --network $networkName --publish 127.0.0.1::443 --env PUBLIC_ORIGIN=https://localhost --mount "type=bind,source=$caddyfile,target=/etc/caddy/Caddyfile,readonly" $image
  if ($LASTEXITCODE -ne 0) { throw 'Could not start the disposable Caddy header probe.' }

  $mapping = ''
  for ($attempt = 0; $attempt -lt 20; $attempt++) {
    $mapping = & rtk docker port $containerName 443/tcp
    if ($LASTEXITCODE -eq 0 -and $mapping) { break }
    Start-Sleep -Milliseconds 500
  }
  if (-not $mapping) { throw 'Caddy did not publish its ephemeral HTTPS port.' }
  $port = $mapping.Trim().Split(':')[-1]

  $probe = @'
import ssl, sys, urllib.error, urllib.request
url = "https://localhost:" + sys.argv[1] + "/"
try:
    response = urllib.request.urlopen(url, context=ssl._create_unverified_context(), timeout=3)
except urllib.error.HTTPError as error:
    response = error
except Exception as error:
    print(f"Caddy HTTPS probe not ready: {error}")
    raise SystemExit(2)
headers = response.headers
expected = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Strict-Transport-Security": "max-age=31536000",
}
for name, value in expected.items():
    if headers.get(name) != value:
        print(f"{name}={headers.get(name)!r}; expected {value!r}")
        raise SystemExit(1)
csp = headers.get("Content-Security-Policy", "")
for directive in ("default-src 'self'", "object-src 'none'", "frame-ancestors 'self'", "https://*.cloud.microsoft"):
    if directive not in csp:
        print(f"CSP is missing {directive!r}: {csp!r}")
        raise SystemExit(1)
print("Caddy HTTPS response contains expected security headers.")
'@
  Set-Content -LiteralPath $probePath -Value $probe -Encoding utf8

  $verified = $false
  for ($attempt = 0; $attempt -lt 20; $attempt++) {
    $probeOutput = & rtk proxy python $probePath $port 2>&1
    if ($LASTEXITCODE -eq 0) {
      $probeOutput
      $verified = $true
      break
    }
    if ($LASTEXITCODE -ne 2) { throw ($probeOutput -join "`n") }
    Start-Sleep -Milliseconds 500
  }
  if (-not $verified) { throw 'Caddy did not return a verifiable HTTPS response in time.' }

  $requestProbeOutput = & rtk proxy python $requestProbePath $port 2>&1
  if ($LASTEXITCODE -ne 0) { throw ($requestProbeOutput -join "`n") }
  $requestProbeOutput
}
finally {
  & rtk proxy docker rm --force $containerName $backendName *> $null
  & rtk proxy docker network rm $networkName *> $null
  Remove-Item -LiteralPath $probePath -Force -ErrorAction SilentlyContinue
}
