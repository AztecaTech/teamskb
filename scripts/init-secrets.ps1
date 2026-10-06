$ErrorActionPreference = 'Stop'
$repository = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$configuredSecretDir = $env:IQKB_SECRETS_DIR
if ([string]::IsNullOrWhiteSpace($configuredSecretDir)) { $configuredSecretDir = '..\IQ-kbteams-secrets' }
if (![System.IO.Path]::IsPathRooted($configuredSecretDir)) { $configuredSecretDir = Join-Path $repository $configuredSecretDir }
$secretDir = [System.IO.Path]::GetFullPath($configuredSecretDir)
New-Item -ItemType Directory -Path $secretDir -Force | Out-Null
foreach ($name in @('bridge_hmac_key', 'app_encryption_key', 'gateway_cache_key', 'bootstrap_secret', 'model_api_key', 'postgres_dsn')) {
    $path = Join-Path $secretDir $name
    if (Test-Path -LiteralPath $path) { throw "Refusing to overwrite existing secret: $path" }
    if ($name -eq 'model_api_key' -or $name -eq 'postgres_dsn') {
        [System.IO.File]::WriteAllText($path, '')
        continue
    }
    $bytes = [byte[]]::new(32)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    if ($name -eq 'bootstrap_secret') {
        $bootstrap = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        [System.IO.File]::WriteAllText($path, $bootstrap)
    } else {
        [System.IO.File]::WriteAllBytes($path, $bytes)
    }
}
Write-Output "Generated local keys in $secretDir. Set model_api_key before checking the provider; add app_client_secret and bot_client_secret after Entra registration. postgres_dsn is empty, so PostgreSQL is disabled. Store backups securely."
