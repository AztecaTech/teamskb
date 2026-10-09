param(
  [Parameter(Mandatory)][string]$CrmOrigin,
  [string]$MicrosoftTenantId = $env:TENANT_ID,
  [string]$IqEnvironmentFile = (Join-Path $PSScriptRoot '../.env'),
  [string]$CrmWorkspace = (Join-Path $PSScriptRoot '../../ats-dashboard')
)
$ErrorActionPreference = 'Stop'
$workspace = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$crmPath = (Resolve-Path -LiteralPath $CrmWorkspace).Path
$origin = [Uri]$CrmOrigin
if ($origin.Scheme -ne 'https' -or $origin.UserInfo -or $origin.Query -or $origin.Fragment -or $origin.AbsolutePath -ne '/') {
  throw 'Use the CRM HTTPS origin without a path, credential or query.'
}
if (-not $MicrosoftTenantId -and (Test-Path -LiteralPath $IqEnvironmentFile)) {
  $entry = Get-Content -LiteralPath $IqEnvironmentFile | Where-Object { $_ -match '^\s*(?:export\s+)?TENANT_ID\s*=' } | Select-Object -Last 1
  if ($entry -match '^\s*(?:export\s+)?TENANT_ID\s*=\s*(.*?)\s*$') {
    $MicrosoftTenantId = $Matches[1].Trim().Trim([char]34).Trim([char]39)
  }
}
if (-not $MicrosoftTenantId -or $MicrosoftTenantId -notmatch '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$') {
  throw 'TENANT_ID must be available locally in the process environment or IQ Knowledge env file. No identifier needs to be shared or added to source code.'
}
if (-not (Test-Path -LiteralPath (Join-Path $crmPath 'backend/src/api/routes/knowledge-permissions.routes.js'))) {
  throw 'The CRM workspace needs the read-only permission export before configuring it.'
}
$nativeFile = Join-Path $crmPath '.env.iqkb-permissions.local'
$clientFile = Join-Path $workspace '.env.crm-permissions.local'
# Both filenames are ignored by their repository; original .env files stay intact.
foreach ($target in @(@{Root=$crmPath;File=$nativeFile}, @{Root=$workspace;File=$clientFile})) {
  & git -C $target.Root check-ignore --quiet $target.File
  if ($LASTEXITCODE -ne 0) { throw 'Permission-token output must be excluded from Git.' }
}
$serverToken = ''
if (Test-Path -LiteralPath $nativeFile) {
  $record = Get-Content -LiteralPath $nativeFile | Where-Object { $_ -match '^IQKB_PERMISSION_TOKEN=([a-f0-9]{64})$' } | Select-Object -First 1
  if ($record -match '^IQKB_PERMISSION_TOKEN=([a-f0-9]{64})$') { $serverToken = $Matches[1] }
}
if (-not $serverToken) {
  $bytes = New-Object byte[] 32
  $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
  try { $generator.GetBytes($bytes) } finally { $generator.Dispose() }
  $serverToken = -join ($bytes | ForEach-Object { $_.ToString('x2') })
}
$nativeContents = "IQKB_PERMISSION_TOKEN=$serverToken`nIQKB_MICROSOFT_TENANT_ID=$MicrosoftTenantId`n"
$clientContents = "POSTGRES_PERMISSION_SOURCE_URL=$($origin.GetLeftPart([UriPartial]::Authority))/api/integrations/iqkb/permissions`nPOSTGRES_PERMISSION_SOURCE_TOKEN=$serverToken`n"
[IO.File]::WriteAllText($nativeFile, $nativeContents)
[IO.File]::WriteAllText($clientFile, $clientContents)
Write-Host "Prepared CRM settings: $nativeFile"
Write-Host "Prepared IQ Knowledge settings: $clientFile"
Write-Host 'Import each file into its application environment and deploy the CRM backend change. No deployment or database changes were performed.'
