param(
  [Parameter(Mandatory)][string]$TeamsAppId,
  [Parameter(Mandatory)][string]$BotClientId,
  [Parameter(Mandatory)][string]$AppClientId,
  [Parameter(Mandatory)][string]$AppIdUri,
  [Parameter(Mandatory)][string]$PublicOrigin,
  [Parameter(Mandatory)][string]$PrivacyUrl,
  [Parameter(Mandatory)][string]$TermsOfUseUrl,
  [Parameter(Mandatory)][string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$guidPattern = '^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
foreach ($item in @(@('TeamsAppId', $TeamsAppId), @('BotClientId', $BotClientId), @('AppClientId', $AppClientId))) {
  if ($item[1] -notmatch $guidPattern) { throw "$($item[0]) must be a GUID." }
}

$origin = $null
if (-not [Uri]::TryCreate($PublicOrigin, [UriKind]::Absolute, [ref]$origin) -or
    $origin.Scheme -ne 'https' -or $origin.UserInfo -ne '' -or
    $origin.AbsolutePath -notin @('', '/') -or $origin.Query -ne '' -or $origin.Fragment -ne '') {
  throw 'PublicOrigin must be an HTTPS origin without a path, query, or fragment.'
}
foreach ($item in @(@('PrivacyUrl', $PrivacyUrl), @('TermsOfUseUrl', $TermsOfUseUrl))) {
  $legalUrl = $null
  if (-not [Uri]::TryCreate($item[1], [UriKind]::Absolute, [ref]$legalUrl) -or $legalUrl.Scheme -ne 'https' -or $legalUrl.UserInfo -ne '') {
    throw "$($item[0]) must be an HTTPS URL reviewed and hosted by the operator."
  }
}
if ($AppIdUri -notmatch '^api://[^\s?#]+$') { throw 'AppIdUri must be an api:// resource URI.' }
$appResource = $null
if (-not [Uri]::TryCreate($AppIdUri, [UriKind]::Absolute, [ref]$appResource) -or $appResource.Scheme -ne 'api') {
  throw 'AppIdUri must be a valid absolute api:// resource URI.'
}
$expectedAppIdUri = "api://$($origin.DnsSafeHost.ToLowerInvariant())/botid-$($BotClientId.ToLowerInvariant())"
if ($AppIdUri -cne $expectedAppIdUri) {
  throw "For this bot-and-tab app, AppIdUri must be '$expectedAppIdUri' (Microsoft bot SSO format)."
}

$repository = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$teamsDirectory = Join-Path $repository 'teams'
$templatePath = Join-Path $teamsDirectory 'manifest.template.json'
$colorPath = Join-Path $teamsDirectory 'color.png'
$outlinePath = Join-Path $teamsDirectory 'outline.png'
foreach ($path in @($templatePath, $colorPath, $outlinePath)) {
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required Teams package file is missing: $path" }
}

function Test-PngSize([string]$Path, [int]$Expected) {
  $bytes = [System.IO.File]::ReadAllBytes($Path)
  $signature = [byte[]](137, 80, 78, 71, 13, 10, 26, 10)
  if ($bytes.Length -lt 24) { return $false }
  for ($index = 0; $index -lt $signature.Length; $index++) {
    if ($bytes[$index] -ne $signature[$index]) { return $false }
  }
  $width = ($bytes[16] -shl 24) -bor ($bytes[17] -shl 16) -bor ($bytes[18] -shl 8) -bor $bytes[19]
  $height = ($bytes[20] -shl 24) -bor ($bytes[21] -shl 16) -bor ($bytes[22] -shl 8) -bor $bytes[23]
  return $width -eq $Expected -and $height -eq $Expected
}
if (-not (Test-PngSize $colorPath 192) -or -not (Test-PngSize $outlinePath 32)) {
  throw 'Teams icons must be PNG images sized 192x192 and 32x32.'
}

$parsedManifest = [System.IO.File]::ReadAllText($templatePath) | ConvertFrom-Json
$parsedManifest.id = $TeamsAppId.ToLowerInvariant()
$parsedManifest.bots[0].botId = $BotClientId.ToLowerInvariant()
$parsedManifest.staticTabs[0].contentUrl = "$($PublicOrigin.TrimEnd('/'))/"
$parsedManifest.staticTabs[0].websiteUrl = "$($PublicOrigin.TrimEnd('/'))/"
$parsedManifest.developer.websiteUrl = $PublicOrigin.TrimEnd('/')
$parsedManifest.developer.privacyUrl = $PrivacyUrl
$parsedManifest.developer.termsOfUseUrl = $TermsOfUseUrl
$parsedManifest.validDomains = @($origin.DnsSafeHost, 'token.botframework.com')
$parsedManifest.webApplicationInfo.id = $AppClientId.ToLowerInvariant()
$parsedManifest.webApplicationInfo.resource = $AppIdUri
$schemaMatch = [regex]::Match([string]$parsedManifest.'$schema', '^https://developer\.microsoft\.com/json-schemas/teams/v(\d+\.\d+)/MicrosoftTeams\.schema\.json$')
if (-not $schemaMatch.Success -or $parsedManifest.manifestVersion -ne $schemaMatch.Groups[1].Value -or
    $parsedManifest.staticTabs[0].contentUrl -ne "$($PublicOrigin.TrimEnd('/'))/" -or
    (@($parsedManifest.bots[0].scopes | Where-Object { $_ -notin @('personal', 'groupChat', 'team') }).Count -gt 0)) {
  throw 'Generated Teams manifest failed its content checks.'
}
$manifest = $parsedManifest | ConvertTo-Json -Depth 32
if ($manifest -match '__[A-Z_]+__') { throw 'Manifest still contains unresolved placeholders.' }

$fullOutput = [System.IO.Path]::GetFullPath($OutputPath)
if ([System.IO.Path]::GetExtension($fullOutput) -ne '.zip') { throw 'OutputPath must end in .zip.' }
if (Test-Path -LiteralPath $fullOutput) { throw 'OutputPath already exists; choose a new package path.' }
$outputDirectory = Split-Path -Parent $fullOutput
if (-not (Test-Path -LiteralPath $outputDirectory)) { New-Item -ItemType Directory -Path $outputDirectory | Out-Null }
$packageDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("iqkb-teams-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $packageDirectory | Out-Null
try {
  [System.IO.File]::WriteAllText((Join-Path $packageDirectory 'manifest.json'), $manifest, [System.Text.UTF8Encoding]::new($false))
  Copy-Item -LiteralPath $colorPath, $outlinePath -Destination $packageDirectory
  Compress-Archive -Path (Join-Path $packageDirectory '*') -DestinationPath $fullOutput -CompressionLevel Optimal
}
finally {
  $resolvedTemp = [System.IO.Path]::GetFullPath($packageDirectory)
  $resolvedTempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
  if ($resolvedTemp.StartsWith($resolvedTempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    Remove-Item -LiteralPath $resolvedTemp -Recurse -Force -ErrorAction SilentlyContinue
  }
}
Write-Output "Created Teams app package: $fullOutput"
