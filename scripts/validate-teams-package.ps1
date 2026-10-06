$ErrorActionPreference = 'Stop'

$repository = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$scratch = Join-Path ([System.IO.Path]::GetTempPath()) ("iqkb-teams-package-" + [Guid]::NewGuid().ToString('N'))
$package = Join-Path $scratch 'valid.zip'
$expanded = Join-Path $scratch 'expanded'
$rejectedPackage = Join-Path $scratch 'invalid.zip'
$teamsAppId = '52345678-1234-4234-9234-123456789abc'
$botClientId = '42345678-1234-4234-9234-123456789abc'
$appClientId = '32345678-1234-4234-9234-123456789abc'
$origin = 'https://teams-assistant.example.test'
$appIdUri = "api://teams-assistant.example.test/botid-$botClientId"
$privacyUrl = "$origin/privacy"
$termsUrl = "$origin/terms"
$packager = Join-Path $PSScriptRoot 'package-teams-app.ps1'

New-Item -ItemType Directory -Path $scratch | Out-Null
try {
  & $packager -TeamsAppId $teamsAppId -BotClientId $botClientId -AppClientId $appClientId `
    -AppIdUri $appIdUri -PublicOrigin $origin -PrivacyUrl $privacyUrl -TermsOfUseUrl $termsUrl -OutputPath $package
  if (-not (Test-Path -LiteralPath $package -PathType Leaf)) { throw 'Package was not created.' }

  Expand-Archive -LiteralPath $package -DestinationPath $expanded
  $files = @(Get-ChildItem -LiteralPath $expanded -File | ForEach-Object Name | Sort-Object)
  if (($files -join ',') -ne 'color.png,manifest.json,outline.png') { throw "Unexpected package contents: $($files -join ', ')" }
  $manifest = Get-Content -LiteralPath (Join-Path $expanded 'manifest.json') -Raw | ConvertFrom-Json
  if ($manifest.id -ne $teamsAppId -or $manifest.bots[0].botId -ne $botClientId -or
      $manifest.webApplicationInfo.id -ne $appClientId -or $manifest.webApplicationInfo.resource -ne $appIdUri) {
    throw 'Generated manifest IDs or SSO resource do not match the supplied values.'
  }

  $rejected = $false
  try {
    & $packager -TeamsAppId $teamsAppId -BotClientId $botClientId -AppClientId $appClientId `
      -AppIdUri "api://teams-assistant.example.test/$appClientId" -PublicOrigin $origin `
      -PrivacyUrl $privacyUrl -TermsOfUseUrl $termsUrl -OutputPath $rejectedPackage
  }
  catch {
    if ($_.Exception.Message -notlike '*AppIdUri must be*') { throw }
    $rejected = $true
  }
  if (-not $rejected -or (Test-Path -LiteralPath $rejectedPackage)) { throw 'A nonconforming SSO resource URI was not rejected.' }

  Write-Output 'Teams package validation passed: URI validation, manifest identity, ZIP contents, and invalid URI rejection.'
}
finally {
  $resolvedScratch = [System.IO.Path]::GetFullPath($scratch)
  $resolvedTempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
  if ($resolvedScratch.StartsWith($resolvedTempRoot, [System.StringComparison]::OrdinalIgnoreCase) -and
      [System.IO.Path]::GetFileName($resolvedScratch).StartsWith('iqkb-teams-package-', [System.StringComparison]::Ordinal)) {
    Remove-Item -LiteralPath $resolvedScratch -Recurse -Force -ErrorAction SilentlyContinue
  }
}
