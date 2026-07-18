$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
$Version = $env:HOL_GUARD_VERSION
$BuildId = $env:HOL_GUARD_BUILD_ID
if ([string]::IsNullOrWhiteSpace($Version) -or [string]::IsNullOrWhiteSpace($BuildId)) {
    throw 'Set HOL_GUARD_VERSION and HOL_GUARD_BUILD_ID.'
}
$Out = Join-Path $Root 'dist/mdm/windows'
$Runtime = Join-Path $Out 'runtime'
Remove-Item -Recurse -Force $Out -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $Runtime | Out-Null
$VersionFile = Join-Path $Out 'version-info.txt'
python (Join-Path $PSScriptRoot 'write-version-info.py') --version $Version --output $VersionFile

uv run --no-sync pyinstaller --clean --noconfirm --onedir --name hol-guard `
    --collect-submodules codex_plugin_scanner --collect-data codex_plugin_scanner `
    --version-file $VersionFile `
    --distpath $Runtime --workpath (Join-Path $Out 'pyinstaller') --specpath $Out `
    (Join-Path $Root 'scripts/mdm/hol-guard-entry.py')
$ManifestArgs = @(
    '--runtime-root', $Runtime, '--version', $Version, '--build-id', $BuildId,
    '--platform', 'windows', '--architecture', $env:PROCESSOR_ARCHITECTURE,
    '--installer-identity', 'HOLGuardMachine', '--output', (Join-Path $Runtime 'release-manifest.json')
)
if (-not [string]::IsNullOrWhiteSpace($env:HOL_GUARD_MANIFEST_SIGNING_KEY)) {
    if ([string]::IsNullOrWhiteSpace($env:HOL_GUARD_MANIFEST_KEY_ID)) { throw 'Manifest key ID is required.' }
    $ManifestArgs += @('--signing-key', $env:HOL_GUARD_MANIFEST_SIGNING_KEY, '--key-id', $env:HOL_GUARD_MANIFEST_KEY_ID)
}
if (-not [string]::IsNullOrWhiteSpace($env:HOL_GUARD_SIGNTOOL_CERT_SHA1)) {
    if ([string]::IsNullOrWhiteSpace($env:HOL_GUARD_MANIFEST_SIGNING_KEY)) { throw 'Signed installers require a signed manifest.' }
    Get-ChildItem -Path $Runtime -Filter '*.exe' -Recurse | ForEach-Object {
        & signtool sign /sha1 $env:HOL_GUARD_SIGNTOOL_CERT_SHA1 /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $_.FullName
    }
}
python (Join-Path $Root 'scripts/mdm/generate-release-manifest.py') @ManifestArgs

$Msi = Join-Path $Out "hol-guard-$Version-x64.msi"
& wix build (Join-Path $PSScriptRoot 'hol-guard.wxs') -arch x64 -d RuntimeRoot=$Runtime -o $Msi
& (Join-Path $PSScriptRoot 'verify-msi-acls.ps1') -MsiPath $Msi
if (-not [string]::IsNullOrWhiteSpace($env:HOL_GUARD_SIGNTOOL_CERT_SHA1)) {
    & signtool sign /sha1 $env:HOL_GUARD_SIGNTOOL_CERT_SHA1 /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $Msi
}
python (Join-Path $Root 'scripts/mdm/generate-sbom.py') --version $Version --output (Join-Path $Out 'sbom.cdx.json')
python (Join-Path $Root 'scripts/mdm/write-release-evidence.py') --artifact $Msi `
    --manifest (Join-Path $Runtime 'release-manifest.json') --sbom (Join-Path $Out 'sbom.cdx.json') `
    --output (Join-Path $Out 'release-evidence.json')
