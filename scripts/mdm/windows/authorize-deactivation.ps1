param(
    [Parameter(Mandatory = $true)][string]$User,
    [Parameter(Mandatory = $true)][string]$Home
)
$ErrorActionPreference = 'Stop'
$Guard = Join-Path $env:ProgramFiles 'HOL Guard/hol-guard/hol-guard.exe'
$TokenName = "$User.json"
& $Guard mdm authorize-deactivation --home $Home --user $User --token-name $TokenName --json
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$Authorization = Join-Path $env:ProgramData "HOL Guard/removal-authorizations/$TokenName"
& icacls.exe $Authorization /grant:r "${User}:(R,D)" | Out-Null
exit $LASTEXITCODE
