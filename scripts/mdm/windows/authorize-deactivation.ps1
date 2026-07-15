param(
    [Parameter(Mandatory = $true)][string]$User,
    [Parameter(Mandatory = $true)][string]$Home
)
$ErrorActionPreference = 'Stop'
$Guard = Join-Path $env:ProgramFiles 'HOL Guard/hol-guard/hol-guard.exe'
$TokenName = "$User.json"
& $Guard mdm authorize-deactivation --home $Home --user $User --token-name $TokenName --json
exit $LASTEXITCODE
