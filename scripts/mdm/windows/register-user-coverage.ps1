param(
    [Parameter(Mandatory = $true)][string]$Home,
    [Parameter(Mandatory = $true)][string]$User
)

$ErrorActionPreference = 'Stop'
$Guard = Join-Path $env:ProgramFiles 'HOL Guard/hol-guard/hol-guard.exe'
& $Guard mdm harness-coverage-register --home $Home --user $User --json
exit $LASTEXITCODE
