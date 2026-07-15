$ErrorActionPreference = 'Stop'
$Guard = Join-Path $env:ProgramFiles 'HOL Guard/hol-guard/hol-guard.exe'
& $Guard mdm activate --home $env:USERPROFILE --user $env:USERNAME --json
exit $LASTEXITCODE
