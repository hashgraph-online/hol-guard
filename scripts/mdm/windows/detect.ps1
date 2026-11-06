$ErrorActionPreference = 'Stop'
$Guard = Join-Path $env:ProgramFiles 'HOL Guard/hol-guard/hol-guard.exe'
if (-not (Test-Path -LiteralPath $Guard -PathType Leaf)) { exit 1 }
& $Guard mdm status --scope machine --json
exit $LASTEXITCODE
