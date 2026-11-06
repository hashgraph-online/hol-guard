$ErrorActionPreference = 'Stop'
$Guard = Join-Path $env:ProgramFiles 'HOL Guard/hol-guard/hol-guard.exe'
$Authorization = Join-Path $env:ProgramData "HOL Guard/removal-authorizations/$env:USERNAME.json"
if (-not (Test-Path -LiteralPath $Authorization -PathType Leaf)) { exit 3 }
try {
    & $Guard mdm deactivate --home $env:USERPROFILE --user $env:USERNAME --authorization-file $Authorization --json
    exit $LASTEXITCODE
} finally {
    # The SYSTEM/device-context remediation removes the authorization after the user assignment completes.
}
