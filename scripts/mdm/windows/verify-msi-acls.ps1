param(
    [Parameter(Mandatory = $true)]
    [string]$MsiPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ResolvedMsi = (Resolve-Path -LiteralPath $MsiPath).Path
$Installer = New-Object -ComObject WindowsInstaller.Installer
$Database = $Installer.GetType().InvokeMember(
    'OpenDatabase', 'InvokeMethod', $null, $Installer, @($ResolvedMsi, 0)
)
$View = $Database.GetType().InvokeMember(
    'OpenView', 'InvokeMethod', $null, $Database,
    @('SELECT `LockObject`, `Table`, `SDDLText`, `Condition` FROM `MsiLockPermissionsEx`')
)
$null = $View.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $View, $null)
$Rows = @()
while ($null -ne ($Record = $View.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $View, $null))) {
    $Rows += [PSCustomObject]@{
        LockObject = $Record.GetType().InvokeMember('StringData', 'GetProperty', $null, $Record, @(1))
        Table = $Record.GetType().InvokeMember('StringData', 'GetProperty', $null, $Record, @(2))
        Sddl = $Record.GetType().InvokeMember('StringData', 'GetProperty', $null, $Record, @(3))
        Condition = $Record.GetType().InvokeMember('StringData', 'GetProperty', $null, $Record, @(4))
    }
}

$Expected = @{
    InstallFolder = 'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)'
    StateFolder = 'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
    LogsFolder = 'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
}
if ($Rows.Count -ne $Expected.Count) {
    throw "Expected exactly $($Expected.Count) MSI ACL records; found $($Rows.Count)."
}
foreach ($Row in $Rows) {
    if (-not $Expected.ContainsKey($Row.LockObject)) {
        throw "Unexpected MSI ACL target: $($Row.LockObject)."
    }
    if ($Row.Table -ne 'CreateFolder' -or $Row.Sddl -ne $Expected[$Row.LockObject]) {
        throw "Invalid MSI ACL record for $($Row.LockObject)."
    }
    if (-not [string]::IsNullOrEmpty($Row.Condition)) {
        throw "MSI ACL record for $($Row.LockObject) must be unconditional."
    }
    $Expected.Remove($Row.LockObject)
}
if ($Expected.Count -ne 0) {
    throw 'One or more required MSI ACL targets are absent.'
}
