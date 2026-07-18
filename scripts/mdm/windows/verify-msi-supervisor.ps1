param(
    [Parameter(Mandatory = $true)]
    [string]$MsiPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Open-MsiView {
    param([object]$Database, [string]$Query)
    $View = $Database.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $Database, @($Query))
    $null = $View.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $View, $null)
    return $View
}

function Fetch-MsiRecord {
    param([object]$View)
    return $View.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $View, $null)
}

$ResolvedMsi = (Resolve-Path -LiteralPath $MsiPath).Path
$Installer = New-Object -ComObject WindowsInstaller.Installer
$Database = $Installer.GetType().InvokeMember(
    'OpenDatabase', 'InvokeMethod', $null, $Installer, @($ResolvedMsi, 0)
)
$ExpectedTargets = @{
    ProvisionMachineDeviceKey = '"[InstallFolder]hol-guard\hol-guard.exe" mdm device-key-provision --json'
    InstallMachineHealthTask = '"[InstallFolder]hol-guard\hol-guard.exe" mdm supervisor-install --json'
    RollbackInstallMachineHealthTask = '"[InstallFolder]hol-guard\hol-guard.exe" mdm supervisor-remove --json'
    RemoveMachineHealthTask = '"[InstallFolder]hol-guard\hol-guard.exe" mdm supervisor-remove --json'
    RollbackRemoveMachineHealthTask = '"[InstallFolder]hol-guard\hol-guard.exe" mdm supervisor-install --json'
}
$ActionView = Open-MsiView $Database (
    'SELECT `Action`, `Type`, `Source`, `Target` FROM `CustomAction` ' +
    "WHERE `Action`='ProvisionMachineDeviceKey' OR `Action`='InstallMachineHealthTask' " +
    "OR `Action`='RollbackInstallMachineHealthTask' " +
    "OR `Action`='RemoveMachineHealthTask' OR `Action`='RollbackRemoveMachineHealthTask'"
)
$Observed = @{}
while ($null -ne ($Record = Fetch-MsiRecord $ActionView)) {
    $Action = $Record.GetType().InvokeMember('StringData', 'GetProperty', $null, $Record, @(1))
    $Type = $Record.GetType().InvokeMember('IntegerData', 'GetProperty', $null, $Record, @(2))
    $Source = $Record.GetType().InvokeMember('StringData', 'GetProperty', $null, $Record, @(3))
    $Target = $Record.GetType().InvokeMember('StringData', 'GetProperty', $null, $Record, @(4))
    if (-not $ExpectedTargets.ContainsKey($Action) -or $Observed.ContainsKey($Action)) {
        throw "Unexpected or duplicate supervisor custom action: $Action."
    }
    if ($Source -ne 'InstallFolder' -or $Target -ne $ExpectedTargets[$Action]) {
        throw "Invalid supervisor custom action target: $Action."
    }
    if (($Type -band 0xC00) -ne 0xC00) {
        throw "Supervisor custom action must be deferred and non-impersonating: $Action."
    }
    $ShouldRollback = $Action.StartsWith('Rollback')
    if ((($Type -band 0x100) -ne 0) -ne $ShouldRollback) {
        throw "Supervisor custom action rollback type is invalid: $Action."
    }
    if ((($Type -band 0x40) -ne 0) -ne $ShouldRollback) {
        throw "Supervisor custom action return semantics are invalid: $Action."
    }
    $Observed[$Action] = $true
}
if ($Observed.Count -ne $ExpectedTargets.Count) {
    throw 'One or more supervisor custom actions are absent from the MSI.'
}

$SequenceView = Open-MsiView $Database (
    'SELECT `Action`, `Condition`, `Sequence` FROM `InstallExecuteSequence` ' +
    "WHERE `Action`='ProvisionMachineDeviceKey' OR `Action`='InstallMachineHealthTask' " +
    "OR `Action`='RollbackInstallMachineHealthTask' " +
    "OR `Action`='RemoveMachineHealthTask' OR `Action`='RollbackRemoveMachineHealthTask' " +
    "OR `Action`='InstallFiles' OR `Action`='RemoveFiles' OR `Action`='InstallFinalize'"
)
$Sequences = @{}
$Conditions = @{}
while ($null -ne ($Record = Fetch-MsiRecord $SequenceView)) {
    $Action = $Record.GetType().InvokeMember('StringData', 'GetProperty', $null, $Record, @(1))
    $Conditions[$Action] = $Record.GetType().InvokeMember('StringData', 'GetProperty', $null, $Record, @(2))
    $Sequences[$Action] = $Record.GetType().InvokeMember('IntegerData', 'GetProperty', $null, $Record, @(3))
}
foreach ($Action in @('ProvisionMachineDeviceKey', 'InstallMachineHealthTask', 'RollbackInstallMachineHealthTask',
        'RemoveMachineHealthTask', 'RollbackRemoveMachineHealthTask', 'InstallFiles', 'RemoveFiles', 'InstallFinalize')) {
    if (-not $Sequences.ContainsKey($Action)) { throw "Missing MSI sequence row: $Action." }
}
if ($Conditions['InstallMachineHealthTask'] -ne 'NOT (REMOVE~="ALL")') {
    throw 'Supervisor install action condition is invalid.'
}
if ($Conditions['ProvisionMachineDeviceKey'] -ne 'NOT (REMOVE~="ALL")') {
    throw 'Device-key provision action condition is invalid.'
}
if ($Conditions['RollbackInstallMachineHealthTask'] -ne 'NOT (REMOVE~="ALL")') {
    throw 'Supervisor install rollback action condition is invalid.'
}
if ($Conditions['RemoveMachineHealthTask'] -ne 'REMOVE~="ALL"') {
    throw 'Supervisor removal action condition is invalid.'
}
if ($Conditions['RollbackRemoveMachineHealthTask'] -ne 'REMOVE~="ALL"') {
    throw 'Supervisor removal rollback action condition is invalid.'
}
if ($Sequences['InstallMachineHealthTask'] -le $Sequences['InstallFiles'] -or
    $Sequences['InstallMachineHealthTask'] -ge $Sequences['InstallFinalize']) {
    throw 'Supervisor install action is sequenced outside the protected post-file window.'
}
if ($Sequences['ProvisionMachineDeviceKey'] -le $Sequences['InstallFiles'] -or
    $Sequences['ProvisionMachineDeviceKey'] -ge $Sequences['RollbackInstallMachineHealthTask']) {
    throw 'Device-key provision action must precede supervisor mutation.'
}
if ($Sequences['RollbackInstallMachineHealthTask'] -le $Sequences['ProvisionMachineDeviceKey'] -or
    $Sequences['RollbackInstallMachineHealthTask'] -ge $Sequences['InstallMachineHealthTask']) {
    throw 'Supervisor install rollback action must precede the protected install action.'
}
if ($Sequences['RemoveMachineHealthTask'] -ge $Sequences['RemoveFiles']) {
    throw 'Supervisor removal action must run before files are removed.'
}
if ($Sequences['RollbackRemoveMachineHealthTask'] -ge $Sequences['RemoveMachineHealthTask']) {
    throw 'Supervisor removal rollback action must precede the protected removal action.'
}
