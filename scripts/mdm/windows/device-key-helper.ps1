param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('create', 'inspect', 'delete')]
    [string]$Verb,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{32}$')]
    [string]$Generation
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$KeyPrefix = 'HOLGuard.DeviceKey.'
$KeyName = $KeyPrefix + $Generation
$PlatformProvider = 'Microsoft Platform Crypto Provider'
$SoftwareProvider = 'Microsoft Software Key Storage Provider'
$ProtectedSddl = 'O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)'

function Emit-Result {
    param(
        [bool]$Ok,
        [string]$State,
        [string]$ProtectionLevel,
        [AllowNull()][string]$PublicKeyX963,
        [string]$ReasonCode,
        [int]$ExitCode
    )
    [ordered]@{
        ok = $Ok
        state = $State
        protectionLevel = $ProtectionLevel
        publicKeyX963 = $PublicKeyX963
        reasonCode = $ReasonCode
    } | ConvertTo-Json -Compress
    exit $ExitCode
}

function Get-SecurityDescriptorBytes {
    $Descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($ProtectedSddl)
    $Bytes = [byte[]]::new($Descriptor.BinaryLength)
    $Descriptor.GetBinaryForm($Bytes, 0)
    return $Bytes
}

function Open-Key {
    param([string]$ProviderName)
    $Provider = [System.Security.Cryptography.CngProvider]::new($ProviderName)
    $Options = [System.Security.Cryptography.CngKeyOpenOptions]::MachineKey
    if (-not [System.Security.Cryptography.CngKey]::Exists($KeyName, $Provider, $Options)) {
        return $null
    }
    return [System.Security.Cryptography.CngKey]::Open($KeyName, $Provider, $Options)
}

function Create-Key {
    param([string]$ProviderName)
    $Parameters = [System.Security.Cryptography.CngKeyCreationParameters]::new()
    $Parameters.Provider = [System.Security.Cryptography.CngProvider]::new($ProviderName)
    $Parameters.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::MachineKey
    $Parameters.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::None
    $Parameters.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::Signing
    $SecurityProperty = [System.Security.Cryptography.CngProperty]::new(
        'Security Descr',
        (Get-SecurityDescriptorBytes),
        [System.Security.Cryptography.CngPropertyOptions]::Persist
    )
    $Parameters.Parameters.Add($SecurityProperty)
    return [System.Security.Cryptography.CngKey]::Create(
        [System.Security.Cryptography.CngAlgorithm]::ECDsaP256,
        $KeyName,
        $Parameters
    )
}

function Find-Keys {
    $Found = @()
    foreach ($ProviderName in @($PlatformProvider, $SoftwareProvider)) {
        $Key = Open-Key $ProviderName
        if ($null -ne $Key) {
            $Found += [pscustomobject]@{ Key = $Key; Provider = $ProviderName }
        }
    }
    return $Found
}

function Inspect-Key {
    param([System.Security.Cryptography.CngKey]$Key, [string]$ProviderName)
    if (-not $Key.IsMachineKey -or
        $Key.Algorithm.Algorithm -ne [System.Security.Cryptography.CngAlgorithm]::ECDsaP256.Algorithm -or
        $Key.KeyUsage -ne [System.Security.Cryptography.CngKeyUsages]::Signing -or
        $Key.ExportPolicy -ne [System.Security.Cryptography.CngExportPolicies]::None -or
        $Key.Provider.Provider -ne $ProviderName) {
        throw 'invalid'
    }
    $SecurityBytes = $Key.GetProperty('Security Descr', [System.Security.Cryptography.CngPropertyOptions]::None).GetValue()
    $Descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($SecurityBytes, 0)
    if ($Descriptor.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All) -ne $ProtectedSddl) {
        throw 'invalid'
    }
    $PublicBlob = $Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
    if ($PublicBlob.Length -ne 72) {
        throw 'invalid'
    }
    $PublicX963 = [byte[]]::new(65)
    $PublicX963[0] = 4
    [Array]::Copy($PublicBlob, 8, $PublicX963, 1, 64)
    $Challenge = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($Challenge)
    $Signer = [System.Security.Cryptography.ECDsaCng]::new($Key)
    try {
        $Signature = $Signer.SignData($Challenge, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        if (-not $Signer.VerifyData($Challenge, $Signature, [System.Security.Cryptography.HashAlgorithmName]::SHA256)) {
            throw 'invalid'
        }
    } finally {
        $Signer.Dispose()
    }
    return [Convert]::ToBase64String($PublicX963)
}

if ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') {
    Emit-Result $false 'unknown' 'unknown' $null 'device_key_system_context_required' 2
}

try {
    if ($Verb -eq 'delete') {
        $FoundKeys = @(Find-Keys)
        foreach ($Found in $FoundKeys) {
            try { $Found.Key.Delete() } finally { $Found.Key.Dispose() }
        }
        Emit-Result $true 'absent' 'unknown' $null 'device_key_absent' 0
    }
    $FoundKeys = @(Find-Keys)
    if ($FoundKeys.Count -gt 1) {
        foreach ($Duplicate in $FoundKeys) { $Duplicate.Key.Dispose() }
        throw 'invalid'
    }
    $Found = if ($FoundKeys.Count -eq 1) { $FoundKeys[0] } else { $null }
    if ($Verb -eq 'create') {
        if ($null -ne $Found) {
            $Found.Key.Dispose()
            Emit-Result $false 'tampered' 'unknown' $null 'device_key_generation_collision' 2
        }
        try {
            $Key = Create-Key $PlatformProvider
            $ProviderName = $PlatformProvider
            $ProtectionLevel = 'hardware-backed'
        } catch {
            $PlatformError = '{0:X8}' -f ($_.Exception.HResult -band 0xffffffff)
            if ($PlatformError -notin @('80090013', '80090029', '80090030')) {
                throw
            }
            $Key = Create-Key $SoftwareProvider
            $ProviderName = $SoftwareProvider
            $ProtectionLevel = 'os-protected'
        }
    } else {
        if ($null -eq $Found) {
            Emit-Result $false 'absent' 'unknown' $null 'device_key_absent' 1
        }
        $Key = $Found.Key
        $ProviderName = $Found.Provider
        $ProtectionLevel = if ($ProviderName -eq $PlatformProvider) { 'hardware-backed' } else { 'os-protected' }
    }
    try {
        $PublicKey = Inspect-Key $Key $ProviderName
    } finally {
        $Key.Dispose()
    }
    Emit-Result $true 'active' $ProtectionLevel $PublicKey 'device_key_active' 0
} catch {
    Emit-Result $false 'unknown' 'unknown' $null 'device_key_probe_failed' 2
}
