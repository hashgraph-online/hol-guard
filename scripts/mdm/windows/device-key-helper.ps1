param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('create', 'inspect', 'delete', 'sign-health-lease', 'sign-protection-lease', 'sign-health-key-registration')]
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
$HealthLeaseDomain = [System.Text.Encoding]::UTF8.GetBytes("HOL-GUARD-HEALTH-LEASE-V1`0")
$HealthKeyRegistrationDomain = [System.Text.Encoding]::UTF8.GetBytes("HOL-GUARD-HEALTH-KEY-REGISTRATION-V1`0")
$MaximumClaimsBytes = 4096

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

function Emit-SignatureResult {
    param([byte[]]$Signature)
    [ordered]@{
        ok = $true
        signature = [Convert]::ToBase64String($Signature)
        signatureAlgorithm = 'ecdsa-p256-sha256'
        signatureEncoding = 'asn1-der'
    } | ConvertTo-Json -Compress
    exit 0
}

function Convert-P1363ToDer {
    param([byte[]]$Signature)
    if ($Signature.Length -ne 64) { throw 'invalid' }
    $EncodedIntegers = [System.Collections.Generic.List[byte]]::new()
    foreach ($Offset in @(0, 32)) {
        $First = $Offset
        while ($First -lt ($Offset + 31) -and $Signature[$First] -eq 0) { $First++ }
        $Length = ($Offset + 32) - $First
        $NeedsPositivePrefix = ($Signature[$First] -band 0x80) -ne 0
        $EncodedIntegers.Add(0x02)
        $EncodedIntegers.Add([byte]($Length + $(if ($NeedsPositivePrefix) { 1 } else { 0 })))
        if ($NeedsPositivePrefix) { $EncodedIntegers.Add(0) }
        for ($Index = $First; $Index -lt ($Offset + 32); $Index++) {
            $EncodedIntegers.Add($Signature[$Index])
        }
    }
    if ($EncodedIntegers.Count -gt 127) { throw 'invalid' }
    $Der = [System.Collections.Generic.List[byte]]::new()
    $Der.Add(0x30)
    $Der.Add([byte]$EncodedIntegers.Count)
    $Der.AddRange($EncodedIntegers)
    return $Der.ToArray()
}

function Get-SigningKeyId {
    param([string]$PublicKeyX963)
    $SpkiPrefix = [byte[]]@(
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00
    )
    $PublicBytes = [Convert]::FromBase64String($PublicKeyX963)
    if ($PublicBytes.Length -ne 65 -or $PublicBytes[0] -ne 4) { throw 'invalid' }
    $Spki = [byte[]]::new($SpkiPrefix.Length + $PublicBytes.Length)
    [Array]::Copy($SpkiPrefix, 0, $Spki, 0, $SpkiPrefix.Length)
    [Array]::Copy($PublicBytes, 0, $Spki, $SpkiPrefix.Length, $PublicBytes.Length)
    $Hasher = [System.Security.Cryptography.SHA256]::Create()
    try { $Digest = $Hasher.ComputeHash($Spki) } finally { $Hasher.Dispose() }
    return [Convert]::ToBase64String($Digest).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Read-HealthLeaseClaims {
    param([string]$ExpectedSigningKeyId)
    $Buffer = [char[]]::new($MaximumClaimsBytes + 1)
    $Count = [Console]::In.ReadBlock($Buffer, 0, $Buffer.Length)
    if ($Count -eq 0 -or $Count -gt $MaximumClaimsBytes) { throw 'invalid' }
    $Text = [string]::new($Buffer, 0, $Count)
    $Utf8 = [System.Text.UTF8Encoding]::new($false, $true)
    if ($Utf8.GetByteCount($Text) -gt $MaximumClaimsBytes) { throw 'invalid' }
    $Claims = $Text | ConvertFrom-Json
    $SequenceMatch = [regex]::Match($Text, '"sequence":([0-9]{1,20}),')
    if (-not $SequenceMatch.Success) { throw 'invalid' }
    $SequenceText = $SequenceMatch.Groups[1].Value
    $Sequence = [decimal]::Parse($SequenceText, [Globalization.CultureInfo]::InvariantCulture)
    $ExpectedKeys = @(
        'deviceId', 'installationGeneration', 'issuedAt', 'leaseExpiresAt', 'machineInstallationId',
        'previousLeaseDigest', 'previousLeaseKeyId', 'schemaVersion', 'sequence', 'signingKeyId',
        'snapshotDigest', 'snapshotSchemaVersion', 'workspaceId'
    )
    $ActualKeys = @($Claims.PSObject.Properties.Name)
    if (@(Compare-Object $ActualKeys $ExpectedKeys).Count -ne 0) { throw 'invalid' }
    if ($Claims.schemaVersion -ne 'hol-guard-health-lease.v1' -or
        $Claims.snapshotSchemaVersion -ne 'local-integrity-snapshot.v1' -or
        $Claims.workspaceId -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' -or
        $Claims.deviceId -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' -or
        $Claims.machineInstallationId -notmatch '^[0-9a-f]{32}$' -or
        $Claims.installationGeneration -notmatch '^[0-9a-f]{32}$' -or
        $Claims.issuedAt -notmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' -or
        $Claims.leaseExpiresAt -notmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' -or
        $Claims.snapshotDigest -notmatch '^[0-9a-f]{64}$' -or
        $Claims.signingKeyId -notmatch '^[A-Za-z0-9_-]{43}$' -or $Claims.signingKeyId -ne $ExpectedSigningKeyId -or
        $Sequence -lt 1 -or
        $Sequence -gt [decimal]::Parse('18446744073709551615', [Globalization.CultureInfo]::InvariantCulture)) {
        throw 'invalid'
    }
    $TimestampStyle = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    $IssuedAt = [DateTime]::ParseExact(
        $Claims.issuedAt, "yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture, $TimestampStyle
    )
    $ExpiresAt = [DateTime]::ParseExact(
        $Claims.leaseExpiresAt, "yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture, $TimestampStyle
    )
    $LeaseSeconds = ($ExpiresAt - $IssuedAt).TotalSeconds
    if ($LeaseSeconds -le 0 -or $LeaseSeconds -gt 3600) { throw 'invalid' }
    if ($Sequence -eq 1) {
        if ($null -ne $Claims.previousLeaseDigest -or $null -ne $Claims.previousLeaseKeyId) { throw 'invalid' }
    } elseif ($Claims.previousLeaseDigest -notmatch '^[0-9a-f]{64}$' -or
              $Claims.previousLeaseKeyId -notmatch '^[A-Za-z0-9_-]{43}$') {
        throw 'invalid'
    }
    $Canonical = [ordered]@{
        deviceId = $Claims.deviceId
        installationGeneration = $Claims.installationGeneration
        issuedAt = $Claims.issuedAt
        leaseExpiresAt = $Claims.leaseExpiresAt
        machineInstallationId = $Claims.machineInstallationId
        previousLeaseDigest = $Claims.previousLeaseDigest
        previousLeaseKeyId = $Claims.previousLeaseKeyId
        schemaVersion = $Claims.schemaVersion
        sequence = '!HOL_GUARD_SEQUENCE!'
        signingKeyId = $Claims.signingKeyId
        snapshotDigest = $Claims.snapshotDigest
        snapshotSchemaVersion = $Claims.snapshotSchemaVersion
        workspaceId = $Claims.workspaceId
    } | ConvertTo-Json -Compress
    $Canonical = $Canonical.Replace('"!HOL_GUARD_SEQUENCE!"', $SequenceText)
    if (-not [string]::Equals($Canonical, $Text, [System.StringComparison]::Ordinal)) { throw 'invalid' }
    return [System.Text.Encoding]::UTF8.GetBytes($Text)
}

function Read-ProtectionLease {
    param([string]$ExpectedSigningKeyId)
    $Buffer = [char[]]::new($MaximumClaimsBytes + 1)
    $Count = [Console]::In.ReadBlock($Buffer, 0, $Buffer.Length)
    if ($Count -eq 0 -or $Count -gt $MaximumClaimsBytes) { throw 'invalid' }
    $Text = [string]::new($Buffer, 0, $Count)
    $Utf8 = [System.Text.UTF8Encoding]::new($false, $true)
    if ($Utf8.GetByteCount($Text) -gt $MaximumClaimsBytes) { throw 'invalid' }
    $Lease = $Text | ConvertFrom-Json
    if (@(Compare-Object @($Lease.PSObject.Properties.Name) @('claims', 'schemaVersion')).Count -ne 0 -or
        $Lease.schemaVersion -ne 'protection-lease.v1') { throw 'invalid' }
    $Claims = $Lease.claims
    $ExpectedClaimKeys = @(
        'challenge', 'deviceId', 'installationGeneration', 'issuedAt', 'machineInstallationId',
        'previousLeaseDigest', 'sequence', 'signingKeyId', 'snapshotDigest', 'snapshotSchemaVersion',
        'validForSeconds', 'workspaceId'
    )
    if (@(Compare-Object @($Claims.PSObject.Properties.Name) $ExpectedClaimKeys).Count -ne 0 -or
        $Claims.snapshotSchemaVersion -ne 'local-integrity-snapshot.v1' -or
        $Claims.workspaceId -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' -or
        $Claims.deviceId -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' -or
        $Claims.machineInstallationId -notmatch '^[0-9a-f]{32}$' -or
        $Claims.installationGeneration -notmatch '^[0-9a-f]{32}$' -or
        $Claims.issuedAt -notmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' -or
        $Claims.snapshotDigest -notmatch '^[0-9a-f]{64}$' -or
        $Claims.signingKeyId -notmatch '^[A-Za-z0-9_-]{43}$' -or
        $Claims.signingKeyId -ne $ExpectedSigningKeyId -or
        $Claims.sequence -lt 1 -or $Claims.validForSeconds -lt 180 -or $Claims.validForSeconds -gt 1800) {
        throw 'invalid'
    }
    $Canonical = [ordered]@{
        claims = [ordered]@{
            challenge = $Claims.challenge
            deviceId = $Claims.deviceId
            installationGeneration = $Claims.installationGeneration
            issuedAt = $Claims.issuedAt
            machineInstallationId = $Claims.machineInstallationId
            previousLeaseDigest = $Claims.previousLeaseDigest
            sequence = $Claims.sequence
            signingKeyId = $Claims.signingKeyId
            snapshotDigest = $Claims.snapshotDigest
            snapshotSchemaVersion = $Claims.snapshotSchemaVersion
            validForSeconds = $Claims.validForSeconds
            workspaceId = $Claims.workspaceId
        }
        schemaVersion = $Lease.schemaVersion
    } | ConvertTo-Json -Compress -Depth 5
    if (-not [string]::Equals($Canonical, $Text, [System.StringComparison]::Ordinal)) { throw 'invalid' }
    return [System.Text.Encoding]::UTF8.GetBytes($Text)
}

function Read-HealthKeyRegistration {
    param([string]$ExpectedSigningKeyId)
    $Buffer = [char[]]::new($MaximumClaimsBytes + 1)
    $Count = [Console]::In.ReadBlock($Buffer, 0, $Buffer.Length)
    if ($Count -eq 0 -or $Count -gt $MaximumClaimsBytes) { throw 'invalid' }
    $Text = [string]::new($Buffer, 0, $Count)
    $Registration = $Text | ConvertFrom-Json
    $ExpectedKeys = @(
        'algorithm', 'deviceId', 'installationGeneration', 'keyId', 'machineInstallationId',
        'previousInstallationGeneration', 'publicKeySpki', 'registeredAt', 'schemaVersion', 'workspaceId'
    )
    if (@(Compare-Object @($Registration.PSObject.Properties.Name) $ExpectedKeys).Count -ne 0 -or
        $Registration.schemaVersion -ne 'hol-guard-health-key-registration.v1' -or
        $Registration.algorithm -ne 'ecdsa-p256-sha256' -or
        $Registration.workspaceId -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' -or
        $Registration.deviceId -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' -or
        $Registration.machineInstallationId -notmatch '^[0-9a-f]{32}$' -or
        $Registration.installationGeneration -notmatch '^[0-9a-f]{32}$' -or
        $Registration.keyId -notmatch '^[A-Za-z0-9_-]{43}$' -or
        $Registration.keyId -ne $ExpectedSigningKeyId -or
        $Registration.registeredAt -notmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$') {
        throw 'invalid'
    }
    $Canonical = [ordered]@{
        algorithm = $Registration.algorithm
        deviceId = $Registration.deviceId
        installationGeneration = $Registration.installationGeneration
        keyId = $Registration.keyId
        machineInstallationId = $Registration.machineInstallationId
        previousInstallationGeneration = $Registration.previousInstallationGeneration
        publicKeySpki = $Registration.publicKeySpki
        registeredAt = $Registration.registeredAt
        schemaVersion = $Registration.schemaVersion
        workspaceId = $Registration.workspaceId
    } | ConvertTo-Json -Compress
    if (-not [string]::Equals($Canonical, $Text, [System.StringComparison]::Ordinal)) { throw 'invalid' }
    return [System.Text.Encoding]::UTF8.GetBytes($Text)
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
    $HealthLeaseSignature = $null
    try {
        $PublicKey = Inspect-Key $Key $ProviderName
        if ($Verb -eq 'sign-health-lease' -or $Verb -eq 'sign-protection-lease' -or
            $Verb -eq 'sign-health-key-registration') {
            if ($Verb -eq 'sign-health-lease') {
                $ClaimsBytes = Read-HealthLeaseClaims (Get-SigningKeyId $PublicKey)
                $Message = [byte[]]::new($HealthLeaseDomain.Length + $ClaimsBytes.Length)
                [Array]::Copy($HealthLeaseDomain, 0, $Message, 0, $HealthLeaseDomain.Length)
                [Array]::Copy($ClaimsBytes, 0, $Message, $HealthLeaseDomain.Length, $ClaimsBytes.Length)
            } elseif ($Verb -eq 'sign-protection-lease') {
                $Message = Read-ProtectionLease (Get-SigningKeyId $PublicKey)
            } else {
                $RegistrationBytes = Read-HealthKeyRegistration (Get-SigningKeyId $PublicKey)
                $Message = [byte[]]::new($HealthKeyRegistrationDomain.Length + $RegistrationBytes.Length)
                [Array]::Copy($HealthKeyRegistrationDomain, 0, $Message, 0, $HealthKeyRegistrationDomain.Length)
                [Array]::Copy(
                    $RegistrationBytes, 0, $Message, $HealthKeyRegistrationDomain.Length, $RegistrationBytes.Length
                )
            }
            $Signer = [System.Security.Cryptography.ECDsaCng]::new($Key)
            try {
                $P1363 = $Signer.SignData($Message, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
                if (-not $Signer.VerifyData($Message, $P1363, [System.Security.Cryptography.HashAlgorithmName]::SHA256)) {
                    throw 'invalid'
                }
                $HealthLeaseSignature = Convert-P1363ToDer $P1363
            } finally {
                $Signer.Dispose()
            }
        }
    } finally {
        $Key.Dispose()
    }
    if ($null -ne $HealthLeaseSignature) {
        Emit-SignatureResult $HealthLeaseSignature
    }
    Emit-Result $true 'active' $ProtectionLevel $PublicKey 'device_key_active' 0
} catch {
    Emit-Result $false 'unknown' 'unknown' $null 'device_key_probe_failed' 2
}
