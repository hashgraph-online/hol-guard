import Foundation
import Security
import CryptoKit

private let labelPrefix = "org.hol.guard.device-key."
private let systemKeychainPath = "/Library/Keychains/System.keychain"
private let installedHelperPath = "/Library/Application Support/HOL Guard/hol-guard-device-key"
private let generationPattern = try! NSRegularExpression(pattern: "^[0-9a-f]{32}$")
private let digestPattern = try! NSRegularExpression(pattern: "^[0-9a-f]{64}$")
private let keyIdPattern = try! NSRegularExpression(pattern: "^[A-Za-z0-9_-]{43}$")
private let timestampPattern = try! NSRegularExpression(pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
private let safeIdPattern = try! NSRegularExpression(pattern: "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
private let healthLeaseDomain = Data("HOL-GUARD-HEALTH-LEASE-V1\0".utf8)
private let healthKeyRegistrationDomain = Data("HOL-GUARD-HEALTH-KEY-REGISTRATION-V1\0".utf8)
private let maximumClaimsBytes = 4096
private let p256IntegerBytes = 32

private enum HelperError: Error {
    case denied
    case invalidRequest
    case keychainUnavailable
    case keyAbsent
    case keyInvalid
    case operationFailed
}

private struct PublicResult: Encodable {
    let ok: Bool
    let state: String
    let protectionLevel: String
    let publicKeyX963: String?
    let reasonCode: String
}

private struct SignatureResult: Encodable {
    let ok: Bool
    let signature: String
    let signatureAlgorithm: String
    let signatureEncoding: String
}

private func emit(_ result: PublicResult, exitCode: Int32) -> Never {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    if let data = try? encoder.encode(result) {
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data([0x0A]))
    }
    exit(exitCode)
}

private func emitSignature(_ signature: Data) -> Never {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let result = SignatureResult(ok: true, signature: signature.base64EncodedString(),
                                 signatureAlgorithm: "ecdsa-p256-sha256", signatureEncoding: "asn1-der")
    guard let data = try? encoder.encode(result) else {
        fail("device_key_probe_failed")
    }
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data([0x0A]))
    exit(0)
}

private func fail(_ reason: String) -> Never {
    emit(PublicResult(ok: false, state: "unknown", protectionLevel: "unknown", publicKeyX963: nil,
                      reasonCode: reason), exitCode: 2)
}

private func validatedGeneration(_ value: String) throws -> String {
    let range = NSRange(value.startIndex..<value.endIndex, in: value)
    guard generationPattern.firstMatch(in: value, range: range)?.range == range else {
        throw HelperError.invalidRequest
    }
    return value
}

private func matches(_ value: String, pattern: NSRegularExpression) -> Bool {
    let range = NSRange(value.startIndex..<value.endIndex, in: value)
    return pattern.firstMatch(in: value, range: range)?.range == range
}

private func requiredString(_ claims: [String: Any], _ key: String, maximumLength: Int,
                            pattern: NSRegularExpression? = nil) throws -> String {
    guard let value = claims[key] as? String, !value.isEmpty, value.utf8.count <= maximumLength else {
        throw HelperError.invalidRequest
    }
    if let requiredPattern = pattern, !matches(value, pattern: requiredPattern) {
        throw HelperError.invalidRequest
    }
    return value
}

private func signingKeyId(publicKeyX963: Data) throws -> String {
    let spkiPrefix = Data([0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
                           0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00])
    guard publicKeyX963.count == 65, publicKeyX963.first == 0x04 else { throw HelperError.keyInvalid }
    let digest = Data(SHA256.hash(data: spkiPrefix + publicKeyX963))
    return digest.base64EncodedString().replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}

private func validateCanonicalHealthLeaseClaims(_ data: Data, expectedSigningKeyId: String) throws {
    guard !data.isEmpty, data.count <= maximumClaimsBytes,
          let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw HelperError.invalidRequest
    }
    let expectedKeys: Set<String> = [
        "deviceId", "installationGeneration", "issuedAt", "leaseExpiresAt", "machineInstallationId",
        "previousLeaseDigest", "previousLeaseKeyId", "schemaVersion", "sequence", "signingKeyId",
        "snapshotDigest", "snapshotSchemaVersion", "workspaceId",
    ]
    guard Set(object.keys) == expectedKeys,
          object["schemaVersion"] as? String == "hol-guard-health-lease.v1",
          object["snapshotSchemaVersion"] as? String == "local-integrity-snapshot.v1" else {
        throw HelperError.invalidRequest
    }
    _ = try requiredString(object, "workspaceId", maximumLength: 128, pattern: safeIdPattern)
    _ = try requiredString(object, "deviceId", maximumLength: 128, pattern: safeIdPattern)
    _ = try requiredString(object, "machineInstallationId", maximumLength: 32, pattern: generationPattern)
    _ = try requiredString(object, "installationGeneration", maximumLength: 32, pattern: generationPattern)
    let issuedText = try requiredString(object, "issuedAt", maximumLength: 20, pattern: timestampPattern)
    let expiresText = try requiredString(object, "leaseExpiresAt", maximumLength: 20, pattern: timestampPattern)
    _ = try requiredString(object, "snapshotDigest", maximumLength: 64, pattern: digestPattern)
    let claimedSigningKeyId = try requiredString(object, "signingKeyId", maximumLength: 43, pattern: keyIdPattern)
    guard claimedSigningKeyId == expectedSigningKeyId else { throw HelperError.invalidRequest }
    guard let maximumSequence = Decimal(string: "18446744073709551615"),
          let sequence = object["sequence"] as? NSNumber,
          CFGetTypeID(sequence) != CFBooleanGetTypeID(), sequence.decimalValue >= 1,
          sequence.decimalValue <= maximumSequence,
          sequence.decimalValue == Decimal(sequence.uint64Value) else {
        throw HelperError.invalidRequest
    }
    let timestampFormatter = DateFormatter()
    timestampFormatter.locale = Locale(identifier: "en_US_POSIX")
    timestampFormatter.timeZone = TimeZone(secondsFromGMT: 0)
    timestampFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
    timestampFormatter.isLenient = false
    guard let issuedAt = timestampFormatter.date(from: issuedText),
          let expiresAt = timestampFormatter.date(from: expiresText),
          expiresAt.timeIntervalSince(issuedAt) > 0,
          expiresAt.timeIntervalSince(issuedAt) <= 3600 else {
        throw HelperError.invalidRequest
    }
    let previousDigest = object["previousLeaseDigest"]
    let previousKeyId = object["previousLeaseKeyId"]
    if sequence.uint64Value == 1 {
        guard previousDigest is NSNull, previousKeyId is NSNull else { throw HelperError.invalidRequest }
    } else {
        guard let digest = previousDigest as? String, matches(digest, pattern: digestPattern),
              let keyId = previousKeyId as? String, matches(keyId, pattern: keyIdPattern) else {
            throw HelperError.invalidRequest
        }
    }
    // Every v1 string claim is ASCII-only. Comparing the exact bytes supplied by Python keeps
    // the helper and verifier on one canonical representation; a broader schema requires v2.
    let canonical = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    guard canonical == data else { throw HelperError.invalidRequest }
}

private func validateCanonicalProtectionLease(_ data: Data, expectedSigningKeyId: String) throws {
    guard !data.isEmpty, data.count <= maximumClaimsBytes,
          let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
          Set(object.keys) == ["claims", "schemaVersion"],
          object["schemaVersion"] as? String == "protection-lease.v1",
          let claims = object["claims"] as? [String: Any] else {
        throw HelperError.invalidRequest
    }
    let expectedClaimKeys: Set<String> = [
        "challenge", "deviceId", "installationGeneration", "issuedAt", "machineInstallationId",
        "previousLeaseDigest", "sequence", "signingKeyId", "snapshotDigest",
        "snapshotSchemaVersion", "validForSeconds", "workspaceId",
    ]
    guard Set(claims.keys) == expectedClaimKeys,
          claims["snapshotSchemaVersion"] as? String == "local-integrity-snapshot.v1",
          try requiredString(claims, "signingKeyId", maximumLength: 43, pattern: keyIdPattern)
            == expectedSigningKeyId else {
        throw HelperError.invalidRequest
    }
    _ = try requiredString(claims, "workspaceId", maximumLength: 128, pattern: safeIdPattern)
    _ = try requiredString(claims, "deviceId", maximumLength: 128, pattern: safeIdPattern)
    _ = try requiredString(claims, "machineInstallationId", maximumLength: 32, pattern: generationPattern)
    _ = try requiredString(claims, "installationGeneration", maximumLength: 32, pattern: generationPattern)
    _ = try requiredString(claims, "issuedAt", maximumLength: 20, pattern: timestampPattern)
    _ = try requiredString(claims, "snapshotDigest", maximumLength: 64, pattern: digestPattern)
    guard let sequence = claims["sequence"] as? NSNumber,
          CFGetTypeID(sequence) != CFBooleanGetTypeID(), sequence.uint64Value >= 1,
          let validForSeconds = claims["validForSeconds"] as? NSNumber,
          CFGetTypeID(validForSeconds) != CFBooleanGetTypeID(),
          validForSeconds.intValue >= 180, validForSeconds.intValue <= 1800 else {
        throw HelperError.invalidRequest
    }
    let canonical = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    guard canonical == data else { throw HelperError.invalidRequest }
}

private func validateCanonicalHealthKeyRegistration(_ data: Data, expectedSigningKeyId: String) throws {
    guard !data.isEmpty, data.count <= maximumClaimsBytes,
          let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw HelperError.invalidRequest
    }
    let expectedKeys: Set<String> = [
        "algorithm", "deviceId", "installationGeneration", "keyId", "machineInstallationId",
        "previousInstallationGeneration", "publicKeySpki", "registeredAt", "schemaVersion", "workspaceId",
    ]
    guard Set(object.keys) == expectedKeys,
          object["schemaVersion"] as? String == "hol-guard-health-key-registration.v1",
          object["algorithm"] as? String == "ecdsa-p256-sha256",
          try requiredString(object, "keyId", maximumLength: 43, pattern: keyIdPattern) == expectedSigningKeyId else {
        throw HelperError.invalidRequest
    }
    _ = try requiredString(object, "workspaceId", maximumLength: 128, pattern: safeIdPattern)
    _ = try requiredString(object, "deviceId", maximumLength: 128, pattern: safeIdPattern)
    _ = try requiredString(object, "machineInstallationId", maximumLength: 32, pattern: generationPattern)
    _ = try requiredString(object, "installationGeneration", maximumLength: 32, pattern: generationPattern)
    _ = try requiredString(object, "registeredAt", maximumLength: 20, pattern: timestampPattern)
    _ = try requiredString(object, "publicKeySpki", maximumLength: 1024)
    let canonical = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    guard canonical == data else { throw HelperError.invalidRequest }
}

private func validateCanonicalDERSignature(_ signature: Data) throws {
    let bytes = [UInt8](signature)
    guard bytes.count >= 8, bytes.count <= 72, bytes[0] == 0x30,
          Int(bytes[1]) == bytes.count - 2 else { throw HelperError.keyInvalid }
    var offset = 2
    for _ in 0..<2 {
        guard offset + 2 <= bytes.count, bytes[offset] == 0x02 else { throw HelperError.keyInvalid }
        let length = Int(bytes[offset + 1])
        offset += 2
        guard length >= 1, length <= p256IntegerBytes + 1, offset + length <= bytes.count,
              bytes[offset] & 0x80 == 0,
              !(length > 1 && bytes[offset] == 0 && bytes[offset + 1] & 0x80 == 0),
              !(length == 1 && bytes[offset] == 0) else { throw HelperError.keyInvalid }
        if length == p256IntegerBytes + 1 && bytes[offset] != 0 { throw HelperError.keyInvalid }
        offset += length
    }
    guard offset == bytes.count else { throw HelperError.keyInvalid }
}

private func openSystemKeychain() throws -> SecKeychain {
    var keychain: SecKeychain?
    guard SecKeychainOpen(systemKeychainPath, &keychain) == errSecSuccess, let resolved = keychain else {
        throw HelperError.keychainUnavailable
    }
    return resolved
}

private func keyQuery(generation: String, keychain: SecKeychain, returnReference: Bool) -> [CFString: Any] {
    var query: [CFString: Any] = [
        kSecClass: kSecClassKey,
        kSecAttrKeyClass: kSecAttrKeyClassPrivate,
        kSecAttrApplicationTag: Data((labelPrefix + generation).utf8),
        kSecMatchLimit: kSecMatchLimitOne,
        kSecUseKeychain: keychain,
        kSecUseAuthenticationUI: kSecUseAuthenticationUIFail,
    ]
    if returnReference {
        query[kSecReturnRef] = true
    }
    return query
}

private func copyPrivateKey(generation: String, keychain: SecKeychain) throws -> SecKey {
    var result: CFTypeRef?
    let status = SecItemCopyMatching(keyQuery(generation: generation, keychain: keychain, returnReference: true) as CFDictionary,
                                     &result)
    if status == errSecItemNotFound {
        throw HelperError.keyAbsent
    }
    guard status == errSecSuccess, let key = result as! SecKey? else {
        throw HelperError.operationFailed
    }
    return key
}

private func inspectKey(_ privateKey: SecKey) throws -> Data {
    guard let attributes = SecKeyCopyAttributes(privateKey) as? [CFString: Any],
          attributes[kSecAttrKeyType] as? String == kSecAttrKeyTypeECSECPrimeRandom as String,
          attributes[kSecAttrKeySizeInBits] as? Int == 256,
          attributes[kSecAttrCanSign] as? Bool == true,
          attributes[kSecAttrCanDecrypt] as? Bool != true,
          attributes[kSecAttrCanDerive] as? Bool != true,
          attributes[kSecAttrCanUnwrap] as? Bool != true,
          attributes[kSecAttrIsExtractable] as? Bool == false,
          let publicKey = SecKeyCopyPublicKey(privateKey),
          let publicData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
        throw HelperError.keyInvalid
    }
    try inspectSigningAccess(privateKey)
    let challenge = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
    guard let signature = SecKeyCreateSignature(privateKey, .ecdsaSignatureMessageX962SHA256,
                                                challenge as CFData, nil) as Data?,
          SecKeyVerifySignature(publicKey, .ecdsaSignatureMessageX962SHA256,
                                challenge as CFData, signature as CFData, nil) else {
        throw HelperError.keyInvalid
    }
    return publicData
}

private func inspectSigningAccess(_ privateKey: SecKey) throws {
    var access: SecAccess?
    let keychainItem = privateKey as AnyObject as! SecKeychainItem
    guard SecKeychainItemCopyAccess(keychainItem, &access) == errSecSuccess, let resolvedAccess = access else {
        throw HelperError.keyInvalid
    }
    var aclList: CFArray?
    guard SecAccessCopyACLList(resolvedAccess, &aclList) == errSecSuccess,
          let entries = aclList as? [SecACL],
          entries.count == 1 else {
        throw HelperError.keyInvalid
    }
    let entry = entries[0]
    guard let authorizations = SecACLCopyAuthorizations(entry) as? [CFString],
          authorizations.count == 1,
          CFEqual(authorizations[0], kSecACLAuthorizationSign) else {
        throw HelperError.keyInvalid
    }
    var applications: CFArray?
    var description: CFString?
    var selector = SecKeychainPromptSelector()
    guard SecACLCopyContents(entry, &applications, &description, &selector) == errSecSuccess,
          let trustedApplications = applications as? [SecTrustedApplication],
          trustedApplications.count == 1 else {
        throw HelperError.keyInvalid
    }
    var expectedApplication: SecTrustedApplication?
    guard SecTrustedApplicationCreateFromPath(installedHelperPath, &expectedApplication) == errSecSuccess,
          let expected = expectedApplication else {
        throw HelperError.keyInvalid
    }
    var actualData: CFData?
    var expectedData: CFData?
    guard SecTrustedApplicationCopyData(trustedApplications[0], &actualData) == errSecSuccess,
          SecTrustedApplicationCopyData(expected, &expectedData) == errSecSuccess,
          let actual = actualData,
          let expectedIdentity = expectedData,
          CFEqual(actual, expectedIdentity) else {
        throw HelperError.keyInvalid
    }
}

private func restrictAccessToSigning(_ access: SecAccess) throws {
    var aclList: CFArray?
    guard SecAccessCopyACLList(access, &aclList) == errSecSuccess,
          let entries = aclList as? [SecACL],
          entries.count == 1,
          SecACLUpdateAuthorizations(entries[0], [kSecACLAuthorizationSign] as CFArray) == errSecSuccess else {
        throw HelperError.operationFailed
    }
}

private func createKey(generation: String, keychain: SecKeychain) throws -> SecKey {
    var trustedApplication: SecTrustedApplication?
    guard SecTrustedApplicationCreateFromPath(installedHelperPath, &trustedApplication) == errSecSuccess,
          let trusted = trustedApplication else {
        throw HelperError.operationFailed
    }
    var access: SecAccess?
    guard SecAccessCreate(labelPrefix + generation as CFString, [trusted] as CFArray, &access) == errSecSuccess,
          let resolvedAccess = access else {
        throw HelperError.operationFailed
    }
    try restrictAccessToSigning(resolvedAccess)
    let privateAttributes: [CFString: Any] = [
        kSecAttrIsPermanent: true,
        kSecAttrApplicationTag: Data((labelPrefix + generation).utf8),
        kSecAttrLabel: labelPrefix + generation,
        kSecAttrCanSign: true,
        kSecAttrCanDecrypt: false,
        kSecAttrCanDerive: false,
        kSecAttrCanUnwrap: false,
        kSecAttrIsExtractable: false,
        kSecAttrAccess: resolvedAccess,
    ]
    let attributes: [CFString: Any] = [
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits: 256,
        kSecUseKeychain: keychain,
        kSecPrivateKeyAttrs: privateAttributes,
    ]
    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        throw HelperError.operationFailed
    }
    return key
}

private func signHealthLease(_ privateKey: SecKey, publicKeyX963: Data) throws -> Data {
    guard let claims = try FileHandle.standardInput.read(upToCount: maximumClaimsBytes + 1),
          claims.count <= maximumClaimsBytes else {
        throw HelperError.invalidRequest
    }
    try validateCanonicalHealthLeaseClaims(claims, expectedSigningKeyId: try signingKeyId(publicKeyX963: publicKeyX963))
    var message = healthLeaseDomain
    message.append(claims)
    guard SecKeyIsAlgorithmSupported(privateKey, .sign, .ecdsaSignatureMessageX962SHA256),
          let signature = SecKeyCreateSignature(privateKey, .ecdsaSignatureMessageX962SHA256,
                                                message as CFData, nil) as Data? else {
        throw HelperError.operationFailed
    }
    try validateCanonicalDERSignature(signature)
    return signature
}

private func signProtectionLease(_ privateKey: SecKey, publicKeyX963: Data) throws -> Data {
    guard let lease = try FileHandle.standardInput.read(upToCount: maximumClaimsBytes + 1),
          lease.count <= maximumClaimsBytes else {
        throw HelperError.invalidRequest
    }
    try validateCanonicalProtectionLease(lease, expectedSigningKeyId: try signingKeyId(publicKeyX963: publicKeyX963))
    guard SecKeyIsAlgorithmSupported(privateKey, .sign, .ecdsaSignatureMessageX962SHA256),
          let signature = SecKeyCreateSignature(privateKey, .ecdsaSignatureMessageX962SHA256,
                                                lease as CFData, nil) as Data? else {
        throw HelperError.operationFailed
    }
    try validateCanonicalDERSignature(signature)
    return signature
}

private func signHealthKeyRegistration(_ privateKey: SecKey, publicKeyX963: Data) throws -> Data {
    guard let registration = try FileHandle.standardInput.read(upToCount: maximumClaimsBytes + 1),
          registration.count <= maximumClaimsBytes else {
        throw HelperError.invalidRequest
    }
    try validateCanonicalHealthKeyRegistration(
        registration,
        expectedSigningKeyId: try signingKeyId(publicKeyX963: publicKeyX963)
    )
    var message = healthKeyRegistrationDomain
    message.append(registration)
    guard SecKeyIsAlgorithmSupported(privateKey, .sign, .ecdsaSignatureMessageX962SHA256),
          let signature = SecKeyCreateSignature(privateKey, .ecdsaSignatureMessageX962SHA256,
                                                message as CFData, nil) as Data? else {
        throw HelperError.operationFailed
    }
    try validateCanonicalDERSignature(signature)
    return signature
}

private func run() throws -> PublicResult {
    guard geteuid() == 0, CommandLine.arguments.count == 3 else {
        throw HelperError.denied
    }
    let verb = CommandLine.arguments[1]
    let generation = try validatedGeneration(CommandLine.arguments[2])
    SecKeychainSetUserInteractionAllowed(false)
    let keychain = try openSystemKeychain()
    if verb == "delete" {
        let status = SecItemDelete(keyQuery(generation: generation, keychain: keychain, returnReference: false) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw HelperError.operationFailed
        }
        return PublicResult(ok: true, state: "absent", protectionLevel: "os-protected", publicKeyX963: nil,
                            reasonCode: "device_key_absent")
    }
    let privateKey: SecKey
    if verb == "create" {
        do {
            _ = try copyPrivateKey(generation: generation, keychain: keychain)
            throw HelperError.keyInvalid
        } catch HelperError.keyAbsent {
            privateKey = try createKey(generation: generation, keychain: keychain)
        }
    } else if verb == "inspect" || verb == "sign-health-lease" || verb == "sign-protection-lease"
        || verb == "sign-health-key-registration" {
        privateKey = try copyPrivateKey(generation: generation, keychain: keychain)
    } else {
        throw HelperError.invalidRequest
    }
    let publicKey = try inspectKey(privateKey)
    if verb == "sign-health-lease" {
        emitSignature(try signHealthLease(privateKey, publicKeyX963: publicKey))
    }
    if verb == "sign-protection-lease" {
        emitSignature(try signProtectionLease(privateKey, publicKeyX963: publicKey))
    }
    if verb == "sign-health-key-registration" {
        emitSignature(try signHealthKeyRegistration(privateKey, publicKeyX963: publicKey))
    }
    return PublicResult(ok: true, state: "active", protectionLevel: "os-protected",
                        publicKeyX963: publicKey.base64EncodedString(), reasonCode: "device_key_active")
}

do {
    let result = try run()
    emit(result, exitCode: 0)
} catch HelperError.denied {
    fail("device_key_system_context_required")
} catch HelperError.invalidRequest {
    fail("device_key_request_invalid")
} catch HelperError.keychainUnavailable {
    fail("device_key_provider_unavailable")
} catch HelperError.keyAbsent {
    emit(PublicResult(ok: false, state: "absent", protectionLevel: "os-protected", publicKeyX963: nil,
                      reasonCode: "device_key_absent"), exitCode: 1)
} catch HelperError.keyInvalid {
    fail("device_key_unusable")
} catch {
    fail("device_key_probe_failed")
}
