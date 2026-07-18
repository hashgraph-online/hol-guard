import Foundation
import Security

private let labelPrefix = "org.hol.guard.device-key."
private let systemKeychainPath = "/Library/Keychains/System.keychain"
private let installedHelperPath = "/Library/Application Support/HOL Guard/hol-guard-device-key"
private let generationPattern = try! NSRegularExpression(pattern: "^[0-9a-f]{32}$")

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

private func emit(_ result: PublicResult, exitCode: Int32) -> Never {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    if let data = try? encoder.encode(result) {
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data([0x0A]))
    }
    exit(exitCode)
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
    } else if verb == "inspect" {
        privateKey = try copyPrivateKey(generation: generation, keychain: keychain)
    } else {
        throw HelperError.invalidRequest
    }
    let publicKey = try inspectKey(privateKey)
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
