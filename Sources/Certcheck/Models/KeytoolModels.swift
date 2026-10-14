import Foundation

// MARK: - Store Type

enum KeystoreFormat: String, CaseIterable, Identifiable {
    case auto    = "Auto-detect"
    case jks     = "JKS"
    case pkcs12  = "PKCS12"
    case jceks   = "JCEKS"

    var id: String { rawValue }

    /// nil means "let keytool infer it" (omit -storetype)
    var keytoolArg: String? {
        switch self {
        case .auto:   return nil
        case .jks:    return "JKS"
        case .pkcs12: return "PKCS12"
        case .jceks:  return "JCEKS"
        }
    }
}

// MARK: - Keystore Entry (list row)

struct KeystoreEntryInfo: Identifiable {
    var id: String { alias }
    var alias: String
    var entryType: String          // "PrivateKeyEntry", "trustedCertEntry", "SecretKeyEntry"
    var creationDate: String
    var chainLength: Int
    var certInfo: CertInfo?        // parsed via CertService from the exported leaf cert (nil for SecretKeyEntry or parse failure)
    var chainPEMs: [String]        // full chain in PEM, leaf first (may be empty)
    var parseError: String?

    var isCertEntry: Bool { entryType != "SecretKeyEntry" }

    var expiryStatus: KeystoreExpiryStatus {
        guard let notAfter = certInfo?.notAfter,
              let date = ISO8601DateFormatter().date(from: notAfter) else { return .unknown }
        let days = Calendar.current.dateComponents([.day], from: Date(), to: date).day ?? 0
        if days < 0 { return .expired }
        if days <= 30 { return .expiringSoon }
        return .valid
    }

    var daysUntilExpiry: Int? {
        guard let notAfter = certInfo?.notAfter,
              let date = ISO8601DateFormatter().date(from: notAfter) else { return nil }
        return Calendar.current.dateComponents([.day], from: Date(), to: date).day
    }
}

enum KeystoreExpiryStatus {
    case valid, expiringSoon, expired, unknown

    var label: String {
        switch self {
        case .valid:         return "Valid"
        case .expiringSoon:  return "Expiring Soon"
        case .expired:       return "Expired"
        case .unknown:       return "Unknown"
        }
    }
}

// MARK: - Certificate Warnings (detail view)

struct KeystoreCertWarning: Identifiable {
    var id = UUID()
    var severity: Severity
    var message: String

    enum Severity { case error, warning }
}

extension CertInfo {
    /// Derives human-readable warnings for the keystore certificate detail view.
    func keystoreWarnings(expiringSoonDays: Int = 30) -> [KeystoreCertWarning] {
        var warnings: [KeystoreCertWarning] = []

        if let date = ISO8601DateFormatter().date(from: notAfter) {
            let days = Calendar.current.dateComponents([.day], from: Date(), to: date).day ?? 0
            if days < 0 {
                warnings.append(.init(severity: .error, message: "Certificate expired \(-days) day(s) ago"))
            } else if days <= expiringSoonDays {
                warnings.append(.init(severity: .warning, message: "Certificate expires in \(days) day(s)"))
            }
        }

        if selfSigned {
            warnings.append(.init(severity: .warning, message: "Self-signed certificate"))
        }

        if san.isEmpty {
            warnings.append(.init(severity: .warning, message: "No Subject Alternative Names (SANs) present"))
        }

        let weakAlgorithms = ["md5", "sha1with", "sha1rsa"]
        let sigLower = signatureAlg.lowercased()
        if weakAlgorithms.contains(where: { sigLower.contains($0) }) {
            warnings.append(.init(severity: .error, message: "Weak signature algorithm: \(signatureAlg)"))
        }

        return warnings
    }
}

// MARK: - Keytool Operations

enum KeytoolOperation: String, CaseIterable, Identifiable {
    case listEntries     = "List Entries"
    case inspectCert      = "Inspect Certificate"
    case exportCert        = "Export Certificate"
    case importTrusted     = "Import Trusted Certificate"
    case importReply       = "Import Certificate Reply"
    case genCSR             = "Generate CSR"
    case genKeyPair         = "Generate Key Pair"
    case convertKeystore   = "Convert Keystore"
    case renameAlias        = "Rename Alias"
    case deleteAlias        = "Delete Alias"
    case changeStorePass   = "Change Store Password"
    case changeKeyPass     = "Change Key Password"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .listEntries:    return "list.bullet.rectangle"
        case .inspectCert:    return "doc.text.magnifyingglass"
        case .exportCert:     return "square.and.arrow.up"
        case .importTrusted:  return "square.and.arrow.down.on.square"
        case .importReply:    return "arrow.triangle.2.circlepath"
        case .genCSR:         return "pencil.and.list.clipboard"
        case .genKeyPair:     return "key.fill"
        case .convertKeystore: return "arrow.2.squarepath"
        case .renameAlias:    return "pencil"
        case .deleteAlias:    return "trash"
        case .changeStorePass: return "lock.rotation"
        case .changeKeyPass:  return "key.horizontal"
        }
    }

    var keytoolCommand: String {
        switch self {
        case .listEntries:     return "keytool -list"
        case .inspectCert:     return "keytool -printcert"
        case .exportCert:      return "keytool -exportcert"
        case .importTrusted:   return "keytool -importcert"
        case .importReply:     return "keytool -importcert"
        case .genCSR:          return "keytool -certreq"
        case .genKeyPair:      return "keytool -genkeypair"
        case .convertKeystore: return "keytool -importkeystore"
        case .renameAlias:     return "keytool -changealias"
        case .deleteAlias:     return "keytool -delete"
        case .changeStorePass: return "keytool -storepasswd"
        case .changeKeyPass:   return "keytool -keypasswd"
        }
    }
}
