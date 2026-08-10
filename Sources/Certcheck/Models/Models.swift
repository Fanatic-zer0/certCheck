import Foundation

// MARK: - Core Models

struct CertFingerprints {
    var md5: String
    var sha1: String
    var sha256: String
    var spkiSha256: String
}

struct PublicKeyInfo {
    var type: String  // "RSA", "EC", "Ed25519", etc.
    var bits: Int
}

struct CertExtension {
    var name: String
    var critical: Bool
    var value: String
}

struct CertInfo {
    var subject: OrderedDN
    var issuer: OrderedDN
    var serial: String
    var notBefore: String   // ISO 8601
    var notAfter: String    // ISO 8601
    var san: [String]
    var fingerprints: CertFingerprints
    var publicKey: PublicKeyInfo
    var signatureAlg: String
    var version: Int
    var extensions: [CertExtension]
}

struct CSRInfo {
    var subject: OrderedDN
    var publicKey: PublicKeyInfo
    var signatureAlg: String
    var selfSigValid: Bool?
    var sans: [String]
    var extensions: [CertExtension]
    var fingerprints: CertFingerprints
}

struct TrustEntry: Identifiable {
    var id: Int { index }
    var index: Int
    var alias: String?
    var subject: OrderedDN
    var issuer: OrderedDN
    var serial: String
    var notBefore: String
    var notAfter: String
    var isCA: Bool
    var selfSigned: Bool
    var san: [String]
    var keyType: String
    var keyBits: Int
    var sigAlg: String
    var fingerprints: CertFingerprints
    var error: String?
    var pem: String
}

struct ChainLink: Identifiable {
    var id: Int { index }
    var index: Int
    var subject: String
    var issuer: String
    var notAfter: String    // ISO 8601
    var selfSigned: Bool
    var issuerChainOk: Bool
    var signatureOk: Bool?
}

struct CSRMatchResult {
    var publicKeyMatch: Bool
    var subjectMatch: Bool
    var certSubject: String
    var csrSubject: String
}

// Ordered DN pairs: [(key, value)]
typealias OrderedDN = [(key: String, value: String)]

// MARK: - Generation Config

enum KeyAlgoKind: String, CaseIterable {
    case rsa     = "rsa"
    case ec      = "ec"
    case ed25519 = "ed25519"
    case ed448   = "ed448"

    var label: String {
        switch self {
        case .rsa:     return "RSA"
        case .ec:      return "ECDSA"
        case .ed25519: return "Ed25519"
        case .ed448:   return "Ed448"
        }
    }
}

enum RSABits: String, CaseIterable {
    case b2048 = "2048"
    case b3072 = "3072"
    case b4096 = "4096"
}

enum ECCurve: String, CaseIterable {
    case p256   = "P-256"
    case p384   = "P-384"
    case p521   = "P-521"
    case secp256k1   = "secp256k1"

    var opensslName: String {
        switch self {
        case .p256:       return "prime256v1"
        case .p384:       return "secp384r1"
        case .p521:       return "secp521r1"
        case .secp256k1:  return "secp256k1"
        }
    }
}

struct KeyAlgoConfig {
    var kind: KeyAlgoKind = .rsa
    var rsaBits: RSABits = .b2048
    var curve: ECCurve = .p256

    var label: String {
        switch kind {
        case .rsa:     return "RSA \(rsaBits.rawValue)"
        case .ec:      return "EC \(curve.rawValue)"
        case .ed25519: return "Ed25519"
        case .ed448:   return "Ed448"
        }
    }
}

enum CertType: String, CaseIterable {
    case selfSigned      = "self-signed"
    case rootCA          = "root-ca"
    case intermediateCA  = "intermediate-ca"
    case caSigned        = "ca-signed"

    var label: String {
        switch self {
        case .selfSigned:     return "Self-Signed"
        case .rootCA:         return "Root CA"
        case .intermediateCA: return "Intermediate CA"
        case .caSigned:       return "CA-Signed"
        }
    }

    var description: String {
        switch self {
        case .selfSigned:     return "Generate key + cert, signed by itself"
        case .rootCA:         return "Create a self-signed Root CA certificate"
        case .intermediateCA: return "CA cert signed by a Root CA"
        case .caSigned:       return "Sign an existing CSR with a CA cert + key"
        }
    }
}

struct CertSubject {
    var cn: String = ""
    var org: String = ""
    var ou: String = ""
    var country: String = "US"
    var state: String = ""
    var locality: String = ""
    var san: [String] = []

    var opensslSubj: String {
        var s = ""
        if !cn.isEmpty       { s += "/CN=\(cn)" }
        if !org.isEmpty      { s += "/O=\(org)" }
        if !ou.isEmpty       { s += "/OU=\(ou)" }
        if !country.isEmpty  { s += "/C=\(country)" }
        if !state.isEmpty    { s += "/ST=\(state)" }
        if !locality.isEmpty { s += "/L=\(locality)" }
        return s.isEmpty ? "/CN=localhost" : s
    }

    var sanString: String? {
        let entries = san.map { s -> String in
            let isIP = s.range(of: #"^\d{1,3}(\.\d{1,3}){3}$"#, options: .regularExpression) != nil
            return isIP ? "IP:\(s)" : "DNS:\(s)"
        }
        return entries.isEmpty ? nil : entries.joined(separator: ",")
    }
    
    // Convert to OrderedDN for OpenSSLHelper
    func toOrderedDN() -> OrderedDN {
        var result: OrderedDN = []
        if !country.isEmpty { result.append((key: "C", value: country)) }
        if !state.isEmpty { result.append((key: "ST", value: state)) }
        if !locality.isEmpty { result.append((key: "L", value: locality)) }
        if !org.isEmpty { result.append((key: "O", value: org)) }
        if !ou.isEmpty { result.append((key: "OU", value: ou)) }
        if !cn.isEmpty { result.append((key: "CN", value: cn)) }
        return result
    }
}
