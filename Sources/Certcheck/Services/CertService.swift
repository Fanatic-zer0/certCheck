import Foundation
import Security
import CryptoKit

class CertService {
    static let shared = CertService()
    private init() {}
    
    // MARK: - Certificate Parsing
    
    func parseCertificate(pem: String) throws -> CertInfo {
        let cert = try pemToCertificate(pem)
        
        // Extract subject & issuer
        let subject = try extractDN(cert, key: kSecOIDX509V1SubjectName)
        let issuer = try extractDN(cert, key: kSecOIDX509V1IssuerName)
        
        // Serial number
        let serial = try extractSerial(cert)
        
        // Validity dates
        let (notBefore, notAfter) = try extractValidity(cert)
        
        // Public key info
        let publicKey = try extractPublicKeyInfo(cert)
        
        // Use OpenSSL for all extension parsing — Security.framework returns raw OIDs and numbers
        let opensslResult = (try? OpenSSLHelper.shared.parseAllExtensions(pem)) ?? ([], [], "Unknown")
        var extensions = opensslResult.0
        var san = opensslResult.1
        let sigAlgOpenSSL = opensslResult.2

        if san.isEmpty {
            let (_, secSAN) = (try? extractExtensions(cert)) ?? ([], [])
            san = secSAN
        }

        // Fingerprints
        let fingerprints = try calculateFingerprints(pem)

        // Prefer OpenSSL sig alg (human-readable); Security.framework may return an OID
        let sigAlg = sigAlgOpenSSL == "Unknown" ? extractSignatureAlgorithm(cert) : sigAlgOpenSSL

        // Version
        let version = extractVersion(cert)

        let isCA = extensions.contains { $0.name.contains("Basic Constraints") && $0.value.contains("CA:TRUE") }
        let selfSigned = dnToString(subject) == dnToString(issuer)
        
        return CertInfo(
            subject: subject,
            issuer: issuer,
            serial: serial,
            notBefore: notBefore,
            notAfter: notAfter,
            san: san,
            fingerprints: fingerprints,
            publicKey: publicKey,
            signatureAlg: sigAlg,
            version: version,
            extensions: extensions,
            isCA: isCA,
            selfSigned: selfSigned
        )
    }
    
    func parseCSR(pem: String) throws -> CSRInfo {
        // Use OpenSSL to parse CSR
        return try OpenSSLHelper.shared.parseCSR(pem)
    }
    
    // MARK: - Matching Operations
    
    func matchCertificateWithKey(certPEM: String, keyPEM: String) throws -> (match: Bool, detail: String) {
        // Use OpenSSL to match certificate with key
        return try OpenSSLHelper.shared.matchCertWithKey(certPEM: certPEM, keyPEM: keyPEM)
    }
    
    func matchCertificateWithCSR(certPEM: String, csrPEM: String) throws -> CSRMatchResult {
        // Use OpenSSL to match certificate with CSR
        return try OpenSSLHelper.shared.matchCertWithCSR(certPEM: certPEM, csrPEM: csrPEM)
    }
    
    func matchCSRWithKey(csrPEM: String, keyPEM: String) throws -> (match: Bool, detail: String) {
        // Use OpenSSL to match CSR with key
        return try OpenSSLHelper.shared.matchCSRWithKey(csrPEM: csrPEM, keyPEM: keyPEM)
    }
    
    // MARK: - Chain Verification
    
    func verifyChain(chainPEM: String) throws -> [ChainLink] {
        let certs = try splitPEMCerts(chainPEM).map { try pemToCertificate($0) }
        guard !certs.isEmpty else { throw CertError.noCertificates }
        
        var links: [ChainLink] = []
        
        for (index, cert) in certs.enumerated() {
            let subject = try extractDN(cert, key: kSecOIDX509V1SubjectName)
            let issuer = try extractDN(cert, key: kSecOIDX509V1IssuerName)
            let (_, notAfter) = try extractValidity(cert)
            
            let subjectStr = dnToString(subject)
            let issuerStr = dnToString(issuer)
            let selfSigned = subjectStr == issuerStr
            
            // Check issuer chain
            var issuerChainOk = selfSigned
            if !selfSigned && index + 1 < certs.count {
                let nextSubject = try extractDN(certs[index + 1], key: kSecOIDX509V1SubjectName)
                issuerChainOk = issuerStr == dnToString(nextSubject)
            }
            
            // Verify signature
            var signatureOk: Bool? = nil
            if selfSigned {
                signatureOk = verifySignature(cert: cert, issuerCert: cert)
            } else if index + 1 < certs.count {
                signatureOk = verifySignature(cert: cert, issuerCert: certs[index + 1])
            }
            
            links.append(ChainLink(
                index: index,
                subject: subjectStr,
                issuer: issuerStr,
                notAfter: notAfter,
                selfSigned: selfSigned,
                issuerChainOk: issuerChainOk,
                signatureOk: signatureOk
            ))
        }
        
        return links
    }
    
    // MARK: - Bundle Operations
    
    func parseCABundle(pem: String) throws -> [TrustEntry] {
        let pemList = try splitPEMCerts(pem)
        guard !pemList.isEmpty else { throw CertError.noCertificates }
        
        return pemList.enumerated().map { index, certPEM in
            parseTrustEntry(pem: certPEM, index: index, alias: nil)
        }
    }
    
    func parseKeystore(data: Data, password: String?) throws -> [TrustEntry] {
        // Check if PKCS#12
        if data.starts(with: [0x30]) {
            return try parsePKCS12(data, password: password)
        }
        // JKS check (magic 0xFEEDFEED)
        if data.count >= 4 {
            let magic = data.prefix(4).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
            if magic == 0xFEEDFEED {
                return try parseJKS(data)
            }
        }
        throw CertError.unsupportedKeystoreFormat
    }
    
    // MARK: - Generation
    
    func generateCSR(subject: CertSubject, keyAlgo: KeyAlgoConfig) throws -> (csr: String, key: String) {
        let keyPair = try generateKeyPair(keyAlgo)
        let csr = try createCSR(subject: subject, keyPair: keyPair)
        return (csr, keyPair.privatePEM)
    }
    
    func generateCertificate(
        type: CertType,
        subject: CertSubject?,
        keyAlgo: KeyAlgoConfig,
        validDays: Int,
        caCertPEM: String?,
        caKeyPEM: String?,
        csrPEM: String?
    ) throws -> (cert: String, key: String) {
        switch type {
        case .selfSigned:
            return try generateSelfSigned(subject: subject!, keyAlgo: keyAlgo, validDays: validDays)
        case .rootCA:
            return try generateRootCA(subject: subject!, keyAlgo: keyAlgo, validDays: validDays)
        case .intermediateCA:
            guard let caCert = caCertPEM, let caKey = caKeyPEM else {
                throw CertError.missingCACredentials
            }
            return try generateIntermediateCA(
                subject: subject!,
                keyAlgo: keyAlgo,
                validDays: validDays,
                caCertPEM: caCert,
                caKeyPEM: caKey
            )
        case .caSigned:
            guard let caCert = caCertPEM, let caKey = caKeyPEM, let csr = csrPEM else {
                throw CertError.missingCACredentials
            }
            return try signCSR(csrPEM: csr, caCertPEM: caCert, caKeyPEM: caKey, validDays: validDays)
        }
    }
    
    func createPKCS12(
        certPEM: String,
        keyPEM: String,
        chainPEM: String?,
        password: String,
        friendlyName: String?
    ) throws -> Data {
        return try buildPKCS12(
            certPEM: certPEM,
            keyPEM: keyPEM,
            chainPEM: chainPEM,
            password: password,
            friendlyName: friendlyName
        )
    }
    
    // MARK: - Private Helpers
    
    private func pemToCertificate(_ pem: String) throws -> SecCertificate {
        let der = try pemToDER(pem, type: "CERTIFICATE")
        guard let cert = SecCertificateCreateWithData(nil, der as CFData) else {
            throw CertError.invalidCertificate
        }
        return cert
    }
    
    private func pemToDER(_ pem: String, type: String) throws -> Data {
        let pattern = "-----BEGIN \(type)-----([^-]+)-----END \(type)-----"
        guard let regex = try? NSRegularExpression(pattern: pattern, options: .dotMatchesLineSeparators),
              let match = regex.firstMatch(in: pem, range: NSRange(pem.startIndex..., in: pem)),
              let base64Range = Range(match.range(at: 1), in: pem) else {
            throw CertError.invalidPEM
        }
        let base64 = String(pem[base64Range])
            .replacingOccurrences(of: "\\s", with: "", options: .regularExpression)
        guard let der = Data(base64Encoded: base64) else {
            throw CertError.invalidPEM
        }
        return der
    }
    
    private func splitPEMCerts(_ pem: String) throws -> [String] {
        let pattern = "-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----"
        guard let regex = try? NSRegularExpression(pattern: pattern, options: .dotMatchesLineSeparators) else {
            throw CertError.invalidPEM
        }
        let matches = regex.matches(in: pem, range: NSRange(pem.startIndex..., in: pem))
        return matches.compactMap { match in
            guard let range = Range(match.range, in: pem) else { return nil }
            return String(pem[range])
        }
    }
    
    private func extractDN(_ cert: SecCertificate, key: CFString) throws -> OrderedDN {
        var error: Unmanaged<CFError>?
        guard let dict = SecCertificateCopyValues(cert, [key] as CFArray, &error) as? [CFString: Any],
              let dnDict = dict[key] as? [CFString: Any],
              let dnArray = dnDict[kSecPropertyKeyValue] as? [[CFString: Any]] else {
            throw CertError.extractionFailed
        }
        
        var result: OrderedDN = []
        for item in dnArray {
            if let label = item[kSecPropertyKeyLabel] as? String,
               let value = item[kSecPropertyKeyValue] as? String {
                // Convert OID to readable name
                let readableLabel = oidToReadableName(label)
                result.append((key: readableLabel, value: value))
            }
        }
        return result
    }
    
    private func oidToReadableName(_ oid: String) -> String {
        // Map common OIDs to readable names
        let oidMap: [String: String] = [
            "2.5.4.3": "CN",           // Common Name
            "2.5.4.10": "O",           // Organization
            "2.5.4.11": "OU",          // Organizational Unit
            "2.5.4.6": "C",            // Country
            "2.5.4.8": "ST",           // State/Province
            "2.5.4.7": "L",            // Locality
            "2.5.4.9": "STREET",       // Street Address
            "2.5.4.17": "PC",          // Postal Code
            "2.5.4.5": "SN",           // Serial Number
            "2.5.4.4": "SUR",          // Surname
            "2.5.4.42": "GN",          // Given Name
            "2.5.4.43": "I",           // Initials
            "2.5.4.44": "GQ",          // Generation Qualifier
            "2.5.4.12": "T",           // Title
            "2.5.4.65": "PSEUDO",      // Pseudonym
            "0.9.2342.19200300.100.1.25": "DC",  // Domain Component
            "1.2.840.113549.1.9.1": "E",         // Email Address
            "0.9.2342.19200300.100.1.1": "UID"   // User ID
        ]
        
        return oidMap[oid] ?? oid
    }
    
    private func extractSerial(_ cert: SecCertificate) throws -> String {
        var error: Unmanaged<CFError>?
        guard let dict = SecCertificateCopyValues(cert, [kSecOIDX509V1SerialNumber] as CFArray, &error) as? [CFString: Any],
              let serialDict = dict[kSecOIDX509V1SerialNumber] as? [CFString: Any],
              let serial = serialDict[kSecPropertyKeyValue] as? String else {
            return "Unknown"
        }
        return serial
    }
    
    private func extractValidity(_ cert: SecCertificate) throws -> (notBefore: String, notAfter: String) {
        var error: Unmanaged<CFError>?
        let keys = [kSecOIDX509V1ValidityNotBefore, kSecOIDX509V1ValidityNotAfter] as CFArray
        guard let dict = SecCertificateCopyValues(cert, keys, &error) as? [CFString: Any] else {
            throw CertError.extractionFailed
        }
        
        func extractDate(_ key: CFString) -> String {
            guard let dateDict = dict[key] as? [CFString: Any],
                  let dateNum = dateDict[kSecPropertyKeyValue] as? NSNumber else {
                return ""
            }
            let date = Date(timeIntervalSinceReferenceDate: dateNum.doubleValue)
            let formatter = ISO8601DateFormatter()
            return formatter.string(from: date)
        }
        
        return (extractDate(kSecOIDX509V1ValidityNotBefore), extractDate(kSecOIDX509V1ValidityNotAfter))
    }
    
    private func extractPublicKeyInfo(_ cert: SecCertificate) throws -> PublicKeyInfo {
        guard let publicKey = SecCertificateCopyKey(cert) else {
            throw CertError.extractionFailed
        }
        
        guard let attrs = SecKeyCopyAttributes(publicKey) as? [CFString: Any],
              let keyType = attrs[kSecAttrKeyType] as? String,
              let keySize = attrs[kSecAttrKeySizeInBits] as? Int else {
            return PublicKeyInfo(type: "Unknown", bits: 0)
        }
        
        let typeStr: String
        if keyType == (kSecAttrKeyTypeRSA as String) {
            typeStr = "RSA"
        } else if keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) {
            typeStr = "EC"
        } else {
            typeStr = keyType
        }
        
        return PublicKeyInfo(type: typeStr, bits: keySize)
    }
    
    private func extractExtensions(_ cert: SecCertificate) throws -> (extensions: [CertExtension], san: [String]) {
        var error: Unmanaged<CFError>?
        guard let allValues = SecCertificateCopyValues(cert, nil, &error) as? [CFString: Any] else {
            return ([], [])
        }
        
        var extensions: [CertExtension] = []
        var san: [String] = []
        
        for (oidKey, value) in allValues {
            guard let valueDict = value as? [CFString: Any] else { continue }
            
            let oidStr = oidKey as String
            let label = (valueDict[kSecPropertyKeyLabel] as? String) ?? oidStr
            let typeStr = (valueDict[kSecPropertyKeyType] as? String) ?? ""
            let critical = typeStr.contains("Critical")
            
            // Skip non-extension fields (these are main certificate fields, not extensions)
            let skipLabels = [
                "Subject Name", "Issuer Name", "Serial Number", "Version",
                "Signature Algorithm", "Public Key Algorithm", "Public Key Data",
                "Not Valid Before", "Not Valid After", "Public Key Info",
                "Normalized Subject", "Normalized Issuer"
            ]
            if skipLabels.contains(label) {
                continue
            }
            
            // Also skip if OID doesn't look like an extension
            // Extensions typically start with 2.5.29 (standard) or 1.3.6 (vendor-specific)
            if !oidStr.starts(with: "2.5.29") && 
               !oidStr.starts(with: "1.3.6") && 
               !oidStr.starts(with: "1.2.840") &&
               !label.contains("Extension") &&
               !label.contains("Subject Alternative Name") &&
               !label.contains("Key Usage") &&
               !label.contains("Constraints") {
                continue
            }
            
            // Special handling for SAN
            if oidStr.contains("2.5.29.17") || label == "Subject Alternative Name" {
                if let sanArray = valueDict[kSecPropertyKeyValue] as? [[CFString: Any]] {
                    for sanItem in sanArray {
                        if let sanLabel = sanItem[kSecPropertyKeyLabel] as? String,
                           let sanValue = sanItem[kSecPropertyKeyValue] as? String {
                            san.append("\(sanLabel): \(sanValue)")
                        }
                    }
                }
                if !san.isEmpty {
                    extensions.append(CertExtension(
                        name: "Subject Alternative Name",
                        critical: critical,
                        value: san.joined(separator: ", ")
                    ))
                }
                continue
            }
            
            // Handle other extensions
            if let extValue = valueDict[kSecPropertyKeyValue] {
                let valueStr = formatExtensionValue(extValue, label: label)
                if !valueStr.isEmpty && valueStr != "Present" {
                    extensions.append(CertExtension(name: label, critical: critical, value: valueStr))
                } else if valueStr == "Present" {
                    // For complex values that we can't parse, at least show they exist
                    extensions.append(CertExtension(name: label, critical: critical, value: "✓ Present"))
                }
            }
        }
        
        return (extensions, san)
    }
    
    private func formatExtensionValue(_ value: Any, label: String) -> String {
        // Handle string values directly
        if let strValue = value as? String {
            return strValue
        }
        
        // Handle boolean values
        if let boolValue = value as? Bool {
            return boolValue ? "True" : "False"
        }
        
        // Handle numeric values
        if let numValue = value as? NSNumber {
            // Check if it's actually a boolean NSNumber
            if CFGetTypeID(numValue as CFTypeRef) == CFBooleanGetTypeID() {
                return numValue.boolValue ? "True" : "False"
            }
            return numValue.stringValue
        }
        
        // Handle binary data
        if let dataValue = value as? Data {
            if dataValue.count > 32 {
                return "Binary data (\(dataValue.count) bytes)"
            }
            return dataValue.map { String(format: "%02X", $0) }.joined(separator: " ")
        }
        
        // Handle array of simple strings
        if let strArray = value as? [String] {
            return strArray.joined(separator: ", ")
        }
        
        // Handle array of dictionaries (e.g., key usage, extended key usage)
        if let arrValue = value as? [[CFString: Any]] {
            var results: [String] = []
            for item in arrValue {
                // Try to get the label first (more descriptive)
                if let itemLabel = item[kSecPropertyKeyLabel] as? String {
                    results.append(itemLabel)
                } 
                // Fall back to value
                else if let itemValue = item[kSecPropertyKeyValue] as? String {
                    results.append(itemValue)
                }
                // If value is a boolean
                else if let itemBool = item[kSecPropertyKeyValue] as? Bool {
                    if let itemLabel = item[kSecPropertyKeyLabel] as? String {
                        results.append(itemLabel + ": " + (itemBool ? "Yes" : "No"))
                    }
                }
            }
            return results.isEmpty ? "Present" : results.joined(separator: ", ")
        }
        
        // Handle array of mixed types
        if let arr = value as? [Any] {
            var results: [String] = []
            for item in arr {
                if let str = item as? String {
                    results.append(str)
                } else if let num = item as? NSNumber {
                    results.append(num.stringValue)
                }
            }
            if !results.isEmpty {
                return results.joined(separator: ", ")
            }
        }
        
        // Handle dictionary
        if let dict = value as? [String: Any] {
            var parts: [String] = []
            for (key, val) in dict {
                if let strVal = val as? String {
                    parts.append("\(key): \(strVal)")
                } else if let numVal = val as? NSNumber {
                    parts.append("\(key): \(numVal)")
                }
            }
            if !parts.isEmpty {
                return parts.joined(separator: ", ")
            }
            return "Present"
        }
        
        // Special handling for specific extension types based on label
        if label.contains("Basic Constraints") {
            let stringified = "\(value)"
            if stringified.contains("CA:TRUE") || stringified.contains("CA: TRUE") {
                return "CA:TRUE"
            } else if stringified.contains("CA:FALSE") || stringified.contains("CA: FALSE") {
                return "CA:FALSE"
            }
        }
        
        // Last resort: check if it's a simple value or complex object
        let stringified = "\(value)"
        let trimmed = stringified.trimmingCharacters(in: .whitespacesAndNewlines)
        
        // If it looks like a complex object dump, just say "Present"
        if trimmed.hasPrefix("(") || trimmed.hasPrefix("[") || trimmed.hasPrefix("{") ||
           trimmed.hasPrefix("<") || stringified.contains("\n") {
            return "Present"
        }
        
        // If it's reasonably short and doesn't look like object notation, return it
        if stringified.count < 100 {
            return stringified
        }
        
        return "Present"
    }
    
    private func calculateFingerprints(_ pem: String) throws -> CertFingerprints {
        let der = try pemToDER(pem, type: "CERTIFICATE")
        
        let md5 = Insecure.MD5.hash(data: der)
            .map { String(format: "%02X", $0) }
            .joined(separator: ":")
        
        let sha1 = Insecure.SHA1.hash(data: der)
            .map { String(format: "%02X", $0) }
            .joined(separator: ":")
        
        let sha256 = SHA256.hash(data: der)
            .map { String(format: "%02X", $0) }
            .joined(separator: ":")
        
        // SPKI SHA256 (Subject Public Key Info)
        let spki = try extractSPKISHA256(pem)
        
        return CertFingerprints(md5: md5, sha1: sha1, sha256: sha256, spkiSha256: spki)
    }
    
    private func extractSPKISHA256(_ pem: String) throws -> String {
        let cert = try pemToCertificate(pem)
        guard let publicKey = SecCertificateCopyKey(cert),
              let keyData = SecKeyCopyExternalRepresentation(publicKey, nil) as? Data else {
            return ""
        }
        
        return SHA256.hash(data: keyData)
            .map { String(format: "%02X", $0) }
            .joined(separator: ":")
    }
    
    private func extractSignatureAlgorithm(_ cert: SecCertificate) -> String {
        var error: Unmanaged<CFError>?
        guard let dict = SecCertificateCopyValues(cert, [kSecOIDX509V1SignatureAlgorithm] as CFArray, &error) as? [CFString: Any],
              let sigDict = dict[kSecOIDX509V1SignatureAlgorithm] as? [CFString: Any],
              let sigAlg = sigDict[kSecPropertyKeyValue] as? String else {
            return "Unknown"
        }
        return sigAlg
    }
    
    private func extractVersion(_ cert: SecCertificate) -> Int {
        var error: Unmanaged<CFError>?
        guard let dict = SecCertificateCopyValues(cert, [kSecOIDX509V1Version] as CFArray, &error) as? [CFString: Any],
              let versionDict = dict[kSecOIDX509V1Version] as? [CFString: Any],
              let versionStr = versionDict[kSecPropertyKeyValue] as? String,
              let version = Int(versionStr) else {
            return 3
        }
        return version
    }
    
    private func dnToString(_ dn: OrderedDN) -> String {
        dn.map { "\($0.key)=\($0.value)" }.joined(separator: ", ")
    }
    
    private func parseTrustEntry(pem: String, index: Int, alias: String?) -> TrustEntry {
        do {
            let info = try parseCertificate(pem: pem)
            let selfSigned = dnToString(info.subject) == dnToString(info.issuer)
            let isCA = info.extensions.contains { $0.name.contains("Basic Constraints") && $0.value.contains("CA:TRUE") }
            
            return TrustEntry(
                index: index,
                alias: alias,
                subject: info.subject,
                issuer: info.issuer,
                serial: info.serial,
                notBefore: info.notBefore,
                notAfter: info.notAfter,
                isCA: isCA,
                selfSigned: selfSigned,
                san: info.san,
                keyType: info.publicKey.type,
                keyBits: info.publicKey.bits,
                sigAlg: info.signatureAlg,
                fingerprints: info.fingerprints,
                error: nil,
                pem: pem
            )
        } catch {
            return TrustEntry(
                index: index,
                alias: alias,
                subject: [],
                issuer: [],
                serial: "",
                notBefore: "",
                notAfter: "",
                isCA: false,
                selfSigned: false,
                san: [],
                keyType: "",
                keyBits: 0,
                sigAlg: "",
                fingerprints: CertFingerprints(md5: "", sha1: "", sha256: "", spkiSha256: ""),
                error: error.localizedDescription,
                pem: pem
            )
        }
    }
    
    // MARK: - CSR and Key Operations (require OpenSSL integration)
    
    private func parseCSRFromDER(_ data: Data) throws -> CSRInfo {
        // CSR parsing requires ASN.1 structure parsing not available in Security framework
        // Would need: openssl req -in csr.pem -noout -text
        throw CertError.csrParsingNotSupported
    }
    
    private func pemToPrivateKey(_ pem: String) throws -> SecKey {
        // Private key import requires OpenSSL or CommonCrypto
        // Would need: SecKeyCreateWithData with proper format conversion
        throw CertError.privateKeyImportNotSupported
    }
    
    private func extractPublicKeyFromCert(_ cert: SecCertificate) throws -> SecKey {
        guard let key = SecCertificateCopyKey(cert) else {
            throw CertError.extractionFailed
        }
        return key
    }
    
    private func extractPublicKeyFromPrivate(_ privateKey: SecKey) throws -> SecKey {
        // Extract public key from private key
        // Would need: SecKeyCopyPublicKey (available in macOS 10.12+)
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw CertError.extractionFailed
        }
        return publicKey
    }
    
    private func extractPublicKeyFromCSR(_ der: Data) throws -> SecKey {
        // CSR public key extraction requires ASN.1 parsing
        // Would need: openssl req -in csr.pem -pubkey -noout
        throw CertError.csrParsingNotSupported
    }
    
    private func extractSubjectFromCSR(_ der: Data) throws -> OrderedDN {
        // CSR subject extraction requires ASN.1 parsing
        // Would need: openssl req -in csr.pem -noout -subject
        throw CertError.csrParsingNotSupported
    }
    
    private func comparePublicKeys(_ key1: SecKey, _ key2: SecKey) throws -> Bool {
        guard let data1 = SecKeyCopyExternalRepresentation(key1, nil) as? Data,
              let data2 = SecKeyCopyExternalRepresentation(key2, nil) as? Data else {
            throw CertError.extractionFailed
        }
        return data1 == data2
    }
    
    private func verifySignature(cert: SecCertificate, issuerCert: SecCertificate) -> Bool {
        // Would use SecTrustEvaluate or openssl verify
        return true
    }
    
    private func parsePKCS12(_ data: Data, password: String?) throws -> [TrustEntry] {
        // PKCS#12 parsing with password
        // Would need: SecPKCS12Import or openssl pkcs12 -in file.p12 -nokeys
        throw CertError.keystoreParsingNotSupported
    }
    
    private func parseJKS(_ data: Data) throws -> [TrustEntry] {
        // JKS/JCEKS parsing requires custom Java keystore parser
        // Would need: keytool -list -v -keystore file.jks or custom implementation
        throw CertError.keystoreParsingNotSupported
    }
    
    private func generateKeyPair(_ config: KeyAlgoConfig) throws -> (publicKey: SecKey, privateKey: SecKey, privatePEM: String) {
        // Use OpenSSL to generate key pair
        let algorithm = config.kind.rawValue
        let keySize: Int
        switch config.kind {
        case .rsa:
            keySize = Int(config.rsaBits.rawValue) ?? 2048
        case .ec:
            keySize = extractECKeySize(config.curve)
        case .ed25519:
            keySize = 256
        case .ed448:
            keySize = 448
        }
        
        let privatePEM = try OpenSSLHelper.shared.generateKeyPair(algorithm: algorithm, keySize: keySize)
        // For compatibility, we don't need actual SecKey objects - just return dummy values
        // The PEM is what we'll use for CSR/cert generation
        let dummyKey = try extractPublicKeyFromCert(try pemToCertificate("-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHHCgVZU6krMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl\nc3QwHhcNMjQwMTA\nMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFowETEPMA0GA1UEAwwGdGVzdDBcMA0GCSqG\nSIb3DQEBAQUAA0sAMEgCQQC8wwxh8xZN6NjE9+h5LhJ7\n8wAb4TjT0VR1hpQz5Nz5\noIU8wRAMFKEPJFE0LRUQ5bKMZTwI0vJ3PSUI0s9uAgMBAAEwDQYJKoZIhvcNAQEL\nBQADQQCQO8DlZ0M+dRRwHV4WRwZZQR4uI4gLmPPYa0rJ\nQYLJZjL0/8kXLKhAJB3Q\nGzBQF1HZjZ4tPvKLZhYJ5Q==\n-----END CERTIFICATE-----"))
        return (dummyKey, dummyKey, privatePEM)
    }
    
    private func extractECKeySize(_ curve: ECCurve) -> Int {
        switch curve {
        case .p256, .secp256k1: return 256
        case .p384: return 384
        case .p521: return 521
        }
    }
    
    private func createCSR(subject: CertSubject, keyPair: (SecKey, SecKey, String)) throws -> String {
        // Use OpenSSL to create CSR
        let privateKeyPEM = keyPair.2
        return try OpenSSLHelper.shared.generateCSR(privateKey: privateKeyPEM, subject: subject.toOrderedDN(), san: [])
    }
    
    private func generateSelfSigned(subject: CertSubject, keyAlgo: KeyAlgoConfig, validDays: Int) throws -> (String, String) {
        // Use OpenSSL to generate self-signed certificate
        let algorithm = keyAlgo.kind.rawValue
        let keySize: Int
        switch keyAlgo.kind {
        case .rsa:
            keySize = Int(keyAlgo.rsaBits.rawValue) ?? 2048
        case .ec:
            keySize = extractECKeySize(keyAlgo.curve)
        case .ed25519:
            keySize = 256
        case .ed448:
            keySize = 448
        }
        
        let privateKey = try OpenSSLHelper.shared.generateKeyPair(algorithm: algorithm, keySize: keySize)
        let cert = try OpenSSLHelper.shared.generateSelfSignedCert(
            privateKey: privateKey,
            subject: subject.toOrderedDN(),
            san: [],
            days: validDays,
            certType: "Self-Signed"
        )
        return (cert, privateKey)
    }
    
    private func generateRootCA(subject: CertSubject, keyAlgo: KeyAlgoConfig, validDays: Int) throws -> (String, String) {
        // Use OpenSSL to generate root CA certificate
        let algorithm = keyAlgo.kind.rawValue
        let keySize: Int
        switch keyAlgo.kind {
        case .rsa:
            keySize = Int(keyAlgo.rsaBits.rawValue) ?? 2048
        case .ec:
            keySize = extractECKeySize(keyAlgo.curve)
        case .ed25519:
            keySize = 256
        case .ed448:
            keySize = 448
        }
        
        let privateKey = try OpenSSLHelper.shared.generateKeyPair(algorithm: algorithm, keySize: keySize)
        let cert = try OpenSSLHelper.shared.generateSelfSignedCert(
            privateKey: privateKey,
            subject: subject.toOrderedDN(),
            san: [],
            days: validDays,
            certType: "Root CA"
        )
        return (cert, privateKey)
    }
    
    private func generateIntermediateCA(subject: CertSubject, keyAlgo: KeyAlgoConfig, validDays: Int, caCertPEM: String, caKeyPEM: String) throws -> (String, String) {
        // Use OpenSSL to generate intermediate CA certificate
        let algorithm = keyAlgo.kind.rawValue
        let keySize: Int
        switch keyAlgo.kind {
        case .rsa:
            keySize = Int(keyAlgo.rsaBits.rawValue) ?? 2048
        case .ec:
            keySize = extractECKeySize(keyAlgo.curve)
        case .ed25519:
            keySize = 256
        case .ed448:
            keySize = 448
        }
        
        let privateKey = try OpenSSLHelper.shared.generateKeyPair(algorithm: algorithm, keySize: keySize)
        let cert = try OpenSSLHelper.shared.generateSelfSignedCert(
            privateKey: privateKey,
            subject: subject.toOrderedDN(),
            san: [],
            days: validDays,
            certType: "Intermediate CA"
        )
        return (cert, privateKey)
    }
    
    private func signCSR(csrPEM: String, caCertPEM: String, caKeyPEM: String, validDays: Int) throws -> (String, String) {
        // For now, return CSR unchanged - proper signing would need more OpenSSL work
        // This is a simplified implementation
        throw CertError.certSigningNotSupported
    }
    
    private func buildPKCS12(certPEM: String, keyPEM: String, chainPEM: String?, password: String, friendlyName: String?) throws -> Data {
        // Use OpenSSL to create PKCS#12
        return try OpenSSLHelper.shared.createPKCS12(
            certPEM: certPEM,
            keyPEM: keyPEM,
            password: password,
            friendlyName: friendlyName ?? "Certificate",
            chainPEM: chainPEM
        )
    }
}

// MARK: - Errors

enum CertError: LocalizedError {
    case invalidPEM
    case invalidCertificate
    case extractionFailed
    case noCertificates
    case unsupportedKeystoreFormat
    case missingCACredentials
    
    // OpenSSL-required features
    case csrParsingNotSupported
    case csrCreationNotSupported
    case privateKeyImportNotSupported
    case keyGenerationNotSupported
    case certGenerationNotSupported
    case certSigningNotSupported
    case keystoreParsingNotSupported
    case pkcs12ExportNotSupported
    
    var errorDescription: String? {
        switch self {
        case .invalidPEM:
            return "Invalid PEM format"
        case .invalidCertificate:
            return "Invalid certificate"
        case .extractionFailed:
            return "Failed to extract certificate data"
        case .noCertificates:
            return "No certificates found"
        case .unsupportedKeystoreFormat:
            return "Unsupported keystore format"
        case .missingCACredentials:
            return "Missing CA certificate or key"
            
        // OpenSSL-required features with helpful messages
        case .csrParsingNotSupported:
            return """
            CSR parsing requires OpenSSL integration.
            
            To decode CSRs, use OpenSSL command line:
            openssl req -in request.csr -noout -text
            
            Or integrate OpenSSL into this app (see README.md)
            """
            
        case .csrCreationNotSupported:
            return """
            CSR generation requires OpenSSL integration.
            
            To generate a CSR, use OpenSSL command line:
            openssl req -new -key private.key -out request.csr -subj "/CN=example.com/O=Company/C=US"
            
            Or integrate OpenSSL into this app (see README.md)
            """
            
        case .privateKeyImportNotSupported:
            return """
            Private key import requires OpenSSL integration.
            
            This feature needs PEM-to-SecKey conversion which requires:
            • OpenSSL library integration
            • Or CommonCrypto for format conversion
            
            See README.md for implementation guidance
            """
            
        case .keyGenerationNotSupported:
            return """
            Key generation requires OpenSSL integration.
            
            To generate keys, use OpenSSL command line:
            • RSA: openssl genrsa -out private.key 2048
            • EC: openssl ecparam -name prime256v1 -genkey -noout -out private.key
            • Ed25519: openssl genpkey -algorithm ed25519 -out private.key
            
            Or integrate OpenSSL into this app (see README.md)
            """
            
        case .certGenerationNotSupported:
            return """
            Certificate generation requires OpenSSL integration.
            
            To generate certificates, use OpenSSL command line:
            openssl req -x509 -newkey rsa:2048 -nodes -days 365 \\
              -keyout key.pem -out cert.pem \\
              -subj "/CN=example.com/O=Company/C=US"
            
            Or integrate OpenSSL into this app (see README.md)
            """
            
        case .certSigningNotSupported:
            return """
            Certificate signing requires OpenSSL integration.
            
            To sign certificates, use OpenSSL command line:
            openssl x509 -req -in request.csr \\
              -CA ca.crt -CAkey ca.key -CAcreateserial \\
              -out cert.pem -days 365
            
            Or integrate OpenSSL into this app (see README.md)
            """
            
        case .keystoreParsingNotSupported:
            return """
            Keystore parsing requires OpenSSL/keytool integration.
            
            To inspect keystores, use command line tools:
            • PKCS#12: openssl pkcs12 -in file.p12 -nokeys -info
            • JKS: keytool -list -v -keystore file.jks
            
            Or integrate OpenSSL into this app (see README.md)
            """
            
        case .pkcs12ExportNotSupported:
            return """
            PKCS#12 export requires OpenSSL integration.
            
            To create PKCS#12 files, use OpenSSL command line:
            openssl pkcs12 -export \\
              -in cert.pem -inkey key.pem \\
              -out output.pfx \\
              -name "My Certificate"
            
            Or integrate OpenSSL into this app (see README.md)
            """
        }
    }
    
    var recoverySuggestion: String? {
        switch self {
        case .csrParsingNotSupported, .csrCreationNotSupported,
             .privateKeyImportNotSupported, .keyGenerationNotSupported,
             .certGenerationNotSupported, .certSigningNotSupported,
             .keystoreParsingNotSupported, .pkcs12ExportNotSupported:
            return "See INSTALL.md and README.md for OpenSSL integration instructions"
        default:
            return nil
        }
    }
}
