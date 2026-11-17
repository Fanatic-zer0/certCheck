import Foundation
import CryptoKit

/// Helper class to execute OpenSSL commands and parse results
class OpenSSLHelper {
    static let shared = OpenSSLHelper()
    private init() {}
    
    private let opensslPath = "/usr/bin/openssl"

    // MARK: - Secure Temp Files

    /// Writes content to a uniquely-named temp file restricted to the owner (0600).
    /// Private keys/passwords must never land in a world-readable path with a
    /// predictable name — both leak secrets to other local users.
    private func writeSecureTempFile(_ content: String, suffix: String = ".pem") throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("certcheck_\(UUID().uuidString)\(suffix)")
        try content.write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        return url
    }

    private func removeTempFiles(_ urls: [URL]) {
        for url in urls { try? FileManager.default.removeItem(at: url) }
    }
    
    // MARK: - Command Execution
    
    private func runCommand(_ args: [String], input: String? = nil) throws -> String {
        let result = try ProcessRunner.run(
            executable: opensslPath, arguments: args,
            stdin: input.flatMap { $0.data(using: .utf8) }
        )

        guard result.exitCode == 0 else {
            let errorMsg = String(data: result.stderr, encoding: .utf8) ?? "Unknown error"
            throw NSError(domain: "OpenSSL", code: Int(result.exitCode),
                         userInfo: [NSLocalizedDescriptionKey: errorMsg])
        }

        return String(data: result.stdout, encoding: .utf8) ?? ""
    }
    
    // MARK: - Certificate Extensions Parsing
    
    // Known vendor/non-standard OIDs that OpenSSL doesn't expand
    private let oidNames: [String: String] = [
        "1.3.6.1.4.1.11129.2.4.2": "Certificate Transparency SCTs",
        "1.3.6.1.4.1.11129.2.4.3": "Certificate Transparency Poison",
        "1.3.6.1.5.5.7.1.1":       "Authority Information Access",
        "1.3.6.1.5.5.7.1.11":      "Subject Information Access",
        "1.3.6.1.5.5.7.48.1":      "OCSP",
        "2.5.29.9":                 "Subject Directory Attributes",
        "2.5.29.56":                "No Revocation Available",
        "1.2.840.113533.7.65.0":    "Entrust Version Extension",
    ]

    /// Parse all X.509v3 extensions AND the signature algorithm from a single OpenSSL text call.
    func parseAllExtensions(_ pem: String) throws -> (extensions: [CertExtension], san: [String], sigAlg: String) {
        let text = try runCommand(["x509", "-noout", "-text", "-certopt", "ext_dump"], input: pem)
        return parseCertificateExtensionsText(text)
    }

    func parseCertificateExtensionsText(_ text: String) -> (extensions: [CertExtension], san: [String], sigAlg: String) {
        let lines = text.components(separatedBy: .newlines)

        // Extract sig alg from first occurrence (the second one is inside the Signature block)
        var sigAlg = "Unknown"
        for line in lines {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("Signature Algorithm:") {
                sigAlg = t.components(separatedBy: ":").dropFirst().joined(separator: ":").trimmingCharacters(in: .whitespaces)
                break
            }
        }

        guard let startIdx = lines.firstIndex(where: {
            $0.trimmingCharacters(in: .whitespaces) == "X509v3 extensions:"
        }) else {
            return ([], [], sigAlg)
        }
        
        var extensions: [CertExtension] = []
        var san: [String] = []
        var baseIndent = -1
        var currentName = ""
        var currentCritical = false
        var currentValueLines: [String] = []
        
        func flush() {
            guard !currentName.isEmpty else { return }
            // Map OID to readable name if still numeric
            let displayName = oidNames[currentName].map { "\($0) (\(currentName))" } ?? currentName
            
            let valueIndent = currentValueLines.filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
                .map { $0.prefix(while: { $0 == " " }).count }.min() ?? 0
            let value = currentValueLines.map { String($0.dropFirst(valueIndent)) }
                .joined(separator: "\n")
            
            if displayName == "Subject Alternative Name" {
                let separators = #",\s*(?=(?:DNS|IP Address|IP|URI|email|DirName|othername|Registered ID|RID|X400Name|EdiPartyName):)"#
                san = value.replacingOccurrences(of: separators, with: "\n", options: .regularExpression)
                    .components(separatedBy: .newlines)
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                    .filter { !$0.isEmpty }
            }
            extensions.append(CertExtension(name: displayName, critical: currentCritical, value: value))
            currentName = ""
            currentCritical = false
            currentValueLines = []
        }

        for i in (startIdx + 1)..<lines.count {
            let raw = lines[i]
            let trimmed = raw.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { continue }

            let indent = raw.prefix(while: { $0 == " " }).count
            if baseIndent == -1 { baseIndent = indent }
            if indent < baseIndent { break }

            if indent == baseIndent {
                flush()
                // Split header on first ":" to separate name from criticality marker
                var namePart = trimmed
                var critical = false
                if let colonRange = trimmed.range(of: ":") {
                    namePart = String(trimmed[..<colonRange.lowerBound]).trimmingCharacters(in: .whitespaces)
                    let rest = String(trimmed[colonRange.upperBound...]).trimmingCharacters(in: .whitespaces)
                    if rest == "critical" { critical = true }
                }
                if namePart.hasPrefix("X509v3 ") {
                    namePart = String(namePart.dropFirst("X509v3 ".count))
                }
                currentName = namePart
                currentCritical = critical
            } else {
                currentValueLines.append(raw)
            }
        }
        flush()

        return (extensions, san, sigAlg)
    }

    // MARK: - CSR Operations
    
    func parseCSR(_ pem: String) throws -> CSRInfo {
        let output = try runCommand(["req", "-noout", "-text"], input: pem)
        let der = try runCommandData(["req", "-outform", "DER"], input: pem)
        let verification = try ProcessRunner.run(
            executable: opensslPath,
            arguments: ["req", "-verify", "-noout"],
            stdin: pem.data(using: .utf8)
        )
        let verificationOutput = String(data: verification.stdout + verification.stderr, encoding: .utf8) ?? ""
        let signatureIsValid = verification.exitCode == 0
            && verificationOutput.localizedCaseInsensitiveContains("verify OK")
            && !verificationOutput.localizedCaseInsensitiveContains("verify failure")
        return parseCSRText(output, der: der, signatureIsValid: signatureIsValid)
    }
    
    func parseCSRText(_ text: String, der: Data, signatureIsValid: Bool) -> CSRInfo {
        var subjectDN: OrderedDN = []
        var signatureAlgorithm = "Unknown"
        var publicKeyType = "Unknown"
        var publicKeySize = 0
        var sanList: [String] = []
        var extensionsList: [CertExtension] = []

        let lines = text.components(separatedBy: .newlines)
        var i = 0

        while i < lines.count {
            let raw = lines[i]
            let line = raw.trimmingCharacters(in: .whitespaces)

            if line.hasPrefix("Subject:") && !line.contains("Subject Public Key") {
                let subjectStr = String(line.dropFirst("Subject:".count)).trimmingCharacters(in: .whitespaces)
                subjectDN = parseSubjectString(subjectStr)
            }

            // Take only the first Signature Algorithm (the second one is inside the raw signature block)
            if line.hasPrefix("Signature Algorithm:") && signatureAlgorithm == "Unknown" {
                signatureAlgorithm = String(line.dropFirst("Signature Algorithm:".count)).trimmingCharacters(in: .whitespaces)
            }

            if line.hasPrefix("Public Key Algorithm:") {
                let alg = String(line.dropFirst("Public Key Algorithm:".count)).trimmingCharacters(in: .whitespaces)
                let normalized = alg.lowercased()
                if normalized.contains("rsa") { publicKeyType = "RSA" }
                else if normalized.contains("ec") { publicKeyType = "EC" }
                else if normalized.contains("ed25519") {
                    publicKeyType = "Ed25519"
                    publicKeySize = 256
                } else if normalized.contains("ed448") {
                    publicKeyType = "Ed448"
                    publicKeySize = 456
                }
                else { publicKeyType = alg }
            }

            if line.contains("Public-Key:"), let parenIdx = line.firstIndex(of: "(") {
                let after = line[line.index(after: parenIdx)...]
                if let spaceIdx = after.firstIndex(of: " ") {
                    let size = String(after[..<spaceIdx])
                    if let bits = Int(size) {
                        publicKeySize = bits
                    }
                }
            }

            // Parse the "Requested Extensions:" block — this is where SANs/KU/EKU live in a CSR
            if line == "Requested Extensions:" {
                i += 1
                guard i < lines.count else { break }
                let baseIndent = lines[i].prefix(while: { $0 == " " }).count

                var extName = ""
                var extCritical = false
                var extValueLines: [String] = []

                func saveCSRExt() {
                    guard !extName.isEmpty else { return }
                    let valueIndent = extValueLines.filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
                        .map { $0.prefix(while: { $0 == " " }).count }.min() ?? 0
                    let val = extValueLines.map { String($0.dropFirst(valueIndent)) }
                        .joined(separator: "\n")
                    if extName == "Subject Alternative Name" {
                        sanList = parseCSRGeneralNames(val)
                    }
                    extensionsList.append(CertExtension(name: extName, critical: extCritical, value: val))
                    extName = ""; extCritical = false; extValueLines = []
                }

                while i < lines.count {
                    let extRaw = lines[i]
                    let extLine = extRaw.trimmingCharacters(in: .whitespaces)
                    guard !extLine.isEmpty else { i += 1; continue }
                    let extIndent = extRaw.prefix(while: { $0 == " " }).count
                    if extIndent < baseIndent { break }

                    if extIndent == baseIndent {
                        saveCSRExt()
                        var header = extLine
                        var critical = false
                        if let colonRange = header.range(of: ":") {
                            let name = String(header[..<colonRange.lowerBound]).trimmingCharacters(in: .whitespaces)
                            let rest = String(header[colonRange.upperBound...]).trimmingCharacters(in: .whitespaces)
                            if rest == "critical" { critical = true }
                            header = name
                        }
                        if header.hasPrefix("X509v3 ") { header = String(header.dropFirst("X509v3 ".count)) }
                        extName = header; extCritical = critical
                    } else {
                        extValueLines.append(extRaw)
                    }
                    i += 1
                }
                saveCSRExt()
                continue
            }

            i += 1
        }

        let fingerprints = CertFingerprints(
            md5: Insecure.MD5.hash(data: der).map { String(format: "%02X", $0) }.joined(separator: ":"),
            sha1: Insecure.SHA1.hash(data: der).map { String(format: "%02X", $0) }.joined(separator: ":"),
            sha256: SHA256.hash(data: der).map { String(format: "%02X", $0) }.joined(separator: ":"),
            spkiSha256: ""
        )

        return CSRInfo(
            subject: subjectDN,
            publicKey: PublicKeyInfo(type: publicKeyType, bits: publicKeySize),
            signatureAlg: signatureAlgorithm,
            selfSigValid: signatureIsValid,
            sans: sanList,
            extensions: extensionsList,
            fingerprints: fingerprints
        )
    }

    private func parseCSRGeneralNames(_ value: String) -> [String] {
        let separators = #",\s*(?=(?:DNS|IP Address|IP|URI|email|DirName|othername|Registered ID|RID|X400Name|EdiPartyName):)"#
        return value.replacingOccurrences(of: separators, with: "\n", options: .regularExpression)
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    // Regex-based subject parser — handles values with commas correctly
    private func parseSubjectString(_ str: String) -> OrderedDN {
        var result: OrderedDN = []
        let pattern = #"([A-Za-z0-9\.]+)\s*=\s*((?:[^,]|,(?!\s*[A-Za-z0-9\.]+\s*=))+)"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return result }
        for match in regex.matches(in: str, range: NSRange(str.startIndex..., in: str)) {
            guard let kr = Range(match.range(at: 1), in: str),
                  let vr = Range(match.range(at: 2), in: str) else { continue }
            let key = String(str[kr]).trimmingCharacters(in: .whitespaces)
            let val = String(str[vr]).trimmingCharacters(in: .whitespaces)
            result.append((key: key, value: val))
        }
        return result
    }
    
    // MARK: - Key Matching
    
    func matchCertWithKey(certPEM: String, keyPEM: String) throws -> (match: Bool, detail: String) {
        // "pkey" derives the public key regardless of algorithm (RSA/EC/Ed25519/Ed448)
        // or container format (PKCS#1, SEC1, PKCS#8) — unlike "rsa"/"ec" which only
        // handle one algorithm each, so a PKCS#8-wrapped EC key would error out on "rsa".
        let certPubKey = try runCommand(["x509", "-noout", "-pubkey"], input: certPEM)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let keyPubKey = try runCommand(["pkey", "-pubout"], input: keyPEM)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        
        let match = certPubKey == keyPubKey
        let detail = match ? "Certificate public key matches the private key" : 
                            "Certificate and private key do NOT match"
        return (match, detail)
    }
    
    func matchCertWithCSR(certPEM: String, csrPEM: String) throws -> CSRMatchResult {
        // Compare public keys
        let certPubKey = try runCommand(["x509", "-noout", "-pubkey"], input: certPEM)
        let csrPubKey = try runCommand(["req", "-noout", "-pubkey"], input: csrPEM)
        let pkMatch = certPubKey.trimmingCharacters(in: .whitespacesAndNewlines) == 
                      csrPubKey.trimmingCharacters(in: .whitespacesAndNewlines)
        
        // Compare subjects
        let certSubject = try runCommand(["x509", "-noout", "-subject"], input: certPEM)
            .replacingOccurrences(of: "subject=", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let csrSubject = try runCommand(["req", "-noout", "-subject"], input: csrPEM)
            .replacingOccurrences(of: "subject=", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let subjMatch = certSubject == csrSubject
        
        return CSRMatchResult(
            publicKeyMatch: pkMatch,
            subjectMatch: subjMatch,
            certSubject: certSubject,
            csrSubject: csrSubject
        )
    }
    
    func matchCSRWithKey(csrPEM: String, keyPEM: String) throws -> (match: Bool, detail: String) {
        // "pkey" derives the public key regardless of algorithm or container format
        let csrPubKey = try runCommand(["req", "-noout", "-pubkey"], input: csrPEM)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let keyPubKey = try runCommand(["pkey", "-pubout"], input: keyPEM)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        
        let match = csrPubKey == keyPubKey
        let detail = match ? "CSR public key matches the private key" : 
                            "CSR and private key do NOT match"
        return (match, detail)
    }
    
    func verifyCertificateChainLink(certificate: String, root: String, intermediates: [String]) -> Bool {
        do {
            let certificateFile = try writeSecureTempFile(certificate)
            let rootFile = try writeSecureTempFile(root)
            var tempFiles = [certificateFile, rootFile]
            var arguments = ["verify", "-CAfile", rootFile.path, "-check_ss_sig"]
            if !intermediates.isEmpty {
                let intermediatesFile = try writeSecureTempFile(intermediates.joined(separator: "\n"))
                tempFiles.append(intermediatesFile)
                arguments += ["-untrusted", intermediatesFile.path]
            }
            arguments.append(certificateFile.path)
            defer { removeTempFiles(tempFiles) }
            _ = try runCommand(arguments)
            return true
        } catch {
            return false
        }
    }
    
    // MARK: - Generation Operations
    
    func generateKeyPair(algorithm: String, keySize: Int) throws -> String {
        switch algorithm.lowercased() {
        case "rsa":
            return try runCommand(["genrsa", "\(keySize)"])
        case "ec":
            let curve: String
            switch keySize {
            case 256: curve = "prime256v1"
            case 384: curve = "secp384r1"
            case 521: curve = "secp521r1"
            default: curve = "prime256v1"
            }
            return try runCommand(["ecparam", "-name", curve, "-genkey", "-noout"])
        case "ed25519":
            return try runCommand(["genpkey", "-algorithm", "ed25519"])
        default:
            throw NSError(domain: "OpenSSL", code: -1, 
                         userInfo: [NSLocalizedDescriptionKey: "Unsupported algorithm: \(algorithm)"])
        }
    }
    
    func generateCSR(privateKey: String, subject: OrderedDN, san: [String]) throws -> String {
        let tempKeyFile = try writeSecureTempFile(privateKey)
        defer { removeTempFiles([tempKeyFile]) }
        
        // Build subject string from OrderedDN
        var subjectStr = ""
        for (key, value) in subject {
            subjectStr += "/\(key)=\(value)"
        }
        
        var args = ["req", "-new", "-key", tempKeyFile.path, "-subj", subjectStr]
        
        // Add SANs if provided
        if !san.isEmpty {
            let sanStr = san.map { entry in
                if entry.contains(":") {
                    return entry // Already formatted (e.g., "DNS:example.com")
                } else if entry.contains("@") {
                    return "email:\(entry)"
                } else if entry.range(of: #"^\d+\.\d+\.\d+\.\d+$"#, options: .regularExpression) != nil {
                    return "IP:\(entry)"
                } else {
                    return "DNS:\(entry)"
                }
            }.joined(separator: ",")
            
            args += ["-addext", "subjectAltName=\(sanStr)"]
        }
        
        return try runCommand(args)
    }
    
    func generateSelfSignedCert(privateKey: String, subject: OrderedDN, san: [String], 
                               days: Int, certType: String) throws -> String {
        let tempKeyFile = try writeSecureTempFile(privateKey)
        defer { removeTempFiles([tempKeyFile]) }
        
        // Build subject string from OrderedDN
        var subjectStr = ""
        for (key, value) in subject {
            subjectStr += "/\(key)=\(value)"
        }
        
        var args = ["req", "-x509", "-new", "-key", tempKeyFile.path, "-days", "\(days)", 
                    "-subj", subjectStr]
        
        // Add SANs if provided
        if !san.isEmpty {
            let sanStr = san.map { entry in
                if entry.contains(":") {
                    return entry
                } else if entry.contains("@") {
                    return "email:\(entry)"
                } else if entry.range(of: #"^\d+\.\d+\.\d+\.\d+$"#, options: .regularExpression) != nil {
                    return "IP:\(entry)"
                } else {
                    return "DNS:\(entry)"
                }
            }.joined(separator: ",")
            
            args += ["-addext", "subjectAltName=\(sanStr)"]
        }
        
        // Add extensions based on cert type
        if certType == "Root CA" {
            args += ["-addext", "basicConstraints=critical,CA:TRUE"]
            args += ["-addext", "keyUsage=critical,keyCertSign,cRLSign"]
        } else if certType == "Intermediate CA" {
            args += ["-addext", "basicConstraints=critical,CA:TRUE,pathlen:0"]
            args += ["-addext", "keyUsage=critical,keyCertSign,cRLSign"]
        }
        
        return try runCommand(args)
    }
    
    /// Signs a CSR with a CA certificate/key, producing a properly chained certificate
    /// (Issuer = CA subject) instead of a self-signed one.
    func signCSRWithCA(csrPEM: String, caCertPEM: String, caKeyPEM: String,
                       days: Int, extensionsConfig: String?) throws -> String {
        let csrFile = try writeSecureTempFile(csrPEM)
        let caCertFile = try writeSecureTempFile(caCertPEM)
        let caKeyFile = try writeSecureTempFile(caKeyPEM)
        // "-CAcreateserial" drops a .srl file next to the CA cert file
        let serialFile = caCertFile.deletingPathExtension().appendingPathExtension("srl")
        var tempFiles = [csrFile, caCertFile, caKeyFile, serialFile]
        defer { removeTempFiles(tempFiles) }

        var args = ["x509", "-req", "-in", csrFile.path,
                    "-CA", caCertFile.path, "-CAkey", caKeyFile.path,
                    "-CAcreateserial", "-days", "\(days)"]

        if let extensionsConfig = extensionsConfig, !extensionsConfig.isEmpty {
            let extFile = try writeSecureTempFile("[v3_ext]\n\(extensionsConfig)\n", suffix: ".cnf")
            tempFiles.append(extFile)
            args += ["-extfile", extFile.path, "-extensions", "v3_ext"]
        }

        return try runCommand(args)
    }
    
    func createPKCS12(certPEM: String, keyPEM: String, password: String, friendlyName: String, 
                     chainPEM: String?) throws -> Data {
        let tempCertFile = try writeSecureTempFile(certPEM)
        let tempKeyFile = try writeSecureTempFile(keyPEM)
        let tempP12File = FileManager.default.temporaryDirectory.appendingPathComponent("certcheck_\(UUID().uuidString).p12")
        // Pass the password via a file, not argv — command-line args are visible
        // to other local users via `ps`.
        let tempPassFile = try writeSecureTempFile(password, suffix: ".pass")
        var tempFiles = [tempCertFile, tempKeyFile, tempPassFile]
        defer { removeTempFiles(tempFiles + [tempP12File]) }
        
        var args = ["pkcs12", "-export", "-out", tempP12File.path, 
                    "-in", tempCertFile.path, "-inkey", tempKeyFile.path,
                    "-passout", "file:\(tempPassFile.path)", "-name", friendlyName]
        
        if let chainPEM = chainPEM, !chainPEM.isEmpty {
            let tempChainFile = try writeSecureTempFile(chainPEM)
            tempFiles.append(tempChainFile)
            args += ["-certfile", tempChainFile.path]
        }
        
        _ = try runCommand(args)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tempP12File.path)
        
        return try Data(contentsOf: tempP12File)
    }

    // MARK: - Private Key Inspector

    struct KeyInspectResult {
        var type: String
        var bits: Int
        var curve: String?
        var isEncrypted: Bool
        var publicKeyPEM: String
        var publicKeyFingerprint: String
        var publicExponent: String?
    }

    func inspectPrivateKey(_ pem: String) throws -> KeyInspectResult {
        let isEncrypted = pem.contains("ENCRYPTED")
        let text = try runCommand(["pkey", "-noout", "-text"], input: pem)
        let pubPEM = try runCommand(["pkey", "-pubout"], input: pem)

        var keyType = "Unknown"
        var bits = 0
        var curve: String? = nil
        var pubExp: String? = nil

        for line in text.components(separatedBy: .newlines) {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.contains("RSA") { keyType = "RSA" }
            if t.contains("Ed25519") || t.contains("ED25519") { keyType = "Ed25519"; bits = 256 }
            if t.hasPrefix("NIST CURVE:") {
                curve = t.components(separatedBy: ":").last?.trimmingCharacters(in: .whitespaces)
                if keyType == "Unknown" { keyType = "EC" }
            }
            if t.hasPrefix("ASN1 OID:") && keyType == "Unknown" {
                keyType = "EC"
                curve = t.components(separatedBy: ":").last?.trimmingCharacters(in: .whitespaces)
            }
            // Extract bit size from "(2048 bit" patterns
            if t.contains(" bit") && bits == 0, let parenIdx = t.firstIndex(of: "(") {
                let after = t[t.index(after: parenIdx)...]
                if let spaceIdx = after.firstIndex(of: " ") {
                    bits = Int(String(after[..<spaceIdx])) ?? 0
                }
            }
            if t.hasPrefix("publicExponent:") {
                pubExp = t.components(separatedBy: ":").last?.trimmingCharacters(in: .whitespaces)
            }
        }

        // Fingerprint = SHA-256 of DER-encoded public key
        let pubDER = try runCommandData(["pkey", "-pubout", "-outform", "DER"], input: pem)
        let fingerprint = SHA256.hash(data: pubDER)
            .map { String(format: "%02x", $0) }.joined(separator: ":")

        return KeyInspectResult(
            type: keyType, bits: bits, curve: curve, isEncrypted: isEncrypted,
            publicKeyPEM: pubPEM.trimmingCharacters(in: .whitespacesAndNewlines),
            publicKeyFingerprint: fingerprint, publicExponent: pubExp
        )
    }

    // MARK: - Certificate Converter

    func convertCertToDER(_ pem: String) throws -> Data {
        return try runCommandData(["x509", "-outform", "DER"], input: pem)
    }

    func convertCertToPKCS7(_ pem: String) throws -> String {
        let tmp = try writeSecureTempFile(pem)
        defer { removeTempFiles([tmp]) }
        return try runCommand(["crl2pkcs7", "-nocrl", "-certfile", tmp.path])
    }

    // MARK: - Keystore (PKCS#12)

    func extractCertsFromPKCS12(path: String, password: String) throws -> [String] {
        // Pass the password via a file, not argv — command-line args are visible
        // to other local users via `ps`.
        let tempPassFile = try writeSecureTempFile(password, suffix: ".pass")
        defer { removeTempFiles([tempPassFile]) }

        let result = try ProcessRunner.run(
            executable: opensslPath,
            arguments: ["pkcs12", "-in", path, "-nokeys", "-passin", "file:\(tempPassFile.path)"]
        )

        let out = String(data: result.stdout, encoding: .utf8) ?? ""
        let err = String(data: result.stderr, encoding: .utf8) ?? ""

        if result.exitCode != 0 && out.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            throw NSError(domain: "OpenSSL", code: Int(result.exitCode),
                         userInfo: [NSLocalizedDescriptionKey: err.trimmingCharacters(in: .whitespacesAndNewlines)])
        }

        let combined = out + err
        guard let regex = try? NSRegularExpression(
            pattern: "-----BEGIN CERTIFICATE-----[\\s\\S]+?-----END CERTIFICATE-----") else { return [] }
        let matches = regex.matches(in: combined, range: NSRange(combined.startIndex..., in: combined))
        let certs = matches.compactMap { m -> String? in
            guard let r = Range(m.range, in: combined) else { return nil }
            return String(combined[r])
        }
        if certs.isEmpty {
            throw NSError(domain: "OpenSSL", code: -1,
                         userInfo: [NSLocalizedDescriptionKey: "No certificates found in keystore. Check password."])
        }
        return certs
    }

    // Binary output variant of runCommand (no string decoding)
    private func runCommandData(_ args: [String], input: String? = nil) throws -> Data {
        let result = try ProcessRunner.run(
            executable: opensslPath, arguments: args,
            stdin: input.flatMap { $0.data(using: .utf8) }
        )
        guard result.exitCode == 0 else {
            let msg = String(data: result.stderr, encoding: .utf8) ?? "Error"
            throw NSError(domain: "OpenSSL", code: Int(result.exitCode),
                         userInfo: [NSLocalizedDescriptionKey: msg])
        }
        return result.stdout
    }
}
