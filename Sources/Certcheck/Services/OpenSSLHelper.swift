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
        let process = Process()
        process.executableURL = URL(fileURLWithPath: opensslPath)
        process.arguments = args
        
        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = errorPipe
        
        if let input = input {
            let inputPipe = Pipe()
            process.standardInput = inputPipe
            try inputPipe.fileHandleForWriting.write(contentsOf: input.data(using: .utf8)!)
            try inputPipe.fileHandleForWriting.close()
        }
        
        try process.run()
        process.waitUntilExit()
        
        let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
        let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
        
        guard process.terminationStatus == 0 else {
            let errorMsg = String(data: errorData, encoding: .utf8) ?? "Unknown error"
            throw NSError(domain: "OpenSSL", code: Int(process.terminationStatus), 
                         userInfo: [NSLocalizedDescriptionKey: errorMsg])
        }
        
        return String(data: outputData, encoding: .utf8) ?? ""
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

    /// Returns true when OpenSSL has dumped a binary blob as ASCII (many non-printable substitution dots)
    private func looksLikeBinaryDump(_ value: String) -> Bool {
        guard !value.isEmpty else { return false }
        let dots = value.filter { $0 == "." }.count
        return Double(dots) / Double(value.count) > 0.25
    }

    /// Parse all X.509v3 extensions AND the signature algorithm from a single OpenSSL text call.
    func parseAllExtensions(_ pem: String) throws -> (extensions: [CertExtension], san: [String], sigAlg: String) {
        let text = try runCommand(["x509", "-noout", "-text"], input: pem)
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
            let displayName = oidNames[currentName] ?? currentName
            
            let value = currentValueLines
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
                .joined(separator: "\n")
            
            // Replace binary garbage output with a clean label
            let displayValue = looksLikeBinaryDump(value) ? "Binary data (not human-readable)" : value
            
            if displayName == "Subject Alternative Name" {
                san = value.components(separatedBy: ",")
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                    .filter { !$0.isEmpty }
            }
            extensions.append(CertExtension(name: displayName, critical: currentCritical, value: displayValue))
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
                currentValueLines.append(trimmed)
            }
        }
        flush()

        return (extensions, san, sigAlg)
    }

    // MARK: - CSR Operations
    
    func parseCSR(_ pem: String) throws -> CSRInfo {
        let output = try runCommand(["req", "-noout", "-text"], input: pem)
        return try parseCSRText(output, pem: pem)
    }
    
    private func parseCSRText(_ text: String, pem: String) throws -> CSRInfo {
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
                if alg.contains("rsaEncryption")  { publicKeyType = "RSA" }
                else if alg.contains("ecPublicKey") || alg.contains("EC") { publicKeyType = "EC" }
                else if alg.contains("Ed25519")   { publicKeyType = "Ed25519" }
                else { publicKeyType = alg }
            }

            if line.hasPrefix("Public-Key:"), let parenIdx = line.firstIndex(of: "(") {
                let after = line[line.index(after: parenIdx)...]
                if let spaceIdx = after.firstIndex(of: " ") {
                    publicKeySize = Int(String(after[..<spaceIdx])) ?? publicKeySize
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
                    let val = extValueLines.map { $0.trimmingCharacters(in: .whitespaces) }
                        .filter { !$0.isEmpty }.joined(separator: "\n")
                    if extName == "Subject Alternative Name" {
                        sanList = val.components(separatedBy: ",")
                            .map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
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
                        extValueLines.append(extLine)
                    }
                    i += 1
                }
                saveCSRExt()
                continue
            }

            i += 1
        }

        // SHA-256 fingerprint of DER-encoded CSR
        var fingerprints = CertFingerprints(md5: "", sha1: "", sha256: "", spkiSha256: "")
        if let derData = try? runCommandData(["req", "-outform", "DER"], input: pem) {
            let sha256 = SHA256.hash(data: derData).map { String(format: "%02X", $0) }.joined(separator: ":")
            fingerprints = CertFingerprints(md5: "", sha1: "", sha256: sha256, spkiSha256: "")
        }

        return CSRInfo(
            subject: subjectDN,
            publicKey: PublicKeyInfo(type: publicKeyType, bits: publicKeySize),
            signatureAlg: signatureAlgorithm,
            selfSigValid: nil,
            sans: sanList,
            extensions: extensionsList,
            fingerprints: fingerprints
        )
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
    
    // MARK: - Chain Verification
    
    func verifyChain(certPEMs: [String], caBundle: String?) throws -> [ChainLink] {
        var links: [ChainLink] = []
        
        for (index, certPEM) in certPEMs.enumerated() {
            let subject = try runCommand(["x509", "-noout", "-subject"], input: certPEM)
                .replacingOccurrences(of: "subject=", with: "")
                .trimmingCharacters(in: .whitespacesAndNewlines)
            let issuer = try runCommand(["x509", "-noout", "-issuer"], input: certPEM)
                .replacingOccurrences(of: "issuer=", with: "")
                .trimmingCharacters(in: .whitespacesAndNewlines)
            let notAfter = try runCommand(["x509", "-noout", "-enddate"], input: certPEM)
                .replacingOccurrences(of: "notAfter=", with: "")
                .trimmingCharacters(in: .whitespacesAndNewlines)
            
            let selfSigned = subject == issuer
            var issuerChainOk = selfSigned
            var signatureOk: Bool? = nil
            
            // Try to verify with next cert or CA bundle
            if index + 1 < certPEMs.count {
                // Verify against next cert in chain
                let nextCert = certPEMs[index + 1]
                let tempCertFile = try writeSecureTempFile(certPEM)
                let tempIssuerFile = try writeSecureTempFile(nextCert)
                defer { removeTempFiles([tempCertFile, tempIssuerFile]) }
                
                do {
                    _ = try runCommand(["verify", "-CAfile", tempIssuerFile.path, tempCertFile.path])
                    signatureOk = true
                    issuerChainOk = true
                } catch {
                    signatureOk = false
                    issuerChainOk = false
                }
            } else if let caBundle = caBundle, !caBundle.isEmpty {
                // Verify against CA bundle
                let tempCertFile = try writeSecureTempFile(certPEM)
                let tempCAFile = try writeSecureTempFile(caBundle)
                defer { removeTempFiles([tempCertFile, tempCAFile]) }
                
                do {
                    _ = try runCommand(["verify", "-CAfile", tempCAFile.path, tempCertFile.path])
                    signatureOk = true
                    issuerChainOk = true
                } catch {
                    signatureOk = false
                    issuerChainOk = false
                }
            }
            
            links.append(ChainLink(
                index: index,
                subject: subject,
                issuer: issuer,
                notAfter: notAfter,
                selfSigned: selfSigned,
                issuerChainOk: issuerChainOk,
                signatureOk: signatureOk
            ))
        }
        
        return links
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

        let process = Process()
        process.executableURL = URL(fileURLWithPath: opensslPath)
        process.arguments = ["pkcs12", "-in", path, "-nokeys", "-passin", "file:\(tempPassFile.path)"]
        let outPipe = Pipe(), errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe
        try process.run()
        process.waitUntilExit()

        let out = String(data: outPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let err = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""

        if process.terminationStatus != 0 && out.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            throw NSError(domain: "OpenSSL", code: Int(process.terminationStatus),
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
        let process = Process()
        process.executableURL = URL(fileURLWithPath: opensslPath)
        process.arguments = args
        let outPipe = Pipe(), errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe
        if let input = input {
            let inPipe = Pipe()
            process.standardInput = inPipe
            try inPipe.fileHandleForWriting.write(contentsOf: input.data(using: .utf8)!)
            try inPipe.fileHandleForWriting.close()
        }
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let msg = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "Error"
            throw NSError(domain: "OpenSSL", code: Int(process.terminationStatus),
                         userInfo: [NSLocalizedDescriptionKey: msg])
        }
        return outPipe.fileHandleForReading.readDataToEndOfFile()
    }
}
