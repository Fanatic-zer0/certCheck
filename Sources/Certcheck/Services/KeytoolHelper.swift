import Foundation

/// Wraps the JDK `keytool` CLI to manage Java keystores (JKS / PKCS#12 / JCEKS)
/// without requiring the user to remember keytool syntax.
class KeytoolHelper {
    static let shared = KeytoolHelper()
    private init() {}

    private lazy var resolvedKeytoolPath: String? = locateKeytool()

    var keytoolPath: String? { resolvedKeytoolPath }

    var isKeytoolAvailable: Bool { resolvedKeytoolPath != nil }

    // MARK: - Locating keytool

    private func locateKeytool() -> String? {
        let fm = FileManager.default

        // 1. /usr/libexec/java_home (macOS JDK registry)
        if let home = try? runRawProcess("/usr/libexec/java_home", args: []) {
            let path = home.trimmingCharacters(in: .whitespacesAndNewlines) + "/bin/keytool"
            if fm.isExecutableFile(atPath: path) { return path }
        }

        // 2. JAVA_HOME environment variable
        if let javaHome = ProcessInfo.processInfo.environment["JAVA_HOME"], !javaHome.isEmpty {
            let path = javaHome + "/bin/keytool"
            if fm.isExecutableFile(atPath: path) { return path }
        }

        // 3. Common install locations
        for path in [
            "/usr/bin/keytool",
            "/opt/homebrew/opt/openjdk/bin/keytool",
            "/usr/local/opt/openjdk/bin/keytool"
        ] {
            if fm.isExecutableFile(atPath: path) { return path }
        }

        return nil
    }

    private func runRawProcess(_ executable: String, args: [String]) throws -> String {
        let result = try ProcessRunner.run(executable: executable, arguments: args)
        guard result.exitCode == 0 else { throw KeytoolError.javaNotFound }
        return String(data: result.stdout, encoding: .utf8) ?? ""
    }

    // MARK: - Secure Temp Files

    /// Writes content to a uniquely-named temp file restricted to the owner (0600).
    /// Passwords must never be passed via argv (visible to other local users via `ps`),
    /// so they are always written to a secure temp file and referenced with `:file`.
    private func writeSecurePassFile(_ content: String) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("certcheck_\(UUID().uuidString).pass")
        try content.write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        return url
    }

    private func writeSecureTempFile(_ content: String, suffix: String) throws -> URL {
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

    @discardableResult
    private func runKeytool(_ args: [String], stdin: String? = nil) throws -> String {
        guard let keytoolPath = resolvedKeytoolPath else { throw KeytoolError.javaNotFound }

        let result = try ProcessRunner.run(
            executable: keytoolPath, arguments: args,
            stdin: stdin.flatMap { $0.data(using: .utf8) }
        )

        let output = String(data: result.stdout, encoding: .utf8) ?? ""
        let errorText = String(data: result.stderr, encoding: .utf8) ?? ""

        guard result.exitCode == 0 else {
            let message = errorText.trimmingCharacters(in: .whitespacesAndNewlines)
            throw KeytoolError.commandFailed(message.isEmpty ? output : message)
        }

        // keytool sometimes writes informational text (e.g. certreq) to stderr even on success
        return output.isEmpty ? errorText : output
    }

    // MARK: - Store Type Detection

    func detectStoreType(path: String) -> KeystoreFormat {
        guard let data = FileManager.default.contents(atPath: path), data.count >= 4 else { return .jks }
        let magic = data.prefix(4).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        if magic == 0xFEED_FEED { return .jks }
        if magic == 0xCECE_CECE { return .jceks }
        if data[0] == 0x30 { return .pkcs12 }
        return .jks
    }

    private func storeTypeArgs(_ format: KeystoreFormat, flag: String = "-storetype") -> [String] {
        guard let arg = format.keytoolArg else { return [] }
        return [flag, arg]
    }

    // MARK: - List Entries

    /// Runs `keytool -list -v` and returns the raw human-readable output.
    func rawList(keystorePath: String, storeType: KeystoreFormat, password: String) throws -> String {
        let passFile = try writeSecurePassFile(password)
        defer { removeTempFiles([passFile]) }

        var args = ["-list", "-v", "-keystore", keystorePath, "-storepass:file", passFile.path]
        args += storeTypeArgs(storeType)
        return try runKeytool(args)
    }

    /// Parses the output of `keytool -list -v` into per-alias summary rows.
    func parseListOutput(_ text: String) -> [(alias: String, entryType: String, creationDate: String, chainLength: Int)] {
        var results: [(String, String, String, Int)] = []
        var alias: String?
        var entryType = "Unknown"
        var creationDate = ""
        var chainLength = 1

        func flush() {
            guard let alias = alias else { return }
            results.append((alias, entryType, creationDate, chainLength))
        }

        for raw in text.components(separatedBy: .newlines) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("Alias name:") {
                flush()
                alias = line.replacingOccurrences(of: "Alias name:", with: "").trimmingCharacters(in: .whitespaces)
                entryType = "Unknown"; creationDate = ""; chainLength = 1
            } else if line.hasPrefix("Creation date:") {
                creationDate = line.replacingOccurrences(of: "Creation date:", with: "").trimmingCharacters(in: .whitespaces)
            } else if line.hasPrefix("Entry type:") {
                entryType = line.replacingOccurrences(of: "Entry type:", with: "").trimmingCharacters(in: .whitespaces)
            } else if line.hasPrefix("Certificate chain length:") {
                chainLength = Int(line.replacingOccurrences(of: "Certificate chain length:", with: "")
                    .trimmingCharacters(in: .whitespaces)) ?? 1
            }
        }
        flush()
        return results
    }

    /// Full list: metadata + parsed leaf certificate (via CertService) + chain PEMs.
    func listEntries(keystorePath: String, storeType: KeystoreFormat, password: String) throws -> [KeystoreEntryInfo] {
        let text = try rawList(keystorePath: keystorePath, storeType: storeType, password: password)
        let rows = parseListOutput(text)
        guard !rows.isEmpty else { return [] }

        let resolvedType = storeType == .auto ? detectStoreType(path: keystorePath) : storeType

        return rows.map { row in
            guard row.entryType != "SecretKeyEntry" else {
                return KeystoreEntryInfo(
                    alias: row.alias, entryType: row.entryType, creationDate: row.creationDate,
                    chainLength: row.chainLength, certInfo: nil, chainPEMs: [], parseError: nil
                )
            }
            do {
                let leafPEM = try exportCertificate(
                    keystorePath: keystorePath, storeType: resolvedType, alias: row.alias, password: password
                )
                let certInfo = try CertService.shared.parseCertificate(pem: leafPEM)
                let chain = row.chainLength > 1
                    ? (try? exportChain(keystorePath: keystorePath, storeType: resolvedType, alias: row.alias, password: password)) ?? [leafPEM]
                    : [leafPEM]
                return KeystoreEntryInfo(
                    alias: row.alias, entryType: row.entryType, creationDate: row.creationDate,
                    chainLength: row.chainLength, certInfo: certInfo, chainPEMs: chain, parseError: nil
                )
            } catch {
                return KeystoreEntryInfo(
                    alias: row.alias, entryType: row.entryType, creationDate: row.creationDate,
                    chainLength: row.chainLength, certInfo: nil, chainPEMs: [], parseError: error.localizedDescription
                )
            }
        }
    }

    // MARK: - Certificate Export / Inspect

    /// `keytool -exportcert -rfc` — exports only the leaf certificate as PEM.
    func exportCertificate(keystorePath: String, storeType: KeystoreFormat, alias: String, password: String) throws -> String {
        let passFile = try writeSecurePassFile(password)
        defer { removeTempFiles([passFile]) }

        var args = ["-exportcert", "-alias", alias, "-keystore", keystorePath,
                    "-storepass:file", passFile.path, "-rfc"]
        args += storeTypeArgs(storeType)
        return try runKeytool(args)
    }

    /// `keytool -list -rfc -alias` — dumps the full certificate chain in PEM (leaf first).
    func exportChain(keystorePath: String, storeType: KeystoreFormat, alias: String, password: String) throws -> [String] {
        let passFile = try writeSecurePassFile(password)
        defer { removeTempFiles([passFile]) }

        var args = ["-list", "-rfc", "-alias", alias, "-keystore", keystorePath, "-storepass:file", passFile.path]
        args += storeTypeArgs(storeType)
        let output = try runKeytool(args)
        return extractPEMBlocks(output)
    }

    private func extractPEMBlocks(_ text: String) -> [String] {
        guard let regex = try? NSRegularExpression(
            pattern: "-----BEGIN CERTIFICATE-----[\\s\\S]+?-----END CERTIFICATE-----") else { return [] }
        let matches = regex.matches(in: text, range: NSRange(text.startIndex..., in: text))
        return matches.compactMap { match -> String? in
            guard let range = Range(match.range, in: text) else { return nil }
            return String(text[range])
        }
    }

    // MARK: - Import Trusted Certificate / Certificate Reply

    /// `keytool -importcert -noprompt` — imports a cert as a new trusted entry.
    func importTrustedCertificate(
        keystorePath: String, storeType: KeystoreFormat, alias: String, password: String, certPEM: String
    ) throws -> String {
        let passFile = try writeSecurePassFile(password)
        let certFile = try writeSecureTempFile(certPEM, suffix: ".pem")
        defer { removeTempFiles([passFile, certFile]) }

        var args = ["-importcert", "-alias", alias, "-file", certFile.path,
                    "-keystore", keystorePath, "-storepass:file", passFile.path, "-noprompt"]
        args += storeTypeArgs(storeType)
        return try runKeytool(args)
    }

    /// `keytool -importcert` into an existing private-key alias — completes a CA-signed CSR reply.
    func importCertificateReply(
        keystorePath: String, storeType: KeystoreFormat, alias: String,
        password: String, keyPassword: String?, replyPEM: String
    ) throws -> String {
        let passFile = try writeSecurePassFile(password)
        let replyFile = try writeSecureTempFile(replyPEM, suffix: ".pem")
        var tempFiles = [passFile, replyFile]
        defer { removeTempFiles(tempFiles) }

        var args = ["-importcert", "-alias", alias, "-file", replyFile.path,
                    "-keystore", keystorePath, "-storepass:file", passFile.path, "-trustcacerts"]
        if let keyPassword = keyPassword, !keyPassword.isEmpty {
            let keyPassFile = try writeSecurePassFile(keyPassword)
            tempFiles.append(keyPassFile)
            args += ["-keypass:file", keyPassFile.path]
        }
        args += storeTypeArgs(storeType)
        return try runKeytool(args)
    }

    // MARK: - CSR Generation

    /// `keytool -certreq` — outputs the CSR to stdout.
    func generateCSR(
        keystorePath: String, storeType: KeystoreFormat, alias: String,
        password: String, keyPassword: String?, dname: String?, sigAlg: String?
    ) throws -> String {
        let passFile = try writeSecurePassFile(password)
        var tempFiles = [passFile]
        defer { removeTempFiles(tempFiles) }

        var args = ["-certreq", "-alias", alias, "-keystore", keystorePath, "-storepass:file", passFile.path]
        if let keyPassword = keyPassword, !keyPassword.isEmpty {
            let keyPassFile = try writeSecurePassFile(keyPassword)
            tempFiles.append(keyPassFile)
            args += ["-keypass:file", keyPassFile.path]
        }
        if let dname = dname, !dname.isEmpty { args += ["-dname", dname] }
        if let sigAlg = sigAlg, !sigAlg.isEmpty { args += ["-sigalg", sigAlg] }
        args += storeTypeArgs(storeType)
        return try runKeytool(args)
    }

    // MARK: - Generate Key Pair

    func generateKeyPair(
        keystorePath: String, storeType: KeystoreFormat, alias: String,
        password: String, keyPassword: String?, keyAlg: String, keySizeOrCurve: Int,
        validityDays: Int, dname: String, sanEntries: [String]
    ) throws -> String {
        let passFile = try writeSecurePassFile(password)
        var tempFiles = [passFile]
        defer { removeTempFiles(tempFiles) }

        var args = ["-genkeypair", "-alias", alias, "-dname", dname,
                    "-validity", "\(validityDays)", "-keystore", keystorePath,
                    "-storepass:file", passFile.path]

        if let keyPassword = keyPassword, !keyPassword.isEmpty {
            let keyPassFile = try writeSecurePassFile(keyPassword)
            tempFiles.append(keyPassFile)
            args += ["-keypass:file", keyPassFile.path]
        }

        if keyAlg.uppercased() == "EC" {
            let group: String
            switch keySizeOrCurve {
            case 384: group = "secp384r1"
            case 521: group = "secp521r1"
            default:  group = "secp256r1"
            }
            args += ["-keyalg", "EC", "-groupname", group]
        } else {
            args += ["-keyalg", "RSA", "-keysize", "\(keySizeOrCurve)"]
        }

        if !sanEntries.isEmpty {
            let sanStr = sanEntries.map { entry -> String in
                if entry.range(of: #"^\d{1,3}(\.\d{1,3}){3}$"#, options: .regularExpression) != nil {
                    return "ip:\(entry)"
                }
                return "dns:\(entry)"
            }.joined(separator: ",")
            args += ["-ext", "SAN=\(sanStr)"]
        }

        args += storeTypeArgs(storeType)
        return try runKeytool(args)
    }

    // MARK: - Convert Keystore (JKS <-> PKCS12)

    func convertKeystore(
        srcPath: String, srcType: KeystoreFormat, srcPassword: String,
        destPath: String, destType: KeystoreFormat, destPassword: String
    ) throws -> String {
        let srcPassFile = try writeSecurePassFile(srcPassword)
        let destPassFile = try writeSecurePassFile(destPassword)
        defer { removeTempFiles([srcPassFile, destPassFile]) }

        var args = ["-importkeystore",
                    "-srckeystore", srcPath, "-srcstorepass:file", srcPassFile.path,
                    "-destkeystore", destPath, "-deststorepass:file", destPassFile.path,
                    "-noprompt"]
        args += storeTypeArgs(srcType, flag: "-srcstoretype")
        args += storeTypeArgs(destType, flag: "-deststoretype")
        return try runKeytool(args)
    }

    // MARK: - Rename / Delete Alias

    func renameAlias(
        keystorePath: String, storeType: KeystoreFormat, password: String,
        oldAlias: String, newAlias: String, keyPassword: String?
    ) throws -> String {
        let passFile = try writeSecurePassFile(password)
        var tempFiles = [passFile]
        defer { removeTempFiles(tempFiles) }

        var args = ["-changealias", "-alias", oldAlias, "-destalias", newAlias,
                    "-keystore", keystorePath, "-storepass:file", passFile.path]
        if let keyPassword = keyPassword, !keyPassword.isEmpty {
            let keyPassFile = try writeSecurePassFile(keyPassword)
            tempFiles.append(keyPassFile)
            args += ["-keypass:file", keyPassFile.path]
        }
        args += storeTypeArgs(storeType)
        return try runKeytool(args)
    }

    func deleteAlias(keystorePath: String, storeType: KeystoreFormat, password: String, alias: String) throws -> String {
        let passFile = try writeSecurePassFile(password)
        defer { removeTempFiles([passFile]) }

        var args = ["-delete", "-alias", alias, "-keystore", keystorePath, "-storepass:file", passFile.path]
        args += storeTypeArgs(storeType)
        return try runKeytool(args)
    }

    // MARK: - Change Passwords

    /// `keytool -storepasswd` — the new password is never passed via argv (not even via
    /// `:file`, since `-new` has no file modifier); it's fed over stdin instead.
    func changeStorePassword(
        keystorePath: String, storeType: KeystoreFormat, oldPassword: String, newPassword: String
    ) throws -> String {
        let passFile = try writeSecurePassFile(oldPassword)
        defer { removeTempFiles([passFile]) }

        var args = ["-storepasswd", "-keystore", keystorePath, "-storepass:file", passFile.path]
        args += storeTypeArgs(storeType)
        return try runKeytool(args, stdin: "\(newPassword)\n\(newPassword)\n")
    }

    /// `keytool -keypasswd` — same rationale as above for the new key password.
    func changeKeyPassword(
        keystorePath: String, storeType: KeystoreFormat, alias: String,
        storePassword: String, oldKeyPassword: String?, newKeyPassword: String
    ) throws -> String {
        let storePassFile = try writeSecurePassFile(storePassword)
        var tempFiles = [storePassFile]
        defer { removeTempFiles(tempFiles) }

        var args = ["-keypasswd", "-alias", alias, "-keystore", keystorePath, "-storepass:file", storePassFile.path]
        if let oldKeyPassword = oldKeyPassword, !oldKeyPassword.isEmpty {
            let oldKeyPassFile = try writeSecurePassFile(oldKeyPassword)
            tempFiles.append(oldKeyPassFile)
            args += ["-keypass:file", oldKeyPassFile.path]
        }
        args += storeTypeArgs(storeType)
        return try runKeytool(args, stdin: "\(newKeyPassword)\n\(newKeyPassword)\n")
    }
}

enum KeytoolError: LocalizedError {
    case javaNotFound
    case commandFailed(String)

    var errorDescription: String? {
        switch self {
        case .javaNotFound:
            return "keytool was not found. Install a JDK (e.g. `brew install openjdk`) or set JAVA_HOME."
        case .commandFailed(let message):
            return message
        }
    }
}
