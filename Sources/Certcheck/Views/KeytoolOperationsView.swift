import SwiftUI
import UniformTypeIdentifiers

// MARK: - Shared small form controls

private struct LabeledField: View {
    let label: String
    @Binding var text: String
    var placeholder: String = ""
    var width: CGFloat = 130

    var body: some View {
        HStack {
            Text(label).font(.system(size: 11, weight: .medium)).foregroundColor(.secondary)
                .frame(width: width, alignment: .trailing)
            TextField(placeholder, text: $text).textFieldStyle(.roundedBorder)
        }
    }
}

private struct LabeledSecureField: View {
    let label: String
    @Binding var text: String
    var width: CGFloat = 130

    var body: some View {
        HStack {
            Text(label).font(.system(size: 11, weight: .medium)).foregroundColor(.secondary)
                .frame(width: width, alignment: .trailing)
            SecureField("", text: $text).textFieldStyle(.roundedBorder)
        }
    }
}

private struct AliasPickerField: View {
    let label: String
    @Binding var alias: String
    let entries: [KeystoreEntryInfo]
    var width: CGFloat = 130

    var body: some View {
        HStack {
            Text(label).font(.system(size: 11, weight: .medium)).foregroundColor(.secondary)
                .frame(width: width, alignment: .trailing)
            TextField("alias", text: $alias).textFieldStyle(.roundedBorder)
            if !entries.isEmpty {
                Menu {
                    ForEach(entries) { e in Button(e.alias) { alias = e.alias } }
                } label: { Image(systemName: "list.bullet.circle") }
                .menuStyle(.borderlessButton)
                .frame(width: 22)
            }
        }
    }
}

/// A button that requires explicit user confirmation before executing a (potentially
/// destructive or irreversible) keytool operation.
private struct ConfirmButton: View {
    let title: String
    let icon: String
    var destructive: Bool = false
    let confirmMessage: String
    let action: () -> Void
    var disabled: Bool = false

    @State private var showConfirm = false

    var body: some View {
        Button(role: destructive ? .destructive : nil) { showConfirm = true } label: {
            HStack(spacing: 6) {
                Image(systemName: icon).font(.system(size: 11))
                Text(title).font(.system(size: 12, weight: .medium))
            }
            .padding(.horizontal, 16).padding(.vertical, 8)
        }
        .buttonStyle(.borderedProminent)
        .tint(destructive ? .red : .accentColor)
        .disabled(disabled)
        .confirmationDialog(confirmMessage, isPresented: $showConfirm, titleVisibility: .visible) {
            Button(destructive ? "Confirm" : "Proceed", role: destructive ? .destructive : nil) { action() }
            Button("Cancel", role: .cancel) {}
        }
    }
}

private struct RawOutputView: View {
    let title: String
    let output: String
    var filename: String = "output.txt"

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(title).font(.system(size: 12, weight: .semibold))
                Spacer()
                CopyButton(text: output)
                DownloadButton(filename: filename, content: output)
            }
            ScrollView {
                Text(output)
                    .font(.system(size: 10, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8)
            }
            .frame(maxHeight: 220)
            .background(Color(nsColor: .textBackgroundColor))
            .cornerRadius(6)
            .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.2), lineWidth: 1))
        }
    }
}

/// Shows the keytool CLI command equivalent to the operation about to run, so users can
/// learn/copy it. Passwords are always masked with a placeholder, never the real value.
private struct EquivalentCommandView: View {
    let command: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text("Equivalent Command").font(.system(size: 10, weight: .semibold)).foregroundColor(.secondary)
                Spacer()
                CopyButton(text: command)
            }
            Text(command)
                .font(.system(size: 10, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(8)
        .background(Color(nsColor: .textBackgroundColor))
        .cornerRadius(6)
        .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.15), lineWidth: 1))
    }
}

private func orderedDNToKeytoolString(_ dn: OrderedDN) -> String {
    dn.map { "\($0.key)=\($0.value)" }.joined(separator: ", ")
}

private func requireOpenKeystore(_ keystore: ManagedKeystore?) -> String? {
    keystore == nil ? "Select a target keystore above (or open a new one) before running this operation." : nil
}

// MARK: - Operations Root

struct KeytoolOperationsView: View {
    @ObservedObject private var registry = KeytoolRegistry.shared
    @State private var operation: KeytoolOperation = .listEntries
    @State private var showQuickOpen = false

    private var keystoreID: UUID? { registry.selectedKeystoreID }
    private var selectedKeystore: ManagedKeystore? { registry.selected }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            targetBar
            if showQuickOpen {
                KeystoreQuickOpenForm { _ in showQuickOpen = false }
                    .padding(.horizontal).padding(.bottom, 10)
            }
            Divider()
            HStack(alignment: .top, spacing: 0) {
                operationList
                Divider()
                ScrollView {
                    VStack(alignment: .leading, spacing: 14) {
                        Text(operation.rawValue).font(.system(size: 15, weight: .semibold))
                        Text(operation.keytoolCommand)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(.secondary)

                        if let warning = requireOpenKeystore(selectedKeystore) {
                            Text(warning).font(.system(size: 11)).foregroundColor(.orange)
                        }

                        operationForm
                    }
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .frame(minHeight: 480)
    }

    private var targetBar: some View {
        HStack(spacing: 10) {
            Image(systemName: "key.card.fill")
                .foregroundColor(Color(hue: 0.11, saturation: 0.88, brightness: 0.82))
            Text("Target Keystore:").font(.system(size: 12, weight: .medium))

            Picker("", selection: $registry.selectedKeystoreID) {
                Text("None selected").tag(UUID?.none)
                ForEach(registry.keystores) { ks in Text(ks.displayName).tag(Optional(ks.id)) }
            }
            .labelsHidden()
            .frame(minWidth: 220, maxWidth: 260)

            if let ks = selectedKeystore {
                Text(ks.resolvedStoreType.rawValue)
                    .font(.system(size: 10, weight: .medium))
                    .foregroundColor(.secondary)
                    .padding(.horizontal, 8).padding(.vertical, 3)
                    .background(Capsule().fill(Color.secondary.opacity(0.12)))
            }

            Spacer()

            Button(showQuickOpen ? "Cancel" : "Open New Keystore…") { showQuickOpen.toggle() }
                .buttonStyle(.bordered).controlSize(.small)
        }
        .padding(.horizontal).padding(.vertical, 10)
        .background(Color(nsColor: .controlBackgroundColor))
    }

    private var operationList: some View {
        VStack(alignment: .leading, spacing: 2) {
            ForEach(KeytoolOperation.allCases) { op in
                Button { operation = op } label: {
                    HStack(spacing: 8) {
                        Image(systemName: op.icon).font(.system(size: 11)).frame(width: 16)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(op.rawValue).font(.system(size: 11.5, weight: .medium))
                            Text(op.keytoolCommand).font(.system(size: 9, design: .monospaced)).foregroundColor(.secondary)
                        }
                        Spacer()
                    }
                    .padding(.vertical, 6).padding(.horizontal, 8)
                    .background(RoundedRectangle(cornerRadius: 6)
                        .fill(operation == op ? Color.accentColor.opacity(0.15) : Color.clear))
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
        .padding(8)
        .frame(width: 240)
    }

    @ViewBuilder
    private var operationForm: some View {
        switch operation {
        case .listEntries:      ListEntriesOperationView(registry: registry, keystoreID: keystoreID)
        case .inspectCert:      InspectCertOperationView(registry: registry, keystoreID: keystoreID)
        case .exportCert:       ExportCertOperationView(registry: registry, keystoreID: keystoreID)
        case .importTrusted:    ImportTrustedOperationView(registry: registry, keystoreID: keystoreID)
        case .importReply:      ImportReplyOperationView(registry: registry, keystoreID: keystoreID)
        case .genCSR:           GenCSROperationView(registry: registry, keystoreID: keystoreID)
        case .genKeyPair:       GenKeyPairOperationView(registry: registry, keystoreID: keystoreID)
        case .convertKeystore:  ConvertKeystoreOperationView(registry: registry, keystoreID: keystoreID)
        case .renameAlias:      RenameAliasOperationView(registry: registry, keystoreID: keystoreID)
        case .deleteAlias:      DeleteAliasOperationView(registry: registry, keystoreID: keystoreID)
        case .changeStorePass:  ChangeStorePassOperationView(registry: registry, keystoreID: keystoreID)
        case .changeKeyPass:    ChangeKeyPassOperationView(registry: registry, keystoreID: keystoreID)
        }
    }
}

// MARK: - 1. List Entries

private struct ListEntriesOperationView: View {
    @ObservedObject var registry: KeytoolRegistry
    let keystoreID: UUID?
    @State private var isRunning = false
    @State private var error: String?

    private var ks: ManagedKeystore? { registry.keystores.first(where: { $0.id == keystoreID }) }

    private var equivalentCommand: String {
        "keytool -list -v -keystore \"\(ks?.path ?? "<keystore path>")\" -storetype \(ks?.resolvedStoreType.rawValue ?? "<type>") -storepass <password>"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Runs `keytool -list -v` against the selected keystore and shows the raw output.")
                .font(.system(size: 11)).foregroundColor(.secondary)

            EquivalentCommandView(command: equivalentCommand)

            ActionButton(title: isRunning ? "Running…" : "Run", icon: "play.fill", action: run,
                         disabled: ks == nil || isRunning)

            if let error = error { ErrorText(error: error) }
            if let output = ks?.rawListOutput, !output.isEmpty {
                RawOutputView(title: "keytool -list -v output", output: output, filename: "keystore-list.txt")
            }
        }
    }

    private func run() {
        guard let id = keystoreID else { return }
        error = nil; isRunning = true
        registry.load(id: id) { isRunning = false }
    }
}

// MARK: - 2. Inspect Certificate

private struct InspectCertOperationView: View {
    @ObservedObject var registry: KeytoolRegistry
    let keystoreID: UUID?
    @State private var alias = ""
    @State private var isRunning = false
    @State private var error: String?
    @State private var detail: KeystoreEntryInfo?

    private var ks: ManagedKeystore? { registry.keystores.first(where: { $0.id == keystoreID }) }

    private var equivalentCommand: String {
        "keytool -exportcert -alias \(alias.isEmpty ? "<alias>" : alias) -keystore \"\(ks?.path ?? "<keystore path>")\" -storetype \(ks?.resolvedStoreType.rawValue ?? "<type>") -storepass <password> -rfc"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            AliasPickerField(label: "Alias", alias: $alias, entries: ks?.entries ?? [])
            EquivalentCommandView(command: equivalentCommand)
            ActionButton(title: isRunning ? "Inspecting…" : "Inspect", icon: "doc.text.magnifyingglass",
                         action: run, disabled: alias.isEmpty || ks == nil || isRunning)
            if let error = error { ErrorText(error: error) }
        }
        .sheet(item: $detail) { entry in KeystoreCertDetailSheet(entry: entry) }
    }

    private func run() {
        guard let ks = ks else { return }
        error = nil; isRunning = true
        let path = ks.path, type = ks.resolvedStoreType, pass = ks.password, aliasName = alias
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let leaf = try KeytoolHelper.shared.exportCertificate(keystorePath: path, storeType: type, alias: aliasName, password: pass)
                let info = try CertService.shared.parseCertificate(pem: leaf)
                let chain = (try? KeytoolHelper.shared.exportChain(keystorePath: path, storeType: type, alias: aliasName, password: pass)) ?? [leaf]
                DispatchQueue.main.async {
                    detail = KeystoreEntryInfo(alias: aliasName, entryType: "—", creationDate: "", chainLength: chain.count,
                                                certInfo: info, chainPEMs: chain, parseError: nil)
                    isRunning = false
                }
            } catch {
                DispatchQueue.main.async { self.error = error.localizedDescription; isRunning = false }
            }
        }
    }
}

// MARK: - 3. Export Certificate

private struct ExportCertOperationView: View {
    @ObservedObject var registry: KeytoolRegistry
    let keystoreID: UUID?
    @State private var alias = ""
    @State private var isRunning = false
    @State private var error: String?
    @State private var pem = ""

    private var ks: ManagedKeystore? { registry.keystores.first(where: { $0.id == keystoreID }) }

    private var equivalentCommand: String {
        "keytool -exportcert -alias \(alias.isEmpty ? "<alias>" : alias) -keystore \"\(ks?.path ?? "<keystore path>")\" -storetype \(ks?.resolvedStoreType.rawValue ?? "<type>") -storepass <password> -rfc -file \(alias.isEmpty ? "<alias>" : alias).pem"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            AliasPickerField(label: "Alias", alias: $alias, entries: ks?.entries ?? [])
            EquivalentCommandView(command: equivalentCommand)
            ActionButton(title: isRunning ? "Exporting…" : "Export as PEM", icon: "square.and.arrow.up",
                         action: run, disabled: alias.isEmpty || ks == nil || isRunning)
            if let error = error { ErrorText(error: error) }
            if !pem.isEmpty { RawOutputView(title: "Certificate (PEM)", output: pem, filename: "\(alias).pem") }
        }
    }

    private func run() {
        guard let ks = ks else { return }
        error = nil; isRunning = true
        let path = ks.path, type = ks.resolvedStoreType, pass = ks.password, aliasName = alias
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let result = try KeytoolHelper.shared.exportCertificate(keystorePath: path, storeType: type, alias: aliasName, password: pass)
                DispatchQueue.main.async { pem = result; isRunning = false }
            } catch {
                DispatchQueue.main.async { self.error = error.localizedDescription; isRunning = false }
            }
        }
    }
}

// MARK: - 4. Import Trusted Certificate

private struct ImportTrustedOperationView: View {
    @ObservedObject var registry: KeytoolRegistry
    let keystoreID: UUID?
    @State private var newAlias = ""
    @State private var certPEM = ""
    @State private var isRunning = false
    @State private var error: String?
    @State private var output: String?

    private var ks: ManagedKeystore? { registry.keystores.first(where: { $0.id == keystoreID }) }

    private var equivalentCommand: String {
        "keytool -importcert -alias \(newAlias.isEmpty ? "<new-alias>" : newAlias) -file <certificate-file> -keystore \"\(ks?.path ?? "<keystore path>")\" -storetype \(ks?.resolvedStoreType.rawValue ?? "<type>") -storepass <password> -noprompt"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            LabeledField(label: "New Alias", text: $newAlias, placeholder: "trusted-ca")

            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text("Certificate (PEM)").font(.system(size: 11, weight: .medium)).foregroundColor(.secondary)
                    Spacer()
                    Button("Load File…") { loadCertFile() }.buttonStyle(.bordered).controlSize(.small)
                }
                TextEditor(text: $certPEM)
                    .font(.system(size: 10, design: .monospaced))
                    .frame(height: 120)
                    .padding(6)
                    .background(Color(nsColor: .textBackgroundColor))
                    .cornerRadius(6)
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.2), lineWidth: 1))
            }

            EquivalentCommandView(command: equivalentCommand)

            ConfirmButton(
                title: isRunning ? "Importing…" : "Import Trusted Certificate",
                icon: "square.and.arrow.down.on.square",
                confirmMessage: "Add \"\(newAlias)\" as a trusted certificate entry in this keystore?",
                action: run,
                disabled: newAlias.isEmpty || certPEM.isEmpty || ks == nil || isRunning
            )

            if let error = error { ErrorText(error: error) }
            if let output = output { RawOutputView(title: "Result", output: output) }
        }
    }

    private func loadCertFile() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.message = "Select a PEM or DER certificate file"
        if panel.runModal() == .OK, let url = panel.url, let contents = try? String(contentsOf: url, encoding: .utf8) {
            certPEM = contents
        }
    }

    private func run() {
        guard let ks = ks else { return }
        error = nil; isRunning = true
        let path = ks.path, type = ks.resolvedStoreType, pass = ks.password
        let aliasName = newAlias, pem = certPEM
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let result = try KeytoolHelper.shared.importTrustedCertificate(
                    keystorePath: path, storeType: type, alias: aliasName, password: pass, certPEM: pem)
                DispatchQueue.main.async {
                    output = result.isEmpty ? "Certificate was added to keystore." : result
                    isRunning = false
                    registry.load(id: ks.id)
                }
            } catch {
                DispatchQueue.main.async { self.error = error.localizedDescription; isRunning = false }
            }
        }
    }
}

// MARK: - 5. Import Certificate Reply

private struct ImportReplyOperationView: View {
    @ObservedObject var registry: KeytoolRegistry
    let keystoreID: UUID?
    @State private var alias = ""
    @State private var keyPassword = ""
    @State private var replyPEM = ""
    @State private var isRunning = false
    @State private var error: String?
    @State private var output: String?

    private var ks: ManagedKeystore? { registry.keystores.first(where: { $0.id == keystoreID }) }

    private var equivalentCommand: String {
        var cmd = "keytool -importcert -alias \(alias.isEmpty ? "<alias>" : alias) -file <reply-file> -keystore \"\(ks?.path ?? "<keystore path>")\" -storetype \(ks?.resolvedStoreType.rawValue ?? "<type>") -storepass <password>"
        if !keyPassword.isEmpty { cmd += " -keypass <key-password>" }
        cmd += " -trustcacerts"
        return cmd
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            AliasPickerField(label: "Existing Alias", alias: $alias, entries: ks?.entries ?? [])
            LabeledSecureField(label: "Key Password", text: $keyPassword)
            Text("Leave empty if the key password matches the store password.")
                .font(.system(size: 10)).foregroundColor(.secondary)

            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text("Signed Certificate Reply (PEM)").font(.system(size: 11, weight: .medium)).foregroundColor(.secondary)
                    Spacer()
                    Button("Load File…") { loadReplyFile() }.buttonStyle(.bordered).controlSize(.small)
                }
                TextEditor(text: $replyPEM)
                    .font(.system(size: 10, design: .monospaced))
                    .frame(height: 120)
                    .padding(6)
                    .background(Color(nsColor: .textBackgroundColor))
                    .cornerRadius(6)
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.2), lineWidth: 1))
            }

            EquivalentCommandView(command: equivalentCommand)

            ConfirmButton(
                title: isRunning ? "Importing…" : "Import Certificate Reply",
                icon: "arrow.triangle.2.circlepath",
                confirmMessage: "Replace the certificate chain for alias \"\(alias)\" with this signed reply?",
                action: run,
                disabled: alias.isEmpty || replyPEM.isEmpty || ks == nil || isRunning
            )

            if let error = error { ErrorText(error: error) }
            if let output = output { RawOutputView(title: "Result", output: output) }
        }
    }

    private func loadReplyFile() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.message = "Select the CA-signed certificate reply (PEM)"
        if panel.runModal() == .OK, let url = panel.url, let contents = try? String(contentsOf: url, encoding: .utf8) {
            replyPEM = contents
        }
    }

    private func run() {
        guard let ks = ks else { return }
        error = nil; isRunning = true
        let path = ks.path, type = ks.resolvedStoreType, pass = ks.password
        let aliasName = alias, kp = keyPassword.isEmpty ? nil : keyPassword, reply = replyPEM
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let result = try KeytoolHelper.shared.importCertificateReply(
                    keystorePath: path, storeType: type, alias: aliasName, password: pass, keyPassword: kp, replyPEM: reply)
                DispatchQueue.main.async {
                    output = result.isEmpty ? "Certificate reply imported." : result
                    isRunning = false
                    registry.load(id: ks.id)
                }
            } catch {
                DispatchQueue.main.async { self.error = error.localizedDescription; isRunning = false }
            }
        }
    }
}

// MARK: - 6. Generate CSR

private struct GenCSROperationView: View {
    @ObservedObject var registry: KeytoolRegistry
    let keystoreID: UUID?
    @State private var alias = ""
    @State private var keyPassword = ""
    @State private var dname = ""
    @State private var isRunning = false
    @State private var error: String?
    @State private var csr = ""

    private var ks: ManagedKeystore? { registry.keystores.first(where: { $0.id == keystoreID }) }

    private var equivalentCommand: String {
        var cmd = "keytool -certreq -alias \(alias.isEmpty ? "<alias>" : alias) -keystore \"\(ks?.path ?? "<keystore path>")\" -storetype \(ks?.resolvedStoreType.rawValue ?? "<type>") -storepass <password>"
        if !keyPassword.isEmpty { cmd += " -keypass <key-password>" }
        if !dname.isEmpty { cmd += " -dname \"\(dname)\"" }
        return cmd
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            AliasPickerField(label: "Private Key Alias", alias: $alias, entries: (ks?.entries ?? []).filter { $0.entryType == "PrivateKeyEntry" })
            LabeledSecureField(label: "Key Password", text: $keyPassword)
            Text("Leave empty if the key password matches the store password.")
                .font(.system(size: 10)).foregroundColor(.secondary)
            LabeledField(label: "Distinguished Name", text: $dname, placeholder: "CN=example.com, O=Example, C=US")
            Text("Optional — omit to use the alias's existing certificate subject.")
                .font(.system(size: 10)).foregroundColor(.secondary)

            EquivalentCommandView(command: equivalentCommand)

            ActionButton(title: isRunning ? "Generating…" : "Generate CSR", icon: "pencil.and.list.clipboard",
                         action: run, disabled: alias.isEmpty || ks == nil || isRunning)

            if let error = error { ErrorText(error: error) }
            if !csr.isEmpty { RawOutputView(title: "Certificate Signing Request", output: csr, filename: "\(alias).csr") }
        }
    }

    private func run() {
        guard let ks = ks else { return }
        error = nil; isRunning = true
        let path = ks.path, type = ks.resolvedStoreType, pass = ks.password
        let aliasName = alias, kp = keyPassword.isEmpty ? nil : keyPassword, dn = dname
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let result = try KeytoolHelper.shared.generateCSR(
                    keystorePath: path, storeType: type, alias: aliasName, password: pass,
                    keyPassword: kp, dname: dn.isEmpty ? nil : dn, sigAlg: nil)
                DispatchQueue.main.async { csr = result; isRunning = false }
            } catch {
                DispatchQueue.main.async { self.error = error.localizedDescription; isRunning = false }
            }
        }
    }
}

// MARK: - 7. Generate Key Pair

private struct GenKeyPairOperationView: View {
    @ObservedObject var registry: KeytoolRegistry
    let keystoreID: UUID?
    @State private var alias = ""
    @State private var keyPassword = ""
    @State private var subject = CertSubject()
    @State private var keyAlg: KeyAlgoKind = .rsa
    @State private var rsaBits: RSABits = .b2048
    @State private var curve: ECCurve = .p256
    @State private var validityDays = 365
    @State private var isRunning = false
    @State private var error: String?
    @State private var output: String?

    private var ks: ManagedKeystore? { registry.keystores.first(where: { $0.id == keystoreID }) }

    private var equivalentCommand: String {
        let dn = orderedDNToKeytoolString(subject.toOrderedDN())
        var cmd = "keytool -genkeypair -alias \(alias.isEmpty ? "<alias>" : alias) -keyalg \(keyAlg == .ec ? "EC" : "RSA")"
        if keyAlg == .ec {
            let group = curve == .p384 ? "secp384r1" : (curve == .p521 ? "secp521r1" : "secp256r1")
            cmd += " -groupname \(group)"
        } else {
            cmd += " -keysize \(rsaBits.rawValue)"
        }
        cmd += " -validity \(validityDays) -dname \"\(dn.isEmpty ? "<dn>" : dn)\" -keystore \"\(ks?.path ?? "<keystore path>")\" -storetype \(ks?.resolvedStoreType.rawValue ?? "<type>") -storepass <password>"
        if !keyPassword.isEmpty { cmd += " -keypass <key-password>" }
        if !subject.san.isEmpty {
            let sanStr = subject.san.map { entry -> String in
                entry.range(of: #"^\d{1,3}(\.\d{1,3}){3}$"#, options: .regularExpression) != nil ? "ip:\(entry)" : "dns:\(entry)"
            }.joined(separator: ",")
            cmd += " -ext SAN=\(sanStr)"
        }
        return cmd
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            LabeledField(label: "New Alias", text: $alias, placeholder: "server")
            LabeledSecureField(label: "Key Password", text: $keyPassword)
            Text("Leave empty to reuse the keystore password.")
                .font(.system(size: 10)).foregroundColor(.secondary)

            GroupBox {
                VStack(spacing: 8) {
                    LabeledField(label: "Common Name (CN) *", text: $subject.cn, placeholder: "example.com")
                    LabeledField(label: "Organization (O)", text: $subject.org, placeholder: "My Company")
                    LabeledField(label: "Org Unit (OU)", text: $subject.ou, placeholder: "Engineering")
                    LabeledField(label: "Locality (L)", text: $subject.locality, placeholder: "City")
                    LabeledField(label: "State (ST)", text: $subject.state, placeholder: "State")
                    LabeledField(label: "Country (C)", text: $subject.country, placeholder: "US")
                    HStack {
                        Text("SANs (comma-sep)").font(.system(size: 11, weight: .medium)).foregroundColor(.secondary).frame(width: 130, alignment: .trailing)
                        TextField("www.example.com, api.example.com", text: Binding(
                            get: { subject.san.joined(separator: ", ") },
                            set: { subject.san = $0.split(separator: ",").map { String($0.trimmingCharacters(in: .whitespaces)) } }
                        )).textFieldStyle(.roundedBorder)
                    }
                }
            } label: { Text("Subject").font(.system(size: 12, weight: .semibold)) }

            Picker("Algorithm", selection: $keyAlg) {
                Text("RSA").tag(KeyAlgoKind.rsa)
                Text("EC").tag(KeyAlgoKind.ec)
            }.pickerStyle(.segmented)

            if keyAlg == .rsa {
                Picker("RSA Key Size", selection: $rsaBits) {
                    ForEach(RSABits.allCases, id: \.self) { b in Text(b.rawValue + " bits").tag(b) }
                }.pickerStyle(.segmented)
            } else {
                Picker("EC Curve", selection: $curve) {
                    Text("P-256").tag(ECCurve.p256)
                    Text("P-384").tag(ECCurve.p384)
                    Text("P-521").tag(ECCurve.p521)
                }.pickerStyle(.segmented)
            }

            Stepper("Validity: \(validityDays) days", value: $validityDays, in: 1...3650)

            EquivalentCommandView(command: equivalentCommand)

            ActionButton(
                title: isRunning ? "Generating…" : "Generate Key Pair",
                icon: "key.fill", action: run,
                disabled: alias.isEmpty || subject.cn.isEmpty || ks == nil || isRunning
            )

            if let error = error { ErrorText(error: error) }
            if let output = output { RawOutputView(title: "Result", output: output) }
        }
    }

    private func run() {
        guard let ks = ks else { return }
        error = nil; isRunning = true
        let path = ks.path, type = ks.resolvedStoreType, pass = ks.password
        let aliasName = alias, kp = keyPassword.isEmpty ? nil : keyPassword
        let dn = orderedDNToKeytoolString(subject.toOrderedDN())
        let alg = keyAlg == .ec ? "EC" : "RSA"
        let size = keyAlg == .ec ? Int(curve.rawValue.replacingOccurrences(of: "P-", with: "")) ?? 256 : Int(rsaBits.rawValue) ?? 2048
        let days = validityDays, sans = subject.san

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let result = try KeytoolHelper.shared.generateKeyPair(
                    keystorePath: path, storeType: type, alias: aliasName, password: pass, keyPassword: kp,
                    keyAlg: alg, keySizeOrCurve: size, validityDays: days, dname: dn, sanEntries: sans)
                DispatchQueue.main.async {
                    output = result.isEmpty ? "Key pair generated under alias \"\(aliasName)\"." : result
                    isRunning = false
                    registry.load(id: ks.id)
                }
            } catch {
                DispatchQueue.main.async { self.error = error.localizedDescription; isRunning = false }
            }
        }
    }
}

// MARK: - 8. Convert Keystore (JKS <-> PKCS12)

private struct ConvertKeystoreOperationView: View {
    @ObservedObject var registry: KeytoolRegistry
    let keystoreID: UUID?
    @State private var destPath = ""
    @State private var destType: KeystoreFormat = .pkcs12
    @State private var destPassword = ""
    @State private var isRunning = false
    @State private var error: String?
    @State private var output: String?

    private var ks: ManagedKeystore? { registry.keystores.first(where: { $0.id == keystoreID }) }

    private var equivalentCommand: String {
        "keytool -importkeystore -srckeystore \"\(ks?.path ?? "<source path>")\" -srcstoretype \(ks?.resolvedStoreType.rawValue ?? "<type>") -srcstorepass <password> -destkeystore \"\(destPath.isEmpty ? "<destination path>" : destPath)\" -deststoretype \(destType.rawValue) -deststorepass <password> -noprompt"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Converts the selected target keystore to a new file in the target format.")
                .font(.system(size: 11)).foregroundColor(.secondary)

            HStack {
                Text("Destination File").font(.system(size: 11, weight: .medium)).foregroundColor(.secondary).frame(width: 130, alignment: .trailing)
                Text(destPath.isEmpty ? "Not selected" : URL(fileURLWithPath: destPath).lastPathComponent)
                    .font(.system(size: 11, design: .monospaced)).foregroundColor(destPath.isEmpty ? .secondary : .primary)
                Spacer()
                Button("Choose…") { chooseDest() }.buttonStyle(.bordered).controlSize(.small)
            }

            Picker("Destination Type", selection: $destType) {
                Text("JKS").tag(KeystoreFormat.jks)
                Text("PKCS12").tag(KeystoreFormat.pkcs12)
                Text("JCEKS").tag(KeystoreFormat.jceks)
            }.pickerStyle(.segmented)

            LabeledSecureField(label: "Destination Password", text: $destPassword)

            EquivalentCommandView(command: equivalentCommand)

            ConfirmButton(
                title: isRunning ? "Converting…" : "Convert Keystore",
                icon: "arrow.2.squarepath",
                confirmMessage: "Create a new \(destType.rawValue) keystore at the chosen path?",
                action: run,
                disabled: destPath.isEmpty || destPassword.isEmpty || ks == nil || isRunning
            )

            if let error = error { ErrorText(error: error) }
            if let output = output {
                Text(output).font(.system(size: 11)).foregroundColor(.green)
                Button("Open Converted Keystore") {
                    let newID = registry.openFile(path: destPath, storeType: destType, password: destPassword)
                    registry.selectedKeystoreID = newID
                }
                .buttonStyle(.bordered).controlSize(.small)
            }
        }
    }

    private func chooseDest() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = destType == .pkcs12 ? "keystore.p12" : "keystore.jks"
        if panel.runModal() == .OK, let url = panel.url { destPath = url.path }
    }

    private func run() {
        guard let ks = ks else { return }
        error = nil; isRunning = true
        let srcPath = ks.path, srcType = ks.resolvedStoreType, srcPass = ks.password
        let dPath = destPath, dType = destType, dPass = destPassword
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                _ = try KeytoolHelper.shared.convertKeystore(
                    srcPath: srcPath, srcType: srcType, srcPassword: srcPass,
                    destPath: dPath, destType: dType, destPassword: dPass)
                DispatchQueue.main.async {
                    output = "Converted keystore written to \(dPath)"
                    isRunning = false
                }
            } catch {
                DispatchQueue.main.async { self.error = error.localizedDescription; isRunning = false }
            }
        }
    }
}

// MARK: - 9. Rename Alias

private struct RenameAliasOperationView: View {
    @ObservedObject var registry: KeytoolRegistry
    let keystoreID: UUID?
    @State private var oldAlias = ""
    @State private var newAlias = ""
    @State private var keyPassword = ""
    @State private var isRunning = false
    @State private var error: String?
    @State private var output: String?

    private var ks: ManagedKeystore? { registry.keystores.first(where: { $0.id == keystoreID }) }

    private var equivalentCommand: String {
        var cmd = "keytool -changealias -alias \(oldAlias.isEmpty ? "<old-alias>" : oldAlias) -destalias \(newAlias.isEmpty ? "<new-alias>" : newAlias) -keystore \"\(ks?.path ?? "<keystore path>")\" -storetype \(ks?.resolvedStoreType.rawValue ?? "<type>") -storepass <password>"
        if !keyPassword.isEmpty { cmd += " -keypass <key-password>" }
        return cmd
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            AliasPickerField(label: "Current Alias", alias: $oldAlias, entries: ks?.entries ?? [])
            LabeledField(label: "New Alias", text: $newAlias, placeholder: "new-alias")
            LabeledSecureField(label: "Key Password", text: $keyPassword)
            Text("Leave empty if the key password matches the store password.")
                .font(.system(size: 10)).foregroundColor(.secondary)

            EquivalentCommandView(command: equivalentCommand)

            ConfirmButton(
                title: isRunning ? "Renaming…" : "Rename Alias",
                icon: "pencil",
                confirmMessage: "Rename alias \"\(oldAlias)\" to \"\(newAlias)\"?",
                action: run,
                disabled: oldAlias.isEmpty || newAlias.isEmpty || ks == nil || isRunning
            )

            if let error = error { ErrorText(error: error) }
            if let output = output { Text(output).font(.system(size: 11)).foregroundColor(.green) }
        }
    }

    private func run() {
        guard let ks = ks else { return }
        error = nil; isRunning = true
        let path = ks.path, type = ks.resolvedStoreType, pass = ks.password
        let old = oldAlias, new = newAlias, kp = keyPassword.isEmpty ? nil : keyPassword
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                _ = try KeytoolHelper.shared.renameAlias(
                    keystorePath: path, storeType: type, password: pass, oldAlias: old, newAlias: new, keyPassword: kp)
                DispatchQueue.main.async {
                    output = "Alias renamed from \"\(old)\" to \"\(new)\"."
                    isRunning = false
                    registry.load(id: ks.id)
                }
            } catch {
                DispatchQueue.main.async { self.error = error.localizedDescription; isRunning = false }
            }
        }
    }
}

// MARK: - 10. Delete Alias

private struct DeleteAliasOperationView: View {
    @ObservedObject var registry: KeytoolRegistry
    let keystoreID: UUID?
    @State private var alias = ""
    @State private var isRunning = false
    @State private var error: String?
    @State private var output: String?

    private var ks: ManagedKeystore? { registry.keystores.first(where: { $0.id == keystoreID }) }

    private var equivalentCommand: String {
        "keytool -delete -alias \(alias.isEmpty ? "<alias>" : alias) -keystore \"\(ks?.path ?? "<keystore path>")\" -storetype \(ks?.resolvedStoreType.rawValue ?? "<type>") -storepass <password>"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            AliasPickerField(label: "Alias", alias: $alias, entries: ks?.entries ?? [])

            EquivalentCommandView(command: equivalentCommand)

            ConfirmButton(
                title: isRunning ? "Deleting…" : "Delete Alias",
                icon: "trash",
                destructive: true,
                confirmMessage: "Permanently delete alias \"\(alias)\" from this keystore? This cannot be undone.",
                action: run,
                disabled: alias.isEmpty || ks == nil || isRunning
            )

            if let error = error { ErrorText(error: error) }
            if let output = output { Text(output).font(.system(size: 11)).foregroundColor(.green) }
        }
    }

    private func run() {
        guard let ks = ks else { return }
        error = nil; isRunning = true
        let path = ks.path, type = ks.resolvedStoreType, pass = ks.password, aliasName = alias
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                _ = try KeytoolHelper.shared.deleteAlias(keystorePath: path, storeType: type, password: pass, alias: aliasName)
                DispatchQueue.main.async {
                    output = "Alias \"\(aliasName)\" deleted."
                    isRunning = false
                    registry.load(id: ks.id)
                }
            } catch {
                DispatchQueue.main.async { self.error = error.localizedDescription; isRunning = false }
            }
        }
    }
}

// MARK: - 11. Change Store Password

private struct ChangeStorePassOperationView: View {
    @ObservedObject var registry: KeytoolRegistry
    let keystoreID: UUID?
    @State private var newPassword = ""
    @State private var confirmPassword = ""
    @State private var isRunning = false
    @State private var error: String?
    @State private var output: String?

    private var ks: ManagedKeystore? { registry.keystores.first(where: { $0.id == keystoreID }) }
    private var mismatch: Bool { !confirmPassword.isEmpty && newPassword != confirmPassword }

    private var equivalentCommand: String {
        "keytool -storepasswd -keystore \"\(ks?.path ?? "<keystore path>")\" -storetype \(ks?.resolvedStoreType.rawValue ?? "<type>") -storepass <password> -new <new-password>"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Uses the password of the selected target keystore as the old store password.")
                .font(.system(size: 11)).foregroundColor(.secondary)
            LabeledSecureField(label: "New Password", text: $newPassword)
            LabeledSecureField(label: "Confirm Password", text: $confirmPassword)
            if mismatch { Text("Passwords do not match").font(.system(size: 10)).foregroundColor(.red) }

            EquivalentCommandView(command: equivalentCommand)

            ConfirmButton(
                title: isRunning ? "Changing…" : "Change Store Password",
                icon: "lock.rotation",
                confirmMessage: "Change the keystore password? Make sure you remember the new password — there is no recovery.",
                action: run,
                disabled: newPassword.isEmpty || mismatch || ks == nil || isRunning
            )

            if let error = error { ErrorText(error: error) }
            if let output = output { Text(output).font(.system(size: 11)).foregroundColor(.green) }
        }
    }

    private func run() {
        guard let ks = ks else { return }
        error = nil; isRunning = true
        let path = ks.path, type = ks.resolvedStoreType, oldPass = ks.password, newPass = newPassword
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                _ = try KeytoolHelper.shared.changeStorePassword(
                    keystorePath: path, storeType: type, oldPassword: oldPass, newPassword: newPass)
                DispatchQueue.main.async {
                    registry.updatePassword(id: ks.id, newPassword: newPass)
                    output = "Store password changed successfully."
                    isRunning = false
                }
            } catch {
                DispatchQueue.main.async { self.error = error.localizedDescription; isRunning = false }
            }
        }
    }
}

// MARK: - 12. Change Key Password

private struct ChangeKeyPassOperationView: View {
    @ObservedObject var registry: KeytoolRegistry
    let keystoreID: UUID?
    @State private var alias = ""
    @State private var oldKeyPassword = ""
    @State private var newPassword = ""
    @State private var confirmPassword = ""
    @State private var isRunning = false
    @State private var error: String?
    @State private var output: String?

    private var ks: ManagedKeystore? { registry.keystores.first(where: { $0.id == keystoreID }) }
    private var mismatch: Bool { !confirmPassword.isEmpty && newPassword != confirmPassword }

    private var equivalentCommand: String {
        var cmd = "keytool -keypasswd -alias \(alias.isEmpty ? "<alias>" : alias) -keystore \"\(ks?.path ?? "<keystore path>")\" -storetype \(ks?.resolvedStoreType.rawValue ?? "<type>") -storepass <password>"
        if !oldKeyPassword.isEmpty { cmd += " -keypass <old-key-password>" }
        cmd += " -new <new-key-password>"
        return cmd
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            AliasPickerField(label: "Alias", alias: $alias, entries: (ks?.entries ?? []).filter { $0.entryType == "PrivateKeyEntry" })
            LabeledSecureField(label: "Old Key Password", text: $oldKeyPassword)
            Text("Leave empty if it currently matches the store password.")
                .font(.system(size: 10)).foregroundColor(.secondary)
            LabeledSecureField(label: "New Key Password", text: $newPassword)
            LabeledSecureField(label: "Confirm Password", text: $confirmPassword)
            if mismatch { Text("Passwords do not match").font(.system(size: 10)).foregroundColor(.red) }

            EquivalentCommandView(command: equivalentCommand)

            ConfirmButton(
                title: isRunning ? "Changing…" : "Change Key Password",
                icon: "key.horizontal",
                confirmMessage: "Change the private key password for alias \"\(alias)\"?",
                action: run,
                disabled: alias.isEmpty || newPassword.isEmpty || mismatch || ks == nil || isRunning
            )

            if let error = error { ErrorText(error: error) }
            if let output = output { Text(output).font(.system(size: 11)).foregroundColor(.green) }
        }
    }

    private func run() {
        guard let ks = ks else { return }
        error = nil; isRunning = true
        let path = ks.path, type = ks.resolvedStoreType, storePass = ks.password
        let aliasName = alias, oldKP = oldKeyPassword.isEmpty ? nil : oldKeyPassword, newKP = newPassword
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                _ = try KeytoolHelper.shared.changeKeyPassword(
                    keystorePath: path, storeType: type, alias: aliasName,
                    storePassword: storePass, oldKeyPassword: oldKP, newKeyPassword: newKP)
                DispatchQueue.main.async {
                    output = "Key password changed for alias \"\(aliasName)\"."
                    isRunning = false
                }
            } catch {
                DispatchQueue.main.async { self.error = error.localizedDescription; isRunning = false }
            }
        }
    }
}
