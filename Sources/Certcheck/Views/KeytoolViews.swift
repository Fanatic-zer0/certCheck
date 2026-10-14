import SwiftUI
import UniformTypeIdentifiers

// MARK: - Quick Open Form (shared by Open Keystore tab and Operations tab)

struct KeystoreQuickOpenForm: View {
    @State private var path = ""
    @State private var storeType: KeystoreFormat = .auto
    @State private var password = ""
    @State private var isLoading = false
    @State private var error: String?
    @State private var alreadyOpenNotice: String?
    var onOpened: ((UUID) -> Void)?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                Button("Choose File…") { chooseFile() }.buttonStyle(.bordered).controlSize(.small)
                Text(path.isEmpty ? "No file selected" : URL(fileURLWithPath: path).lastPathComponent)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(path.isEmpty ? .secondary : .primary)
                    .lineLimit(1)
            }
            HStack(spacing: 10) {
                Picker("Type", selection: $storeType) {
                    ForEach(KeystoreFormat.allCases) { f in Text(f.rawValue).tag(f) }
                }.frame(width: 170)
                SecureField("Keystore password (required)", text: $password)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 220)
                ActionButton(
                    title: isLoading ? "Opening…" : "Open",
                    icon: "lock.open", action: open,
                    disabled: path.isEmpty || password.isEmpty || isLoading
                )
            }
            if path.isEmpty {
                Text("Choose a .jks / .p12 / .pfx file, then enter its password.")
                    .font(.system(size: 10)).foregroundColor(.secondary)
            } else if password.isEmpty {
                Text("Enter the keystore password to continue.")
                    .font(.system(size: 10)).foregroundColor(.orange)
            }
            if let notice = alreadyOpenNotice {
                Text(notice).font(.system(size: 10)).foregroundColor(.blue)
            }
            if let error = error { ErrorText(error: error) }
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color(nsColor: .controlBackgroundColor)))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.secondary.opacity(0.2), lineWidth: 1))
    }

    private func chooseFile() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.message = "Select a Java keystore (.jks, .p12, or .pfx)"
        panel.allowedContentTypes = ["jks", "p12", "pfx", "jceks"].compactMap { UTType(filenameExtension: $0) }
        guard panel.runModal() == .OK, let url = panel.url else { return }
        path = url.path
        error = nil
        // If this file is already open, don't silently clobber its working password with a blank field.
        if let existing = KeytoolRegistry.shared.keystores.first(where: { $0.path == path }) {
            storeType = existing.storeType
            password = existing.password
            alreadyOpenNotice = "This file is already open — reopening will refresh it with the password below."
        } else {
            password = ""
            alreadyOpenNotice = nil
        }
    }

    private func open() {
        error = nil
        isLoading = true
        let chosenPath = path, type = storeType, pass = password
        KeytoolRegistry.shared.openFile(path: chosenPath, storeType: type, password: pass) {
            isLoading = false
            if let ks = KeytoolRegistry.shared.keystores.first(where: { $0.path == chosenPath }) {
                if let errMsg = ks.error {
                    error = errMsg
                } else {
                    onOpened?(ks.id)
                }
            }
        }
    }
}

// MARK: - Root Tab: Open Keystore

struct OpenKeystoreView: View {
    @ObservedObject private var registry = KeytoolRegistry.shared
    @State private var showOpenForm = true
    @State private var selectedAlias: String?
    @State private var detailEntry: KeystoreEntryInfo?
    @State private var sortOrder = [KeyPathComparator(\KeystoreEntryInfo.alias)]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 10) {
                    Image(systemName: "lock.open.fill")
                        .font(.title2)
                        .foregroundColor(Color(hue: 0.11, saturation: 0.88, brightness: 0.82))
                    Text("Open Keystore")
                        .font(.title2.bold())
                }
                .padding([.top, .horizontal])

                Text("Open one or more JKS / PKCS12 keystores and inspect their entries")
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .padding(.horizontal)

                if !KeytoolHelper.shared.isKeytoolAvailable {
                    ErrorText(error: KeytoolError.javaNotFound.localizedDescription).padding(.horizontal)
                }

                if showOpenForm || registry.keystores.isEmpty {
                    KeystoreQuickOpenForm { _ in showOpenForm = false }
                        .padding(.horizontal)
                }

                if !registry.keystores.isEmpty {
                    openFilesBar.padding(.horizontal)
                }

                if let ks = registry.selected {
                    keystoreDetail(ks)
                } else if !registry.keystores.isEmpty {
                    Text("Select an opened keystore above").font(.system(size: 12)).foregroundColor(.secondary).padding(.horizontal)
                }
            }
            .padding(.bottom)
        }
        .sheet(item: $detailEntry) { entry in KeystoreCertDetailSheet(entry: entry) }
    }

    private var openFilesBar: some View {
        HStack(spacing: 8) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    ForEach(registry.keystores) { ks in
                        HStack(spacing: 6) {
                            Text(ks.displayName).font(.system(size: 11, weight: .medium)).lineLimit(1)
                            Button { registry.close(id: ks.id) } label: {
                                Image(systemName: "xmark.circle.fill").font(.system(size: 10))
                            }
                            .buttonStyle(.plain)
                            .foregroundColor(.secondary)
                        }
                        .padding(.horizontal, 10).padding(.vertical, 6)
                        .background(RoundedRectangle(cornerRadius: 6)
                            .fill(registry.selectedKeystoreID == ks.id ? Color.accentColor.opacity(0.18) : Color(nsColor: .controlBackgroundColor)))
                        .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.2), lineWidth: 1))
                        .contentShape(Rectangle())
                        .onTapGesture { registry.selectedKeystoreID = ks.id }
                    }
                }
            }
            Button {
                showOpenForm.toggle()
            } label: {
                Image(systemName: showOpenForm ? "chevron.up.circle" : "plus.circle")
            }
            .buttonStyle(.plain)
        }
    }

    @ViewBuilder
    private func keystoreDetail(_ ks: ManagedKeystore) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text("File: \(ks.path)")
                Text("Detected type: \(ks.resolvedStoreType.rawValue)")
            }
            .font(.system(size: 10, design: .monospaced))
            .foregroundColor(.secondary)
            .padding(.horizontal)

            if ks.isLoading { ProgressView("Running keytool -list -v…").padding(.horizontal) }
            if let error = ks.error { ErrorText(error: error).padding(.horizontal) }

            if !ks.entries.isEmpty {
                statsRow(ks).padding(.horizontal)
                entriesTable(ks).padding(.horizontal)
            }
        }
    }

    private func statsRow(_ ks: ManagedKeystore) -> some View {
        HStack(spacing: 10) {
            statBadge("\(ks.entries.count)", "Entries", .accentColor)
            statBadge("\(ks.entries.filter { $0.entryType == "PrivateKeyEntry" }.count)", "Private Key", .blue)
            statBadge("\(ks.entries.filter { $0.entryType == "trustedCertEntry" }.count)", "Trusted Cert", .purple)
            let expired = ks.entries.filter { $0.expiryStatus == .expired }.count
            statBadge("\(expired)", "Expired", expired > 0 ? .red : .secondary)
            let expiring = ks.entries.filter { $0.expiryStatus == .expiringSoon }.count
            statBadge("\(expiring)", "Expiring Soon", expiring > 0 ? .orange : .secondary)
        }
    }

    private func entriesTable(_ ks: ManagedKeystore) -> some View {
        Table(ks.entries.sorted(using: sortOrder), selection: $selectedAlias, sortOrder: $sortOrder) {
            TableColumn("Alias", value: \.alias) { e in
                Text(e.alias).font(.system(size: 11, weight: .medium)).lineLimit(1)
            }.width(min: 90, ideal: 120)

            TableColumn("Entry Type", value: \.entryType) { e in
                Text(shortEntryType(e.entryType)).font(.system(size: 10)).foregroundColor(.secondary)
            }.width(100)

            TableColumn("Subject (CN)") { e in
                Text(e.certInfo.map { cn($0.subject) } ?? "—").font(.system(size: 11)).lineLimit(1)
            }.width(min: 140, ideal: 180)

            TableColumn("Issuer (CN)") { e in
                Text(e.certInfo.map { cn($0.issuer) } ?? "—").font(.system(size: 11)).foregroundColor(.secondary).lineLimit(1)
            }.width(min: 130, ideal: 170)

            TableColumn("Valid Until") { e in
                Text(e.certInfo.map { shortDate($0.notAfter) } ?? "—").font(.system(size: 11))
            }.width(90)

            TableColumn("Days Left") { e in
                if let days = e.daysUntilExpiry {
                    Text(days < 0 ? "\(-days)d ago" : "\(days)d").font(.system(size: 11, design: .monospaced))
                } else {
                    Text("—").foregroundColor(.secondary)
                }
            }.width(70)

            TableColumn("Status") { e in statusBadge(e.expiryStatus) }.width(100)
        }
        .frame(minHeight: 280)
        .tableStyle(.inset(alternatesRowBackgrounds: true))
        .onChange(of: selectedAlias) { alias in
            guard let alias, let entry = ks.entries.first(where: { $0.alias == alias }) else { return }
            detailEntry = entry
        }
    }

    private func shortEntryType(_ type: String) -> String {
        switch type {
        case "PrivateKeyEntry": return "Private Key"
        case "trustedCertEntry": return "Trusted Cert"
        case "SecretKeyEntry": return "Secret Key"
        default: return type
        }
    }

    @ViewBuilder
    private func statusBadge(_ status: KeystoreExpiryStatus) -> some View {
        let color: Color = switch status {
        case .valid: .green
        case .expiringSoon: .orange
        case .expired: .red
        case .unknown: .secondary
        }
        Text(status.label)
            .font(.system(size: 10, weight: .semibold))
            .foregroundColor(color)
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background(Capsule().fill(color.opacity(0.15)))
            .lineLimit(1)
    }

    private func statBadge(_ value: String, _ label: String, _ color: Color) -> some View {
        VStack(spacing: 2) {
            Text(value).font(.system(size: 15, weight: .bold)).foregroundColor(color)
            Text(label).font(.system(size: 9)).foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
        .background(RoundedRectangle(cornerRadius: 6).fill(Color(nsColor: .controlBackgroundColor)))
        .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.2), lineWidth: 1))
    }

    private func cn(_ dn: OrderedDN) -> String {
        dn.first(where: { $0.key == "CN" })?.value ?? dn.first?.value ?? "—"
    }

    private func shortDate(_ iso: String) -> String {
        guard let d = ISO8601DateFormatter().date(from: iso) else { return iso }
        let f = DateFormatter(); f.dateFormat = "yyyy-MM-dd"
        return f.string(from: d)
    }
}

// MARK: - Certificate Detail Sheet

struct KeystoreCertDetailSheet: View {
    let entry: KeystoreEntryInfo
    @Environment(\.dismiss) private var dismiss

    private var warnings: [KeystoreCertWarning] {
        entry.certInfo?.keystoreWarnings() ?? []
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(spacing: 14) {
                    if let info = entry.certInfo {
                        if !warnings.isEmpty { warningsCard }
                        infoCard("Subject") {
                            ForEach(info.subject.indices, id: \.self) { i in
                                FieldRow(label: info.subject[i].key, value: info.subject[i].value)
                            }
                        }
                        infoCard("Issuer") {
                            ForEach(info.issuer.indices, id: \.self) { i in
                                FieldRow(label: info.issuer[i].key, value: info.issuer[i].value)
                            }
                        }
                        infoCard("Properties") {
                            FieldRow(label: "Serial", value: info.serial)
                            FieldRow(label: "Key Algorithm", value: "\(info.publicKey.type) \(info.publicKey.bits) bits")
                            FieldRow(label: "Signature Algorithm", value: info.signatureAlg)
                            FieldRow(label: "Not Before", value: fmtDate(info.notBefore))
                            FieldRow(label: "Not After", value: fmtDate(info.notAfter))
                            if let days = entry.daysUntilExpiry {
                                FieldRow(label: "Days Until Expiry", value: days < 0 ? "Expired \(-days)d ago" : "\(days) day(s)")
                            }
                            FieldRow(label: "Self-Signed", value: info.selfSigned ? "Yes" : "No")
                        }
                        if !info.san.isEmpty {
                            infoCard("Subject Alternative Names") {
                                ForEach(info.san.indices, id: \.self) { i in
                                    FieldRow(label: i == 0 ? "SAN" : "", value: info.san[i])
                                }
                            }
                        }
                        infoCard("Fingerprints") {
                            FieldRow(label: "SHA-256", value: info.fingerprints.sha256)
                            FieldRow(label: "SHA-1", value: info.fingerprints.sha1)
                            FieldRow(label: "MD5", value: info.fingerprints.md5)
                        }
                        if entry.chainPEMs.count > 1 {
                            infoCard("Certificate Chain (\(entry.chainPEMs.count))") {
                                ForEach(entry.chainPEMs.indices, id: \.self) { i in
                                    FieldRow(label: "Cert #\(i + 1)", value: chainSummary(entry.chainPEMs[i]))
                                }
                            }
                        }
                        exportActions(pem: entry.chainPEMs.first ?? "")
                    } else if entry.entryType == "SecretKeyEntry" {
                        Text("Secret key entries do not contain a certificate.")
                            .font(.system(size: 12)).foregroundColor(.secondary).padding()
                    } else if let parseError = entry.parseError {
                        ErrorText(error: parseError)
                    }
                }
                .padding()
            }
        }
        .frame(minWidth: 620, minHeight: 520)
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.alias).font(.headline)
                Text(entry.entryType).font(.caption).foregroundColor(.secondary)
            }
            Spacer()
            if entry.expiryStatus == .expired { badge("Expired", .red) }
            if entry.expiryStatus == .expiringSoon { badge("Expiring Soon", .orange) }
            Button("Done") { dismiss() }.buttonStyle(.borderedProminent).controlSize(.small)
        }
        .padding()
        .background(Color(nsColor: .controlBackgroundColor))
    }

    private var warningsCard: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(warnings) { w in
                HStack(spacing: 6) {
                    Image(systemName: w.severity == .error ? "xmark.octagon.fill" : "exclamationmark.triangle.fill")
                        .foregroundColor(w.severity == .error ? .red : .orange)
                        .font(.system(size: 11))
                    Text(w.message).font(.system(size: 11)).foregroundColor(.primary)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color.orange.opacity(0.08)))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.orange.opacity(0.25), lineWidth: 1))
    }

    private func exportActions(pem: String) -> some View {
        HStack {
            Text("Certificate (PEM)").font(.system(size: 12, weight: .semibold))
            Spacer()
            CopyButton(text: pem)
            DownloadButton(filename: "\(entry.alias).pem", content: pem)
        }
        .padding(.top, 4)
    }

    @ViewBuilder
    private func infoCard<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.system(size: 12, weight: .semibold))
            VStack(spacing: 0) { content() }
                .padding(10)
                .background(RoundedRectangle(cornerRadius: 8).fill(Color(nsColor: .controlBackgroundColor)))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.secondary.opacity(0.15), lineWidth: 1))
        }
    }

    private func badge(_ text: String, _ color: Color) -> some View {
        Text(text).font(.system(size: 10, weight: .semibold))
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background(Capsule().fill(color.opacity(0.15))).foregroundColor(color)
    }

    private func chainSummary(_ pem: String) -> String {
        guard let info = try? CertService.shared.parseCertificate(pem: pem) else { return "Unable to parse" }
        let subjectCN = info.subject.first(where: { $0.key == "CN" })?.value ?? "—"
        return subjectCN
    }

    private func fmtDate(_ iso: String) -> String {
        guard let d = ISO8601DateFormatter().date(from: iso) else { return iso }
        let f = DateFormatter(); f.dateStyle = .medium; f.timeStyle = .short
        return f.string(from: d)
    }
}

extension KeystoreExpiryStatus: Equatable {}
