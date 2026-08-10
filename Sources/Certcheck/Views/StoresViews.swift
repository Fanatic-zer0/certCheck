import SwiftUI

struct CABundleView: View {
    @State private var inputPEM = ""
    @State private var entries: [TrustEntry] = []
    @State private var error: String?
    @State private var filter = ""
    @State private var showOnlyCA = false
    @State private var selectedID: Int?
    @State private var sortOrder = [KeyPathComparator(\TrustEntry.index)]
    @State private var detailEntry: TrustEntry?

    private var filteredEntries: [TrustEntry] {
        let base = entries.filter { entry in
            if showOnlyCA && !entry.isCA { return false }
            if filter.isEmpty { return true }
            let q = filter.lowercased()
            let subject = cn(entry.subject).lowercased()
            let issuer  = cn(entry.issuer).lowercased()
            return subject.contains(q) || issuer.contains(q) || entry.serial.lowercased().contains(q)
        }
        return base.sorted(using: sortOrder)
    }

    private var stats: (total: Int, ca: Int, selfSigned: Int, expired: Int) {
        let now = Date()
        return (
            total: entries.count,
            ca: entries.filter { $0.isCA }.count,
            selfSigned: entries.filter { $0.selfSigned }.count,
            expired: entries.filter {
                guard let d = ISO8601DateFormatter().date(from: $0.notAfter) else { return false }
                return d < now
            }.count
        )
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Image(systemName: "books.vertical")
                    .font(.title2)
                    .foregroundColor(Color(hue: 0.11, saturation: 0.88, brightness: 0.82))
                Text("CA Bundle Inspector")
                    .font(.title2.bold())
            }
            .padding([.top, .horizontal])

            Text("Paste a PEM CA bundle or truststore to inspect all certificates")
                .font(.caption)
                .foregroundColor(.secondary)
                .padding(.horizontal)

            VStack(alignment: .leading, spacing: 4) {
                Text("PEM CA Bundle / Truststore")
                    .font(.system(size: 11, weight: .medium))
                    .foregroundColor(.secondary)

                TextEditor(text: $inputPEM)
                    .font(.system(size: 10, design: .monospaced))
                    .frame(height: 120)
                    .padding(6)
                    .background(Color(nsColor: .textBackgroundColor))
                    .cornerRadius(6)
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.2), lineWidth: 1))
            }
            .padding(.horizontal)

            HStack(spacing: 12) {
                ActionButton(
                    title: "Parse Bundle",
                    icon: "doc.text.magnifyingglass",
                    action: parseBundle,
                    disabled: inputPEM.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                )
                if !entries.isEmpty {
                    Button("Clear") { entries = []; filter = ""; showOnlyCA = false; selectedID = nil }
                        .buttonStyle(.bordered)
                }
            }
            .padding(.horizontal)

            if let error = error { ErrorText(error: error).padding(.horizontal) }

            if !entries.isEmpty {
                // Stats row
                HStack(spacing: 10) {
                    statBadge("\(stats.total)", "Total", .accentColor)
                    statBadge("\(stats.ca)", "CA", .blue)
                    statBadge("\(stats.selfSigned)", "Self-Signed", .purple)
                    statBadge("\(stats.expired)", "Expired", stats.expired > 0 ? .red : .secondary)
                }
                .padding(.horizontal)

                // Filter bar
                HStack {
                    Image(systemName: "magnifyingglass").foregroundColor(.secondary)
                    TextField("Filter by subject, issuer, serial…", text: $filter)
                        .textFieldStyle(.plain)
                    if !filter.isEmpty {
                        Button { filter = "" } label: { Image(systemName: "xmark.circle.fill").foregroundColor(.secondary) }
                            .buttonStyle(.plain)
                    }
                }
                .padding(6)
                .background(Color(nsColor: .controlBackgroundColor))
                .cornerRadius(7)
                .overlay(RoundedRectangle(cornerRadius: 7).stroke(Color.secondary.opacity(0.2), lineWidth: 1))
                .padding(.horizontal)

                Toggle("Show CA certs only", isOn: $showOnlyCA)
                    .toggleStyle(.checkbox)
                    .font(.system(size: 11))
                    .padding(.horizontal)

                // Table
                Table(filteredEntries, selection: $selectedID, sortOrder: $sortOrder) {
                    TableColumn("#") { e in
                        Text("\(e.index + 1)")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(.secondary)
                    }
                    .width(30)

                    TableColumn("Subject (CN)", value: \.index) { e in
                        VStack(alignment: .leading, spacing: 1) {
                            Text(cn(e.subject))
                                .font(.system(size: 11, weight: .medium))
                                .lineLimit(1)
                            if e.isCA || e.selfSigned {
                                HStack(spacing: 4) {
                                    if e.isCA    { badge("CA",          .green) }
                                    if e.selfSigned { badge("Self-Signed", .purple) }
                                }
                            }
                        }
                    }
                    .width(min: 160, ideal: 200)

                    TableColumn("Issuer (CN)", value: \.index) { e in
                        Text(cn(e.issuer))
                            .font(.system(size: 11))
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                    }
                    .width(min: 140, ideal: 180)

                    TableColumn("Key", value: \.keyBits) { e in
                        Text("\(e.keyType) \(e.keyBits)")
                            .font(.system(size: 11, design: .monospaced))
                    }
                    .width(70)

                    TableColumn("Valid Until", value: \.notAfter) { e in
                        Text(shortDate(e.notAfter))
                            .font(.system(size: 11))
                    }
                    .width(90)

                    TableColumn("Expires In", value: \.notAfter) { e in
                        expiresInText(e.notAfter)
                    }
                    .width(90)

                    TableColumn("Status", value: \.notAfter) { e in
                        expiresInCell(e.notAfter)
                    }
                    .width(100)
                }
                .frame(minHeight: 300)
                .tableStyle(.inset(alternatesRowBackgrounds: true))
                .onChange(of: selectedID) { id in
                    if let id, let entry = entries.first(where: { $0.id == id }) {
                        detailEntry = entry
                    }
                }
            }

            Spacer()
        }
        .sheet(item: $detailEntry) { entry in
            BundleEntryDetailSheet(entry: entry)
        }
    }

    // MARK: - Helpers

    @ViewBuilder
    private func expiresInText(_ iso: String) -> some View {
        if let date = ISO8601DateFormatter().date(from: iso) {
            let days = Calendar.current.dateComponents([.day], from: Date(), to: date).day ?? 0
            if days < 0 {
                Text("\(-days)d ago")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.red)
            } else if days == 0 {
                Text("Today")
                    .font(.system(size: 11))
                    .foregroundColor(.orange)
            } else {
                Text("in \(days)d")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.secondary)
            }
        } else {
            Text("—").foregroundColor(.secondary)
        }
    }

    @ViewBuilder
    private func expiresInCell(_ iso: String) -> some View {
        if let date = ISO8601DateFormatter().date(from: iso) {
            let days = Calendar.current.dateComponents([.day], from: Date(), to: date).day ?? 0
            if days < 0 {
                statusBadge("Expired", color: .red)
            } else if days == 0 {
                statusBadge("Expires Today", color: .orange)
            } else if days <= 30 {
                statusBadge("Expiring Soon", color: .orange)
            } else {
                statusBadge("Active", color: .green)
            }
        } else {
            Text("—").foregroundColor(.secondary)
        }
    }

    @ViewBuilder
    private func statusBadge(_ label: String, color: Color) -> some View {
        Text(label)
            .font(.system(size: 10, weight: .semibold))
            .foregroundColor(color)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(Capsule().fill(color.opacity(0.15)))
            .lineLimit(1)
    }

    @ViewBuilder
    private func badge(_ text: String, _ color: Color) -> some View {
        Text(text)
            .font(.system(size: 9, weight: .semibold))
            .padding(.horizontal, 5).padding(.vertical, 2)
            .background(Capsule().fill(color.opacity(0.15)))
            .foregroundColor(color)
    }

    @ViewBuilder
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

    private func parseBundle() {
        error = nil; entries = []; selectedID = nil
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let result = try CertService.shared.parseCABundle(pem: inputPEM)
                DispatchQueue.main.async { self.entries = result }
            } catch {
                DispatchQueue.main.async { self.error = error.localizedDescription }
            }
        }
    }
}

struct KeystoreView: View {
    @State private var entries: [TrustEntry] = []
    @State private var error: String?
    @State private var filePath = ""
    @State private var password = ""
    @State private var isLoading = false
    @State private var selectedID: Int?
    @State private var sortOrder = [KeyPathComparator(\TrustEntry.index)]
    @State private var detailEntry: TrustEntry?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Image(systemName: "cylinder")
                    .font(.title2)
                    .foregroundColor(Color(hue: 0.11, saturation: 0.88, brightness: 0.82))
                Text("Keystore Inspector")
                    .font(.title2.bold())
            }
            .padding([.top, .horizontal])

            Text("Open a PKCS#12 (.p12 / .pfx) file to inspect its certificates")
                .font(.caption).foregroundColor(.secondary)
                .padding(.horizontal)

            HStack {
                SecureField("Password (leave empty if none)", text: $password)
                    .textFieldStyle(.roundedBorder)
                Button("Open File…") { chooseFile() }.buttonStyle(.bordered)
                if !entries.isEmpty {
                    Button("Clear") { entries = []; filePath = ""; selectedID = nil }
                        .buttonStyle(.bordered)
                }
            }
            .padding(.horizontal)

            if !filePath.isEmpty {
                Text("File: \(URL(fileURLWithPath: filePath).lastPathComponent)")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.secondary)
                    .padding(.horizontal)
            }

            if isLoading { ProgressView("Parsing keystore…").padding() }
            if let error = error { ErrorText(error: error).padding(.horizontal) }

            if !entries.isEmpty {
                HStack(spacing: 10) {
                    statBadge("\(entries.count)", "Total", .accentColor)
                    statBadge("\(entries.filter { $0.isCA }.count)", "CA", .blue)
                    let expired = entries.filter {
                        ISO8601DateFormatter().date(from: $0.notAfter).map { $0 < Date() } ?? false
                    }.count
                    statBadge("\(expired)", "Expired", expired > 0 ? .red : .secondary)
                }
                .padding(.horizontal)

                Table(entries.sorted(using: sortOrder), selection: $selectedID, sortOrder: $sortOrder) {
                    TableColumn("#") { e in
                        Text("\(e.index + 1)").font(.system(size: 11, design: .monospaced)).foregroundColor(.secondary)
                    }.width(30)
                    TableColumn("Subject (CN)", value: \.index) { e in
                        VStack(alignment: .leading, spacing: 1) {
                            Text(cn(e.subject)).font(.system(size: 11, weight: .medium)).lineLimit(1)
                            if e.isCA { badge("CA", .green) }
                        }
                    }.width(min: 160, ideal: 200)
                    TableColumn("Issuer (CN)", value: \.index) { e in
                        Text(cn(e.issuer)).font(.system(size: 11)).foregroundColor(.secondary).lineLimit(1)
                    }.width(min: 130, ideal: 170)
                    TableColumn("Key", value: \.keyBits) { e in
                        Text("\(e.keyType) \(e.keyBits)").font(.system(size: 11, design: .monospaced))
                    }.width(70)
                    TableColumn("Valid Until", value: \.notAfter) { e in
                        Text(shortDate(e.notAfter)).font(.system(size: 11))
                    }.width(90)
                    TableColumn("Status", value: \.notAfter) { e in
                        expiresInCell(e.notAfter)
                    }.width(100)
                }
                .frame(minHeight: 250)
                .tableStyle(.inset(alternatesRowBackgrounds: true))
                .onChange(of: selectedID) { id in
                    if let id, let entry = entries.first(where: { $0.id == id }) {
                        detailEntry = entry
                    }
                }
            }
            Spacer()
        }
        .sheet(item: $detailEntry) { entry in BundleEntryDetailSheet(entry: entry) }
    }

    // MARK: - Helpers (shared with CABundleView)

    @ViewBuilder
    private func expiresInCell(_ iso: String) -> some View {
        if let date = ISO8601DateFormatter().date(from: iso) {
            let days = Calendar.current.dateComponents([.day], from: Date(), to: date).day ?? 0
            if days < 0 { statusBadge("Expired", color: .red) }
            else if days == 0 { statusBadge("Expires Today", color: .orange) }
            else if days <= 30 { statusBadge("Expiring Soon", color: .orange) }
            else { statusBadge("Active", color: .green) }
        } else { Text("—").foregroundColor(.secondary) }
    }

    @ViewBuilder
    private func statusBadge(_ label: String, color: Color) -> some View {
        Text(label).font(.system(size: 10, weight: .semibold)).foregroundColor(color)
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background(Capsule().fill(color.opacity(0.15))).lineLimit(1)
    }

    @ViewBuilder
    private func statBadge(_ value: String, _ label: String, _ color: Color) -> some View {
        VStack(spacing: 2) {
            Text(value).font(.system(size: 15, weight: .bold)).foregroundColor(color)
            Text(label).font(.system(size: 9)).foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity).padding(.vertical, 8)
        .background(RoundedRectangle(cornerRadius: 6).fill(Color(nsColor: .controlBackgroundColor)))
        .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.2), lineWidth: 1))
    }

    @ViewBuilder
    private func badge(_ text: String, _ color: Color) -> some View {
        Text(text).font(.system(size: 9, weight: .semibold))
            .padding(.horizontal, 5).padding(.vertical, 2)
            .background(Capsule().fill(color.opacity(0.15))).foregroundColor(color)
    }

    private func cn(_ dn: OrderedDN) -> String {
        dn.first(where: { $0.key == "CN" })?.value ?? dn.first?.value ?? "—"
    }

    private func shortDate(_ iso: String) -> String {
        guard let d = ISO8601DateFormatter().date(from: iso) else { return iso }
        let f = DateFormatter(); f.dateFormat = "yyyy-MM-dd"; return f.string(from: d)
    }

    private func chooseFile() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.message = "Select a PKCS#12 keystore (.p12 or .pfx)"
        if panel.runModal() == .OK, let url = panel.url {
            filePath = url.path
            loadKeystore(path: url.path)
        }
    }

    private func loadKeystore(path: String) {
        isLoading = true; error = nil; entries = []
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let pems = try OpenSSLHelper.shared.extractCertsFromPKCS12(path: path, password: password)
                let result = try pems.enumerated().map { idx, pem -> TrustEntry in
                    let info = try CertService.shared.parseCertificate(pem: pem)
                    return TrustEntry(
                        index: idx,
                        alias: "cert-\(idx + 1)",
                        subject: info.subject,
                        issuer: info.issuer,
                        serial: info.serial,
                        notBefore: info.notBefore,
                        notAfter: info.notAfter,
                        isCA: info.extensions.contains(where: {
                            $0.name == "Basic Constraints" && $0.value.contains("CA:TRUE")
                        }),
                        selfSigned: info.subject.map { "\($0.key)=\($0.value)" }.joined() ==
                                    info.issuer.map { "\($0.key)=\($0.value)" }.joined(),
                        san: info.san,
                        keyType: info.publicKey.type,
                        keyBits: info.publicKey.bits,
                        sigAlg: info.signatureAlg,
                        fingerprints: info.fingerprints,
                        pem: pem
                    )
                }
                DispatchQueue.main.async { self.entries = result; self.isLoading = false }
            } catch {
                DispatchQueue.main.async { self.error = error.localizedDescription; self.isLoading = false }
            }
        }
    }
}

// MARK: - Shared detail sheet for CA Bundle and Keystore rows

struct BundleEntryDetailSheet: View {
    let entry: TrustEntry
    @Environment(\.dismiss) private var dismiss

    private var isExpired: Bool {
        ISO8601DateFormatter().date(from: entry.notAfter).map { $0 < Date() } ?? false
    }

    var body: some View {
        VStack(spacing: 0) {
            // Title bar
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(cn(entry.subject)).font(.headline)
                    Text("Certificate #\(entry.index + 1)").font(.caption).foregroundColor(.secondary)
                }
                Spacer()
                if entry.isCA { badge("CA", .green) }
                if isExpired { badge("Expired", .red) }
                Button("Done") { dismiss() }.buttonStyle(.borderedProminent).controlSize(.small)
            }
            .padding()
            .background(Color(nsColor: .controlBackgroundColor))

            Divider()

            ScrollView {
                VStack(spacing: 14) {
                    infoCard("Subject") {
                        ForEach(entry.subject.indices, id: \.self) { i in
                            FieldRow(label: entry.subject[i].key, value: entry.subject[i].value)
                        }
                    }
                    infoCard("Issuer") {
                        ForEach(entry.issuer.indices, id: \.self) { i in
                            FieldRow(label: entry.issuer[i].key, value: entry.issuer[i].value)
                        }
                    }
                    infoCard("Properties") {
                        FieldRow(label: "Serial", value: entry.serial)
                        FieldRow(label: "Key", value: "\(entry.keyType) \(entry.keyBits) bits")
                        FieldRow(label: "Signature Alg", value: entry.sigAlg)
                        FieldRow(label: "Not Before", value: fmtDate(entry.notBefore))
                        FieldRow(label: "Not After",
                                 value: fmtDate(entry.notAfter) + (isExpired ? " ⚠ EXPIRED" : ""))
                    }
                    if !entry.san.isEmpty {
                        infoCard("Subject Alternative Names") {
                            ForEach(entry.san.indices, id: \.self) { i in
                                FieldRow(label: i == 0 ? "SAN" : "", value: entry.san[i])
                            }
                        }
                    }
                    infoCard("Fingerprints") {
                        FieldRow(label: "MD5",     value: entry.fingerprints.md5)
                        FieldRow(label: "SHA-1",   value: entry.fingerprints.sha1)
                        FieldRow(label: "SHA-256", value: entry.fingerprints.sha256)
                    }
                }
                .padding()
            }
        }
        .frame(minWidth: 600, minHeight: 480)
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

    @ViewBuilder
    private func badge(_ text: String, _ color: Color) -> some View {
        Text(text).font(.system(size: 10, weight: .semibold))
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background(Capsule().fill(color.opacity(0.15))).foregroundColor(color)
    }

    private func cn(_ dn: OrderedDN) -> String {
        dn.first(where: { $0.key == "CN" })?.value ?? dn.first?.value ?? "—"
    }

    private func fmtDate(_ iso: String) -> String {
        guard let d = ISO8601DateFormatter().date(from: iso) else { return iso }
        let f = DateFormatter(); f.dateStyle = .medium; f.timeStyle = .short
        return f.string(from: d)
    }
}
