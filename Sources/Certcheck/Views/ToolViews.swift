import SwiftUI

// MARK: - Private Key Inspector

struct KeyInspectView: View {
    @State private var inputPEM = ""
    @State private var result: OpenSSLHelper.KeyInspectResult?
    @State private var error: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack(spacing: 10) {
                    Image(systemName: "lock.open")
                        .font(.title2)
                        .foregroundColor(Color(hue: 0.68, saturation: 0.70, brightness: 0.75))
                    Text("Private Key Inspector")
                        .font(.title2.bold())
                }
                Text("Inspect RSA, EC, and Ed25519 private keys in PEM format")
                    .font(.caption).foregroundColor(.secondary)

                PEMInputField(
                    label: "PEM Private Key",
                    placeholder: "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
                    text: $inputPEM
                )

                ActionButton(
                    title: "Inspect Key",
                    icon: "magnifyingglass",
                    action: inspect,
                    disabled: inputPEM.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                )

                if let error = error { ErrorText(error: error) }

                if let r = result {
                    InfoCard(title: "Key Properties") {
                        AnyView(VStack(spacing: 4) {
                            FieldRow(label: "Type",      value: r.type)
                            if r.bits > 0 { FieldRow(label: "Size", value: "\(r.bits) bits") }
                            if let c = r.curve { FieldRow(label: "Curve", value: c) }
                            if let e = r.publicExponent { FieldRow(label: "Public Exponent", value: e) }
                            FieldRow(label: "Encrypted", value: r.isEncrypted ? "Yes" : "No")
                        })
                    }

                    InfoCard(title: "Public Key Fingerprint") {
                        AnyView(FieldRow(label: "SHA-256", value: r.publicKeyFingerprint))
                    }

                    InfoCard(title: "Public Key (PEM)") {
                        AnyView(VStack(alignment: .leading, spacing: 6) {
                            Text(r.publicKeyPEM)
                                .font(.system(size: 10, design: .monospaced))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                            CopyButton(text: r.publicKeyPEM)
                        })
                    }
                }
            }
            .padding()
        }
    }

    private func inspect() {
        error = nil; result = nil
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let r = try OpenSSLHelper.shared.inspectPrivateKey(inputPEM)
                DispatchQueue.main.async { self.result = r }
            } catch {
                DispatchQueue.main.async { self.error = error.localizedDescription }
            }
        }
    }
}

// MARK: - Certificate Diff

struct CertDiffView: View {
    @State private var pemA = ""
    @State private var pemB = ""
    @State private var certA: CertInfo?
    @State private var certB: CertInfo?
    @State private var error: String?
    @State private var isLoading = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack(spacing: 10) {
                    Image(systemName: "arrow.left.arrow.right")
                        .font(.title2)
                        .foregroundColor(Color(hue: 0.46, saturation: 0.60, brightness: 0.58))
                    Text("Certificate Diff")
                        .font(.title2.bold())
                }
                Text("Compare two X.509 certificates field by field")
                    .font(.caption).foregroundColor(.secondary)

                HStack(alignment: .top, spacing: 12) {
                    PEMInputField(
                        label: "Certificate A",
                        placeholder: "-----BEGIN CERTIFICATE-----\n...",
                        text: $pemA
                    )
                    PEMInputField(
                        label: "Certificate B",
                        placeholder: "-----BEGIN CERTIFICATE-----\n...",
                        text: $pemB
                    )
                }

                ActionButton(
                    title: isLoading ? "Comparing…" : "Compare",
                    icon: "arrow.left.arrow.right",
                    action: compare,
                    disabled: pemA.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ||
                              pemB.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || isLoading
                )

                if let error = error { ErrorText(error: error) }

                if let a = certA, let b = certB {
                    // Legend
                    HStack(spacing: 16) {
                        Label("Match", systemImage: "checkmark.circle.fill").foregroundColor(.green)
                        Label("Differ", systemImage: "exclamationmark.circle.fill").foregroundColor(.orange)
                    }
                    .font(.system(size: 11))

                    diffTable(a, b)
                }
            }
            .padding()
        }
    }

    @ViewBuilder
    private func diffTable(_ a: CertInfo, _ b: CertInfo) -> some View {
        VStack(spacing: 0) {
            // Header
            HStack(spacing: 0) {
                Text("Field")
                    .font(.system(size: 11, weight: .semibold))
                    .frame(width: 130, alignment: .leading)
                    .padding(.leading, 12)
                Text("Certificate A")
                    .font(.system(size: 11, weight: .semibold))
                    .frame(maxWidth: .infinity, alignment: .leading)
                Text("Certificate B")
                    .font(.system(size: 11, weight: .semibold))
                    .frame(maxWidth: .infinity, alignment: .leading)
                Spacer().frame(width: 28)
            }
            .padding(.vertical, 8)
            .background(Color(nsColor: .controlBackgroundColor))
            .cornerRadius(8, corners: [.topLeft, .topRight])

            Divider()

            // Rows
            VStack(spacing: 0) {
                diffRow("CN",            va(a.subject, "CN"),   va(b.subject, "CN"))
                diffRow("Organization",  va(a.subject, "O"),    va(b.subject, "O"))
                diffRow("Country",       va(a.subject, "C"),    va(b.subject, "C"))
                diffRow("Issuer CN",     va(a.issuer, "CN"),    va(b.issuer, "CN"))
                diffRow("Serial",        a.serial,              b.serial)
                diffRow("Not Before",    fmtDate(a.notBefore),  fmtDate(b.notBefore))
                diffRow("Not After",     fmtDate(a.notAfter),   fmtDate(b.notAfter))
                diffRow("Key",           "\(a.publicKey.type) \(a.publicKey.bits)b", "\(b.publicKey.type) \(b.publicKey.bits)b")
                diffRow("Sig Algorithm", a.signatureAlg,        b.signatureAlg)
                diffRow("SANs",          a.san.joined(separator: ", "), b.san.joined(separator: ", "))
                diffRow("SHA-256",       a.fingerprints.sha256, b.fingerprints.sha256)
            }
            .background(Color(nsColor: .controlBackgroundColor))
            .cornerRadius(8, corners: [.bottomLeft, .bottomRight])
        }
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.secondary.opacity(0.15), lineWidth: 1))
    }

    @ViewBuilder
    private func diffRow(_ label: String, _ valA: String, _ valB: String) -> some View {
        let matches = valA.lowercased() == valB.lowercased()
        VStack(spacing: 0) {
            HStack(spacing: 0) {
                Text(label)
                    .font(.system(size: 11, weight: .medium))
                    .foregroundColor(.secondary)
                    .frame(width: 130, alignment: .leading)
                    .padding(.leading, 12)

                Text(valA.isEmpty ? "—" : valA)
                    .font(.system(size: 11))
                    .foregroundColor(matches ? .primary : .orange)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
                    .lineLimit(2)

                Divider().frame(height: 24)

                Text(valB.isEmpty ? "—" : valB)
                    .font(.system(size: 11))
                    .foregroundColor(matches ? .primary : .orange)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
                    .lineLimit(2)

                Image(systemName: matches ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                    .foregroundColor(matches ? Color.green.opacity(0.5) : .orange)
                    .font(.system(size: 12))
                    .frame(width: 28)
            }
            .padding(.vertical, 7)
            .background(matches ? Color.clear : Color.orange.opacity(0.04))
            Divider()
        }
    }

    private func compare() {
        isLoading = true; error = nil; certA = nil; certB = nil
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let a = try CertService.shared.parseCertificate(pem: pemA)
                let b = try CertService.shared.parseCertificate(pem: pemB)
                DispatchQueue.main.async { self.certA = a; self.certB = b; self.isLoading = false }
            } catch {
                DispatchQueue.main.async { self.error = error.localizedDescription; self.isLoading = false }
            }
        }
    }

    private func va(_ dn: OrderedDN, _ key: String) -> String {
        dn.first(where: { $0.key == key })?.value ?? "—"
    }

    private func fmtDate(_ iso: String) -> String {
        guard let d = ISO8601DateFormatter().date(from: iso) else { return iso }
        let f = DateFormatter(); f.dateFormat = "yyyy-MM-dd"; return f.string(from: d)
    }
}

// MARK: - Certificate Converter

struct CertConvertView: View {
    @State private var inputPEM = ""
    @State private var outputDER = ""
    @State private var outputPKCS7 = ""
    @State private var error: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack(spacing: 10) {
                    Image(systemName: "arrow.2.squarepath")
                        .font(.title2)
                        .foregroundColor(Color(hue: 0.86, saturation: 0.60, brightness: 0.78))
                    Text("Certificate Converter")
                        .font(.title2.bold())
                }
                Text("Convert a PEM certificate to DER (Base64) or PKCS#7 / P7B format")
                    .font(.caption).foregroundColor(.secondary)

                PEMInputField(
                    label: "PEM Certificate (input)",
                    placeholder: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
                    text: $inputPEM
                )

                ActionButton(
                    title: "Convert",
                    icon: "arrow.2.squarepath",
                    action: convert,
                    disabled: inputPEM.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                )

                if let error = error { ErrorText(error: error) }

                if !outputDER.isEmpty {
                    InfoCard(title: "DER — Base64 Encoded") {
                        AnyView(VStack(alignment: .leading, spacing: 8) {
                            Text("Save/paste as a .cer or .der file (binary when decoded from Base64)")
                                .font(.system(size: 10)).foregroundColor(.secondary)
                            Text(outputDER)
                                .font(.system(size: 10, design: .monospaced))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                            CopyButton(text: outputDER)
                        })
                    }
                }

                if !outputPKCS7.isEmpty {
                    InfoCard(title: "PKCS#7 / P7B (PEM)") {
                        AnyView(VStack(alignment: .leading, spacing: 8) {
                            Text("Compatible with IIS, Java keystores, and most Windows tools")
                                .font(.system(size: 10)).foregroundColor(.secondary)
                            Text(outputPKCS7)
                                .font(.system(size: 10, design: .monospaced))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                            CopyButton(text: outputPKCS7)
                        })
                    }
                }
            }
            .padding()
        }
    }

    private func convert() {
        error = nil; outputDER = ""; outputPKCS7 = ""
        do {
            let derData = try OpenSSLHelper.shared.convertCertToDER(inputPEM)
            outputDER = derData.base64EncodedString(options: [.lineLength64Characters])
            outputPKCS7 = (try? OpenSSLHelper.shared.convertCertToPKCS7(inputPEM)) ?? ""
        } catch {
            self.error = error.localizedDescription
        }
    }
}

// MARK: - RoundedCorner helper (corners on specific sides only)

private extension View {
    func cornerRadius(_ radius: CGFloat, corners: RectCorner) -> some View {
        clipShape(RoundedCornerShape(radius: radius, corners: corners))
    }
}

private struct RoundedCornerShape: Shape {
    var radius: CGFloat
    var corners: RectCorner

    func path(in rect: CGRect) -> Path {
        let tl = corners.contains(.topLeft)
        let tr = corners.contains(.topRight)
        let bl = corners.contains(.bottomLeft)
        let br = corners.contains(.bottomRight)
        var path = Path()
        path.move(to: CGPoint(x: rect.minX + (tl ? radius : 0), y: rect.minY))
        path.addLine(to: CGPoint(x: rect.maxX - (tr ? radius : 0), y: rect.minY))
        if tr { path.addArc(center: CGPoint(x: rect.maxX - radius, y: rect.minY + radius), radius: radius, startAngle: .degrees(-90), endAngle: .degrees(0), clockwise: false) }
        path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY - (br ? radius : 0)))
        if br { path.addArc(center: CGPoint(x: rect.maxX - radius, y: rect.maxY - radius), radius: radius, startAngle: .degrees(0), endAngle: .degrees(90), clockwise: false) }
        path.addLine(to: CGPoint(x: rect.minX + (bl ? radius : 0), y: rect.maxY))
        if bl { path.addArc(center: CGPoint(x: rect.minX + radius, y: rect.maxY - radius), radius: radius, startAngle: .degrees(90), endAngle: .degrees(180), clockwise: false) }
        path.addLine(to: CGPoint(x: rect.minX, y: rect.minY + (tl ? radius : 0)))
        if tl { path.addArc(center: CGPoint(x: rect.minX + radius, y: rect.minY + radius), radius: radius, startAngle: .degrees(180), endAngle: .degrees(270), clockwise: false) }
        path.closeSubpath()
        return path
    }
}

struct RectCorner: OptionSet {
    let rawValue: Int
    static let topLeft     = RectCorner(rawValue: 1 << 0)
    static let topRight    = RectCorner(rawValue: 1 << 1)
    static let bottomLeft  = RectCorner(rawValue: 1 << 2)
    static let bottomRight = RectCorner(rawValue: 1 << 3)
    static let all: RectCorner = [.topLeft, .topRight, .bottomLeft, .bottomRight]
}
