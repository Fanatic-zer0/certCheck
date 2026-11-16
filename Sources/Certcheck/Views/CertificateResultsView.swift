import SwiftUI

struct CertificateResultsView: View {
    let info: CertInfo
    let validity: CertificateValidity

    var body: some View {
        LazyVStack(alignment: .leading, spacing: 24) {
            summary
            resultSection("Subject", icon: "person.text.rectangle") {
                distinguishedName(info.subject)
            }
            resultSection("Issuer", icon: "building.2") {
                distinguishedName(info.issuer)
            }
            resultSection("Validity", icon: "calendar") {
                resultRow("Not Before", value: validity.notBeforeText)
                resultRow("Not After", value: validity.notAfterText)
            }
            resultSection("Certificate Details", icon: "doc.text") {
                resultRow("Version", value: "\(info.version)")
                resultRow("Serial Number", value: info.serial)
                resultRow("Signature Algorithm", value: info.signatureAlg)
                resultRow("Public Key", value: "\(info.publicKey.type) (\(info.publicKey.bits) bits)")
                resultRow("Certificate Type", value: info.certType.label)
            }
            if !info.san.isEmpty {
                resultSection("Subject Alternative Names (\(info.san.count))", icon: "network") {
                    ForEach(info.san.indices, id: \.self) { index in
                        resultRow("Name \(index + 1)", value: info.san[index])
                    }
                }
            }
            resultSection("Extensions (\(info.extensions.count))", icon: "list.bullet.rectangle") {
                if let warning = info.extensionWarning {
                    Label(warning, systemImage: "exclamationmark.triangle")
                        .font(.system(size: 12))
                        .foregroundStyle(.orange)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.vertical, 12)
                } else if info.extensions.isEmpty {
                    Text("No X.509 extensions present")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .padding(.vertical, 12)
                }
                ForEach(info.extensions.indices, id: \.self) { index in
                    let item = info.extensions[index]
                    resultRow(item.critical ? "\(item.name) (Critical)" : item.name, value: item.value)
                }
            }
            resultSection("Fingerprints", icon: "touchid") {
                resultRow("SHA-256", value: info.fingerprints.sha256)
                resultRow("SHA-1", value: info.fingerprints.sha1)
                resultRow("MD5", value: info.fingerprints.md5)
                resultRow("Public Key SHA-256", value: info.fingerprints.spkiSha256)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var summary: some View {
        VStack(alignment: .leading, spacing: 12) {
            Divider()
            Text("Decoded Certificate")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(.secondary)
            ViewThatFits(in: .horizontal) {
                HStack(alignment: .top, spacing: 20) {
                    summaryIdentity.fixedSize(horizontal: true, vertical: false)
                    Spacer(minLength: 12)
                    validitySummary.fixedSize(horizontal: true, vertical: false)
                }
                VStack(alignment: .leading, spacing: 12) {
                    summaryIdentity
                    validitySummary.frame(maxWidth: .infinity, alignment: .trailing)
                }
            }
        }
    }

    private var summaryIdentity: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(info.subject.first { $0.key == "CN" }?.value ?? info.san.first ?? "X.509 Certificate")
                .font(.title3.bold())
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            ViewThatFits(in: .horizontal) {
                HStack(spacing: 16) { summaryLabels }
                VStack(alignment: .leading, spacing: 8) { summaryLabels }
            }
            .font(.system(size: 12, weight: .medium))
        }
    }

    private var validitySummary: some View {
        TimelineView(.periodic(from: .now, by: 60)) { context in
            let status = validity.status(at: context.date)
            VStack(alignment: .trailing, spacing: 6) {
                Label(status.rawValue, systemImage: status == .valid ? "calendar.badge.checkmark" : "exclamationmark.triangle")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(status == .valid ? Color.green : status == .expired ? Color.red : Color.orange)
                    .help("Certificate dates only; trust and hostname have not been verified")
                Text(validity.notAfter == nil
                     ? "Expiry Date Unavailable"
                     : "\(status == .expired ? "Expired" : "Expires"): \(validity.notAfterText)")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .multilineTextAlignment(.trailing)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    @ViewBuilder
    private var summaryLabels: some View {
        Label(info.certType.label, systemImage: info.certType.icon)
        Label("\(info.publicKey.type) \(info.publicKey.bits) bits", systemImage: "key")
    }

    private func resultSection<Content: View>(_ title: String, icon: String,
                                              @ViewBuilder content: () -> Content) -> some View {
        LazyVStack(alignment: .leading, spacing: 0) {
            Label(title, systemImage: icon)
                .font(.system(size: 13, weight: .semibold))
                .padding(.bottom, 10)
            Divider()
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    @ViewBuilder
    private func distinguishedName(_ name: OrderedDN) -> some View {
        if name.isEmpty {
            resultRow("Distinguished Name", value: "Not present")
        } else {
            ForEach(name.indices, id: \.self) { index in
                let field = name[index]
                resultRow(dnLabel(field.key), value: field.value)
            }
        }
    }

    private func dnLabel(_ key: String) -> String {
        switch key {
        case "CN": return "Common Name (CN)"
        case "O": return "Organization (O)"
        case "OU": return "Organizational Unit (OU)"
        case "C": return "Country (C)"
        case "ST": return "State / Province (ST)"
        case "L": return "Locality (L)"
        default: return key
        }
    }

    private func resultRow(_ label: String, value: String) -> some View {
        FieldRow(label: label, value: value.isEmpty ? "Not available" : value)
            .padding(.horizontal, 10)
            .padding(.vertical, 4)
            .background(Color(nsColor: .controlBackgroundColor).opacity(0.6))
            .overlay(alignment: .bottom) { Divider() }
    }
}
