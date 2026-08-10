import SwiftUI

struct CertDecodeView: View {
    @State private var inputPEM = ""
    @State private var certInfo: CertInfo?
    @State private var error: String?
    @State private var isLoading = false
    
    private var isExpired: Bool {
        guard let info = certInfo,
              let date = ISO8601DateFormatter().date(from: info.notAfter) else {
            return false
        }
        return date < Date()
    }
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack(spacing: 10) {
                    Image(systemName: "doc.text.magnifyingglass")
                        .font(.title2)
                        .foregroundColor(Color(hue: 0.68, saturation: 0.70, brightness: 0.75))
                    Text("Certificate Decoder")
                        .font(.title2.bold())
                }
                
                Text("Decode and inspect X.509 certificates in PEM format")
                    .font(.caption)
                    .foregroundColor(.secondary)
                
                PEMInputField(
                    label: "PEM Certificate",
                    placeholder: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
                    text: $inputPEM
                )
                
                HStack(spacing: 12) {
                    ActionButton(
                        title: "Parse Certificate",
                        icon: "magnifyingglass",
                        action: parseCert,
                        disabled: inputPEM.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                    )
                    
                    if certInfo != nil {
                        HStack(spacing: 4) {
                            Image(systemName: isExpired ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                                .foregroundColor(isExpired ? .red : .green)
                            Text(isExpired ? "Expired" : "Valid")
                                .font(.system(size: 11, weight: .semibold))
                        }
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                        .background(
                            Capsule()
                                .fill(isExpired ? Color.red.opacity(0.12) : Color.green.opacity(0.12))
                        )
                    }
                }
                
                if let error = error {
                    ErrorText(error: error)
                }
                
                if let info = certInfo {
                    certDetailView(info)
                }
            }
            .padding()
        }
    }
    
    @ViewBuilder
    private func certDetailView(_ info: CertInfo) -> some View {
        VStack(spacing: 16) {
            // Subject
            InfoCard(title: "Subject") {
                AnyView(
                    VStack(spacing: 4) {
                        if info.subject.isEmpty {
                            FieldRow(label: "—", value: "(no subject fields)")
                        } else {
                            ForEach(info.subject.indices, id: \.self) { idx in
                                FieldRow(label: info.subject[idx].key, value: info.subject[idx].value)
                            }
                        }
                    }
                )
            }
            
            // Issuer
            InfoCard(title: "Issuer") {
                AnyView(
                    VStack(spacing: 4) {
                        if info.issuer.isEmpty {
                            FieldRow(label: "—", value: "(no issuer fields)")
                        } else {
                            ForEach(info.issuer.indices, id: \.self) { idx in
                                FieldRow(label: info.issuer[idx].key, value: info.issuer[idx].value)
                            }
                        }
                    }
                )
            }
            
            // Properties
            InfoCard(title: "Properties") {
                AnyView(
                    VStack(spacing: 4) {
                        FieldRow(label: "Version", value: "v\(info.version)")
                        FieldRow(label: "Serial", value: info.serial)
                        FieldRow(label: "Signature Alg", value: info.signatureAlg)
                        FieldRow(label: "Public Key", value: "\(info.publicKey.type) (\(info.publicKey.bits) bits)")
                        FieldRow(label: "Not Before", value: formatDate(info.notBefore))
                        FieldRow(label: "Not After", value: formatDate(info.notAfter) + (isExpired ? " ⚠ EXPIRED" : ""))
                    }
                )
            }
            
            // Extensions
            if !info.extensions.isEmpty {
                InfoCard(title: "Certificate Extensions (\(info.extensions.count))") {
                    AnyView(
                        VStack(spacing: 4) {
                            ForEach(info.extensions.indices, id: \.self) { idx in
                                let ext = info.extensions[idx]
                                FieldRow(
                                    label: ext.name,
                                    value: (ext.critical ? "[Critical] " : "") + ext.value
                                )
                            }
                        }
                    )
                }
            }
            
            // SANs
            if !info.san.isEmpty {
                InfoCard(title: "Subject Alternative Names") {
                    AnyView(
                        VStack(spacing: 4) {
                            ForEach(info.san.indices, id: \.self) { idx in
                                FieldRow(label: idx == 0 ? "SAN" : "", value: info.san[idx])
                            }
                        }
                    )
                }
            }
            
            // Fingerprints
            InfoCard(title: "Certificate Fingerprints") {
                AnyView(
                    VStack(spacing: 4) {
                        FieldRow(label: "MD5", value: info.fingerprints.md5)
                        FieldRow(label: "SHA-1", value: info.fingerprints.sha1)
                        FieldRow(label: "SHA-256", value: info.fingerprints.sha256)
                        FieldRow(label: "SPKI SHA256", value: info.fingerprints.spkiSha256)
                    }
                )
            }
        }
    }
    
    private func parseCert() {
        isLoading = true
        error = nil
        certInfo = nil
        
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let info = try CertService.shared.parseCertificate(pem: inputPEM)
                DispatchQueue.main.async {
                    self.certInfo = info
                    self.isLoading = false
                }
            } catch {
                DispatchQueue.main.async {
                    self.error = error.localizedDescription
                    self.isLoading = false
                }
            }
        }
    }
    
    private func formatDate(_ iso: String) -> String {
        guard let date = ISO8601DateFormatter().date(from: iso) else {
            return iso
        }
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter.string(from: date)
    }
}

struct CSRDecodeView: View {
    @State private var inputPEM = ""
    @State private var csrInfo: CSRInfo?
    @State private var error: String?
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack(spacing: 10) {
                    Image(systemName: "key.viewfinder")
                        .font(.title2)
                        .foregroundColor(Color(hue: 0.68, saturation: 0.70, brightness: 0.75))
                    Text("CSR Decoder")
                        .font(.title2.bold())
                }
                
                Text("Decode and inspect Certificate Signing Requests (CSR) in PEM format")
                    .font(.caption)
                    .foregroundColor(.secondary)
                
                PEMInputField(
                    label: "PEM Certificate Signing Request (CSR)",
                    placeholder: "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----",
                    text: $inputPEM
                )
                
                HStack(spacing: 12) {
                    ActionButton(
                        title: "Parse CSR",
                        icon: "magnifyingglass",
                        action: parseCSR,
                        disabled: inputPEM.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                    )
                    
                    if let info = csrInfo {
                        HStack(spacing: 4) {
                            Image(systemName: info.selfSigValid == true ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                                .foregroundColor(info.selfSigValid == true ? .green : .orange)
                            Text(info.selfSigValid == true ? "Signature Valid" : "Signature Unverified")
                                .font(.system(size: 11, weight: .semibold))
                        }
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                        .background(
                            Capsule()
                                .fill(info.selfSigValid == true ? Color.green.opacity(0.12) : Color.orange.opacity(0.12))
                        )
                    }
                }
                
                if let error = error {
                    ErrorText(error: error)
                }
                
                if let info = csrInfo {
                    csrDetailView(info)
                }
            }
            .padding()
        }
    }
    
    @ViewBuilder
    private func csrDetailView(_ info: CSRInfo) -> some View {
        VStack(spacing: 16) {
            InfoCard(title: "Subject") {
                AnyView(
                    VStack(spacing: 4) {
                        if info.subject.isEmpty {
                            FieldRow(label: "—", value: "(empty)")
                        } else {
                            ForEach(info.subject.indices, id: \.self) { idx in
                                FieldRow(label: info.subject[idx].key, value: info.subject[idx].value)
                            }
                        }
                    }
                )
            }
            
            InfoCard(title: "Public Key") {
                AnyView(
                    VStack(spacing: 4) {
                        FieldRow(label: "Algorithm", value: info.publicKey.type)
                        FieldRow(label: "Key Size", value: "\(info.publicKey.bits) bits")
                        FieldRow(label: "Signature Alg", value: info.signatureAlg)
                    }
                )
            }
            
            if !info.sans.isEmpty {
                InfoCard(title: "Subject Alternative Names (Requested)") {
                    AnyView(
                        VStack(spacing: 4) {
                            ForEach(info.sans.indices, id: \.self) { idx in
                                FieldRow(label: idx == 0 ? "SAN" : "", value: info.sans[idx])
                            }
                        }
                    )
                }
            }
            
            if !info.extensions.isEmpty {
                InfoCard(title: "Requested Extensions") {
                    AnyView(
                        VStack(spacing: 4) {
                            ForEach(info.extensions.indices, id: \.self) { idx in
                                let ext = info.extensions[idx]
                                FieldRow(label: ext.name, value: ext.value)
                            }
                        }
                    )
                }
            }
            
            InfoCard(title: "Fingerprints") {
                AnyView(
                    VStack(spacing: 4) {
                        FieldRow(label: "MD5", value: info.fingerprints.md5)
                        FieldRow(label: "SHA-1", value: info.fingerprints.sha1)
                        FieldRow(label: "SHA-256", value: info.fingerprints.sha256)
                    }
                )
            }
        }
    }
    
    private func parseCSR() {
        error = nil
        csrInfo = nil
        
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let info = try CertService.shared.parseCSR(pem: inputPEM)
                DispatchQueue.main.async {
                    self.csrInfo = info
                }
            } catch {
                DispatchQueue.main.async {
                    self.error = error.localizedDescription
                }
            }
        }
    }
}
