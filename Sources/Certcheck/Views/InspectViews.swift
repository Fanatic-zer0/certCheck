import SwiftUI

struct CertDecodeView: View {
    @Environment(\.updateSessionResourceName) private var updateSessionResourceName
    @State private var inputPEM = ""
    @State private var certInfo: CertInfo?
    @State private var error: String?
    @State private var isLoading = false
    @State private var validity: CertificateValidity?
    @State private var activeRequestID: UUID?
    @State private var inputExpanded = true
    
    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 20) {
                HStack(spacing: 10) {
                    Image(systemName: "doc.text.magnifyingglass")
                        .font(.title2)
                        .foregroundStyle(.teal)
                    Text("Certificate Decoder")
                        .font(.title2.bold())
                    Spacer()
                    Button {
                        reset()
                        inputPEM = ""
                        inputExpanded = true
                    } label: {
                        Image(systemName: "trash")
                    }
                    .help("Clear Certificate")
                    .accessibilityLabel("Clear Certificate")
                    .disabled(inputPEM.isEmpty && certInfo == nil && !isLoading)
                }

                DisclosureGroup("PEM Certificate", isExpanded: $inputExpanded) {
                    VStack(alignment: .leading, spacing: 12) {
                        PEMInputField(
                            label: "X.509 Certificate",
                            placeholder: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
                            text: $inputPEM
                        )
                        HStack(spacing: 12) {
                            ActionButton(
                                title: isLoading ? "Decoding..." : "Decode Certificate",
                                icon: "magnifyingglass",
                                action: parseCert,
                                disabled: isLoading || inputPEM.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                            )
                            if isLoading {
                                ProgressView().controlSize(.small)
                                    .accessibilityLabel("Decoding certificate")
                            }
                        }
                    }
                    .padding(.top, 10)
                }
                .font(.system(size: 12, weight: .semibold))

                if let error = error {
                    ErrorText(error: error)
                }

                if let info = certInfo, let validity {
                    CertificateResultsView(info: info, validity: validity)
                }
            }
            .padding(4)
        }
        .onChange(of: inputPEM) { _ in
            reset()
        }
        .onDisappear {
            activeRequestID = nil
            isLoading = false
        }
    }
    
    private func parseCert() {
        guard !isLoading else { return }
        let pem = inputPEM
        let requestID = UUID()
        activeRequestID = requestID
        isLoading = true
        error = nil
        certInfo = nil
        validity = nil
        updateSessionResourceName([], [])
        
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let info = try CertService.shared.parseCertificate(pem: pem)
                let dates = CertificateValidity(notBefore: info.notBefore, notAfter: info.notAfter)
                DispatchQueue.main.async {
                    guard self.activeRequestID == requestID else { return }
                    self.certInfo = info
                    self.validity = dates
                    self.isLoading = false
                    self.activeRequestID = nil
                    self.inputExpanded = false
                    self.updateSessionResourceName(info.subject, info.san)
                }
            } catch {
                DispatchQueue.main.async {
                    guard self.activeRequestID == requestID else { return }
                    self.error = error.localizedDescription
                    self.isLoading = false
                    self.activeRequestID = nil
                }
            }
        }
    }

    private func reset() {
        activeRequestID = nil
        certInfo = nil
        validity = nil
        error = nil
        isLoading = false
        updateSessionResourceName([], [])
    }
}

struct CSRDecodeView: View {
    @Environment(\.updateSessionResourceName) private var updateSessionResourceName
    @State private var inputPEM = ""
    @State private var csrInfo: CSRInfo?
    @State private var error: String?
    @State private var isLoading = false
    @State private var activeRequestID: UUID?
    
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
                        title: isLoading ? "Decoding..." : "Parse CSR",
                        icon: "magnifyingglass",
                        action: parseCSR,
                        disabled: isLoading || inputPEM.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                    )

                    if isLoading {
                        ProgressView().controlSize(.small)
                            .accessibilityLabel("Decoding CSR")
                    }
                    
                    if let info = csrInfo {
                        HStack(spacing: 4) {
                            Image(systemName: signatureIcon(info.selfSigValid))
                                .foregroundColor(signatureColor(info.selfSigValid))
                            Text(signatureLabel(info.selfSigValid))
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
        .onChange(of: inputPEM) { _ in
            activeRequestID = nil
            csrInfo = nil
            error = nil
            isLoading = false
            updateSessionResourceName([], [])
        }
        .onDisappear {
            activeRequestID = nil
            isLoading = false
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
                                FieldRow(label: ext.critical ? "\(ext.name) (Critical)" : ext.name, value: ext.value)
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
        guard !isLoading else { return }
        let pem = inputPEM
        let requestID = UUID()
        activeRequestID = requestID
        isLoading = true
        error = nil
        csrInfo = nil
        updateSessionResourceName([], [])
        
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let info = try CertService.shared.parseCSR(pem: pem)
                DispatchQueue.main.async {
                    guard self.activeRequestID == requestID else { return }
                    self.csrInfo = info
                    self.isLoading = false
                    self.activeRequestID = nil
                    self.updateSessionResourceName(info.subject, info.sans)
                }
            } catch {
                DispatchQueue.main.async {
                    guard self.activeRequestID == requestID else { return }
                    self.error = error.localizedDescription
                    self.isLoading = false
                    self.activeRequestID = nil
                }
            }
        }
    }

    private func signatureLabel(_ isValid: Bool?) -> String {
        switch isValid {
        case .some(true): return "Signature Valid"
        case .some(false): return "Signature Invalid"
        case .none: return "Signature Not Checked"
        }
    }

    private func signatureIcon(_ isValid: Bool?) -> String {
        isValid == true ? "checkmark.circle.fill" : "exclamationmark.triangle.fill"
    }

    private func signatureColor(_ isValid: Bool?) -> Color {
        isValid == true ? .green : isValid == false ? .red : .orange
    }
}
