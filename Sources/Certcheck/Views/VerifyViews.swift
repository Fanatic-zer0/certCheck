import SwiftUI

struct CertKeyView: View {
    @State private var certPEM = ""
    @State private var keyPEM = ""
    @State private var result: (match: Bool, detail: String)?
    @State private var error: String?
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Certificate ↔ Key Match")
                    .font(.title2.bold())
                
                Text("Verify that a certificate's public key matches the corresponding private key")
                    .font(.caption)
                    .foregroundColor(.secondary)
                
                PEMInputField(
                    label: "Certificate (PEM)",
                    placeholder: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
                    text: $certPEM
                )
                
                PEMInputField(
                    label: "Private Key (PEM)",
                    placeholder: "-----BEGIN RSA PRIVATE KEY-----\nor\n-----BEGIN PRIVATE KEY-----\n...",
                    text: $keyPEM
                )
                
                ActionButton(
                    title: "Check Match",
                    icon: "checkmark.circle",
                    action: checkMatch,
                    disabled: certPEM.isEmpty || keyPEM.isEmpty
                )
                
                if let error = error {
                    ErrorText(error: error)
                }
                
                if let result = result {
                    MatchBadge(
                        match: result.match,
                        yesText: "Certificate and Private Key MATCH ✓",
                        noText: "Certificate and Private Key do NOT match ✗"
                    )
                    
                    Text(result.detail)
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                        .padding()
                }
            }
            .padding()
        }
    }
    
    private func checkMatch() {
        error = nil
        result = nil
        
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let res = try CertService.shared.matchCertificateWithKey(certPEM: certPEM, keyPEM: keyPEM)
                DispatchQueue.main.async {
                    self.result = res
                }
            } catch {
                DispatchQueue.main.async {
                    self.error = error.localizedDescription
                }
            }
        }
    }
}

struct CertCSRView: View {
    @State private var certPEM = ""
    @State private var csrPEM = ""
    @State private var result: CSRMatchResult?
    @State private var error: String?
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Certificate ↔ CSR Match")
                    .font(.title2.bold())
                
                Text("Verify that a certificate was issued from a given CSR")
                    .font(.caption)
                    .foregroundColor(.secondary)
                
                PEMInputField(
                    label: "Certificate (PEM)",
                    placeholder: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
                    text: $certPEM
                )
                
                PEMInputField(
                    label: "Certificate Signing Request (PEM)",
                    placeholder: "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----",
                    text: $csrPEM
                )
                
                ActionButton(
                    title: "Check Match",
                    icon: "checkmark.circle",
                    action: checkMatch,
                    disabled: certPEM.isEmpty || csrPEM.isEmpty
                )
                
                if let error = error {
                    ErrorText(error: error)
                }
                
                if let result = result {
                    VStack(spacing: 12) {
                        MatchBadge(
                            match: result.publicKeyMatch && result.subjectMatch,
                            yesText: "Certificate and CSR MATCH ✓",
                            noText: "Certificate and CSR do NOT match ✗"
                        )
                        
                        InfoCard(title: "Match Details") {
                            AnyView(
                                VStack(spacing: 8) {
                                    HStack {
                                        Image(systemName: result.publicKeyMatch ? "checkmark.circle.fill" : "xmark.circle.fill")
                                            .foregroundColor(result.publicKeyMatch ? .green : .red)
                                        Text("Public Key: \(result.publicKeyMatch ? "Match" : "Mismatch")")
                                            .font(.system(size: 11))
                                    }
                                    
                                    HStack {
                                        Image(systemName: result.subjectMatch ? "checkmark.circle.fill" : "xmark.circle.fill")
                                            .foregroundColor(result.subjectMatch ? .green : .red)
                                        Text("Subject: \(result.subjectMatch ? "Match" : "Mismatch")")
                                            .font(.system(size: 11))
                                    }
                                    
                                    Divider()
                                    
                                    FieldRow(label: "Cert Subject", value: result.certSubject)
                                    FieldRow(label: "CSR Subject", value: result.csrSubject)
                                }
                            )
                        }
                    }
                }
            }
            .padding()
        }
    }
    
    private func checkMatch() {
        error = nil
        result = nil
        
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let res = try CertService.shared.matchCertificateWithCSR(certPEM: certPEM, csrPEM: csrPEM)
                DispatchQueue.main.async {
                    self.result = res
                }
            } catch {
                DispatchQueue.main.async {
                    self.error = error.localizedDescription
                }
            }
        }
    }
}

struct CSRKeyView: View {
    @State private var csrPEM = ""
    @State private var keyPEM = ""
    @State private var result: (match: Bool, detail: String)?
    @State private var error: String?
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("CSR ↔ Key Match")
                    .font(.title2.bold())
                
                Text("Verify that a CSR was created with a specific private key")
                    .font(.caption)
                    .foregroundColor(.secondary)
                
                PEMInputField(
                    label: "Certificate Signing Request (PEM)",
                    placeholder: "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----",
                    text: $csrPEM
                )
                
                PEMInputField(
                    label: "Private Key (PEM)",
                    placeholder: "-----BEGIN RSA PRIVATE KEY-----\nor\n-----BEGIN PRIVATE KEY-----\n...",
                    text: $keyPEM
                )
                
                ActionButton(
                    title: "Check Match",
                    icon: "checkmark.circle",
                    action: checkMatch,
                    disabled: csrPEM.isEmpty || keyPEM.isEmpty
                )
                
                if let error = error {
                    ErrorText(error: error)
                }
                
                if let result = result {
                    MatchBadge(
                        match: result.match,
                        yesText: "CSR and Private Key MATCH ✓",
                        noText: "CSR and Private Key do NOT match ✗"
                    )
                    
                    Text(result.detail)
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                        .padding()
                }
            }
            .padding()
        }
    }
    
    private func checkMatch() {
        error = nil
        result = nil
        
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let res = try CertService.shared.matchCSRWithKey(csrPEM: csrPEM, keyPEM: keyPEM)
                DispatchQueue.main.async {
                    self.result = res
                }
            } catch {
                DispatchQueue.main.async {
                    self.error = error.localizedDescription
                }
            }
        }
    }
}

struct ChainVerifyView: View {
    @State private var chainPEM = ""
    @State private var links: [ChainLink] = []
    @State private var error: String?
    
    private var overallValid: Bool {
        !links.isEmpty && links.allSatisfy { link in
            link.issuerChainOk &&
            (link.signatureOk ?? true) &&
            (ISO8601DateFormatter().date(from: link.notAfter).map { $0 >= Date() } ?? true)
        }
    }
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Chain Verification")
                    .font(.title2.bold())
                
                Text("Paste the full certificate chain (leaf first, then intermediates, then root CA)")
                    .font(.caption)
                    .foregroundColor(.secondary)
                
                VStack(alignment: .leading, spacing: 4) {
                    Text("Certificate Chain (PEM — one or more certs)")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(.secondary)
                    
                    TextEditor(text: $chainPEM)
                        .font(.system(size: 10, design: .monospaced))
                        .frame(height: 200)
                        .padding(6)
                        .background(Color(nsColor: .textBackgroundColor))
                        .cornerRadius(6)
                        .overlay(
                            RoundedRectangle(cornerRadius: 6)
                                .stroke(Color.secondary.opacity(0.2), lineWidth: 1)
                        )
                }
                
                ActionButton(
                    title: "Verify Chain",
                    icon: "shield.checkered",
                    action: verifyChain,
                    disabled: chainPEM.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                )
                
                if let error = error {
                    ErrorText(error: error)
                }
                
                if !links.isEmpty {
                    MatchBadge(
                        match: overallValid,
                        yesText: "Chain is valid (\(links.count) certificate\(links.count > 1 ? "s" : "")) ✓",
                        noText: "Chain has issues — see details below ✗"
                    )
                    
                    ForEach(links) { link in
                        chainLinkView(link)
                    }
                }
            }
            .padding()
        }
    }
    
    @ViewBuilder
    private func chainLinkView(_ link: ChainLink) -> some View {
        let isExpired = ISO8601DateFormatter().date(from: link.notAfter).map { $0 < Date() } ?? false
        
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(linkLabel(link.index, link.selfSigned))
                    .font(.system(size: 11, weight: .bold))
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(
                        Capsule()
                            .fill(Color.accentColor)
                    )
                    .foregroundColor(.white)
                
                if isExpired {
                    Text("Expired")
                        .font(.system(size: 10, weight: .semibold))
                        .padding(.horizontal, 6)
                        .padding(.vertical, 3)
                        .background(Capsule().fill(Color.red.opacity(0.15)))
                        .foregroundColor(.red)
                }
                
                if link.selfSigned {
                    Text("Self-signed")
                        .font(.system(size: 10, weight: .semibold))
                        .padding(.horizontal, 6)
                        .padding(.vertical, 3)
                        .background(Capsule().fill(Color.blue.opacity(0.15)))
                        .foregroundColor(.blue)
                }
            }
            
            VStack(spacing: 4) {
                FieldRow(label: "Subject", value: link.subject)
                FieldRow(label: "Issuer", value: link.issuer)
                FieldRow(label: "Not After", value: formatDate(link.notAfter) + (isExpired ? " ⚠" : ""))
                
                HStack(spacing: 16) {
                    HStack(spacing: 4) {
                        Image(systemName: link.issuerChainOk ? "checkmark.circle.fill" : "xmark.circle.fill")
                            .foregroundColor(link.issuerChainOk ? .green : .red)
                            .font(.system(size: 10))
                        Text("Issuer chain")
                            .font(.system(size: 10))
                            .foregroundColor(.secondary)
                    }
                    
                    if let sigOk = link.signatureOk {
                        HStack(spacing: 4) {
                            Image(systemName: sigOk ? "checkmark.circle.fill" : "xmark.circle.fill")
                                .foregroundColor(sigOk ? .green : .red)
                                .font(.system(size: 10))
                            Text("Signature")
                                .font(.system(size: 10))
                                .foregroundColor(.secondary)
                        }
                    }
                }
                .padding(.top, 4)
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(Color(nsColor: .controlBackgroundColor))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color.secondary.opacity(0.2), lineWidth: 1)
        )
    }
    
    private func linkLabel(_ index: Int, _ selfSigned: Bool) -> String {
        if index == 0 { return "Leaf" }
        if selfSigned { return "Root CA" }
        return "Intermediate \(index)"
    }
    
    private func verifyChain() {
        error = nil
        links = []
        
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let result = try CertService.shared.verifyChain(chainPEM: chainPEM)
                DispatchQueue.main.async {
                    self.links = result
                }
            } catch {
                DispatchQueue.main.async {
                    self.error = error.localizedDescription
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
