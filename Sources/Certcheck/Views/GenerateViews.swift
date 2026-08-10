import SwiftUI

struct GenCSRView: View {
    @State private var subject = CertSubject()
    @State private var keyAlgo = KeyAlgoConfig()
    @State private var csrPEM = ""
    @State private var keyPEM = ""
    @State private var error: String?
    @State private var isGenerating = false
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Generate CSR + Key")
                    .font(.title2.bold())
                
                Text("Generate a Certificate Signing Request and private key")
                    .font(.caption)
                    .foregroundColor(.secondary)
                
                subjectFieldsView
                
                KeyAlgoSelectorView(config: $keyAlgo)
                
                ActionButton(
                    title: isGenerating ? "Generating..." : "Generate CSR + Key",
                    icon: "key.fill",
                    action: generate,
                    disabled: subject.cn.isEmpty || isGenerating
                )
                
                if let error = error {
                    ErrorText(error: error)
                }
                
                if !csrPEM.isEmpty {
                    pemOutputView(label: "Certificate Signing Request (CSR)", pem: csrPEM, filename: "request.csr")
                }
                
                if !keyPEM.isEmpty {
                    pemOutputView(label: "Private Key (keep secret!)", pem: keyPEM, filename: "private.key")
                }
            }
            .padding()
        }
    }
    
    @ViewBuilder
    private var subjectFieldsView: some View {
        GroupBox {
            VStack(spacing: 10) {
                HStack {
                    Text("Common Name (CN) *")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(.secondary)
                        .frame(width: 140, alignment: .trailing)
                    TextField("example.com", text: $subject.cn)
                        .textFieldStyle(.roundedBorder)
                }
                
                HStack {
                    Text("Organization (O)")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(.secondary)
                        .frame(width: 140, alignment: .trailing)
                    TextField("My Company Ltd", text: $subject.org)
                        .textFieldStyle(.roundedBorder)
                }
                
                HStack {
                    Text("Org Unit (OU)")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(.secondary)
                        .frame(width: 140, alignment: .trailing)
                    TextField("Engineering", text: $subject.ou)
                        .textFieldStyle(.roundedBorder)
                }
                
                HStack {
                    Text("Country (2-letter)")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(.secondary)
                        .frame(width: 140, alignment: .trailing)
                    TextField("US", text: $subject.country)
                        .textFieldStyle(.roundedBorder)
                }
                
                HStack {
                    Text("State / Province")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(.secondary)
                        .frame(width: 140, alignment: .trailing)
                    TextField("California", text: $subject.state)
                        .textFieldStyle(.roundedBorder)
                }
                
                HStack {
                    Text("Locality / City")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(.secondary)
                        .frame(width: 140, alignment: .trailing)
                    TextField("San Francisco", text: $subject.locality)
                        .textFieldStyle(.roundedBorder)
                }
                
                HStack(alignment: .top) {
                    Text("SANs (comma-sep)")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(.secondary)
                        .frame(width: 140, alignment: .trailing)
                    TextField("www.example.com, api.example.com", text: Binding(
                        get: { subject.san.joined(separator: ", ") },
                        set: { subject.san = $0.split(separator: ",").map { String($0.trimmingCharacters(in: .whitespaces)) } }
                    ))
                    .textFieldStyle(.roundedBorder)
                }
            }
        } label: {
            Text("Subject Information")
                .font(.system(size: 12, weight: .semibold))
        }
    }
    
    @ViewBuilder
    private func pemOutputView(label: String, pem: String, filename: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(label)
                    .font(.system(size: 13, weight: .semibold))
                Spacer()
                CopyButton(text: pem)
                DownloadButton(filename: filename, content: pem)
            }
            
            ScrollView(.horizontal) {
                Text(pem)
                    .font(.system(size: 9, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(8)
            }
            .frame(height: 100)
            .background(Color(nsColor: .textBackgroundColor))
            .cornerRadius(6)
            .overlay(
                RoundedRectangle(cornerRadius: 6)
                    .stroke(Color.secondary.opacity(0.2), lineWidth: 1)
            )
        }
    }
    
    private func generate() {
        isGenerating = true
        error = nil
        csrPEM = ""
        keyPEM = ""
        
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let result = try CertService.shared.generateCSR(subject: subject, keyAlgo: keyAlgo)
                DispatchQueue.main.async {
                    self.csrPEM = result.csr
                    self.keyPEM = result.key
                    self.isGenerating = false
                }
            } catch {
                DispatchQueue.main.async {
                    self.error = error.localizedDescription
                    self.isGenerating = false
                }
            }
        }
    }
}

struct GenCertView: View {
    @State private var certType: CertType = .selfSigned
    @State private var subject = CertSubject()
    @State private var keyAlgo = KeyAlgoConfig()
    @State private var validDays = "365"
    @State private var caCertPEM = ""
    @State private var caKeyPEM = ""
    @State private var csrPEM = ""
    @State private var certOut = ""
    @State private var keyOut = ""
    @State private var error: String?
    @State private var isGenerating = false
    
    private var needsSubject: Bool {
        certType != .caSigned
    }
    
    private var needsCA: Bool {
        certType == .caSigned || certType == .intermediateCA
    }
    
    private var needsCSR: Bool {
        certType == .caSigned
    }
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Generate Certificate")
                    .font(.title2.bold())
                
                Text("Create self-signed, CA, or CA-signed certificates")
                    .font(.caption)
                    .foregroundColor(.secondary)
                
                // Certificate Type
                GroupBox {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(CertType.allCases, id: \.self) { type in
                            Button {
                                certType = type
                            } label: {
                                HStack {
                                    Image(systemName: certType == type ? "largecircle.fill.circle" : "circle")
                                        .foregroundColor(.accentColor)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(type.label)
                                            .font(.system(size: 12, weight: .medium))
                                        Text(type.description)
                                            .font(.system(size: 10))
                                            .foregroundColor(.secondary)
                                    }
                                    Spacer()
                                }
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                        }
                    }
                } label: {
                    Text("Certificate Type")
                        .font(.system(size: 12, weight: .semibold))
                }
                
                if needsSubject {
                    subjectFieldsView
                    KeyAlgoSelectorView(config: $keyAlgo)
                }
                
                HStack {
                    Text("Valid Days")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(.secondary)
                    TextField("365", text: $validDays)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 80)
                }
                
                if needsCA {
                    PEMInputField(label: "CA Certificate (PEM)", placeholder: "-----BEGIN CERTIFICATE-----\n...", text: $caCertPEM)
                    PEMInputField(label: "CA Private Key (PEM)", placeholder: "-----BEGIN RSA PRIVATE KEY-----\n...", text: $caKeyPEM)
                }
                
                if needsCSR {
                    PEMInputField(label: "CSR to Sign (PEM)", placeholder: "-----BEGIN CERTIFICATE REQUEST-----\n...", text: $csrPEM)
                }
                
                ActionButton(
                    title: isGenerating ? "Generating..." : "Generate Certificate",
                    icon: "checkmark.shield.fill",
                    action: generate,
                    disabled: isGenerating || (needsSubject && subject.cn.isEmpty)
                )
                
                if let error = error {
                    ErrorText(error: error)
                }
                
                if !certOut.isEmpty {
                    pemOutputView(label: "Certificate", pem: certOut, filename: "certificate.crt")
                }
                
                if !keyOut.isEmpty {
                    pemOutputView(label: "Private Key", pem: keyOut, filename: "private.key")
                }
            }
            .padding()
        }
    }
    
    @ViewBuilder
    private var subjectFieldsView: some View {
        GroupBox {
            VStack(spacing: 10) {
                HStack {
                    Text("Common Name (CN) *")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(.secondary)
                        .frame(width: 140, alignment: .trailing)
                    TextField("example.com", text: $subject.cn)
                        .textFieldStyle(.roundedBorder)
                }
                
                HStack {
                    Text("Organization (O)")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(.secondary)
                        .frame(width: 140, alignment: .trailing)
                    TextField("My Company Ltd", text: $subject.org)
                        .textFieldStyle(.roundedBorder)
                }
                
                HStack {
                    Text("Country (2-letter)")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(.secondary)
                        .frame(width: 140, alignment: .trailing)
                    TextField("US", text: $subject.country)
                        .textFieldStyle(.roundedBorder)
                }
                
                HStack(alignment: .top) {
                    Text("SANs (comma-sep)")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(.secondary)
                        .frame(width: 140, alignment: .trailing)
                    TextField("www.example.com, 192.168.1.1", text: Binding(
                        get: { subject.san.joined(separator: ", ") },
                        set: { subject.san = $0.split(separator: ",").map { String($0.trimmingCharacters(in: .whitespaces)) } }
                    ))
                    .textFieldStyle(.roundedBorder)
                }
            }
        } label: {
            Text("Subject Information")
                .font(.system(size: 12, weight: .semibold))
        }
    }
    
    @ViewBuilder
    private func pemOutputView(label: String, pem: String, filename: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(label)
                    .font(.system(size: 13, weight: .semibold))
                Spacer()
                CopyButton(text: pem)
                DownloadButton(filename: filename, content: pem)
            }
            
            ScrollView(.horizontal) {
                Text(pem)
                    .font(.system(size: 9, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(8)
            }
            .frame(height: 100)
            .background(Color(nsColor: .textBackgroundColor))
            .cornerRadius(6)
            .overlay(
                RoundedRectangle(cornerRadius: 6)
                    .stroke(Color.secondary.opacity(0.2), lineWidth: 1)
            )
        }
    }
    
    private func generate() {
        isGenerating = true
        error = nil
        certOut = ""
        keyOut = ""
        
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let result = try CertService.shared.generateCertificate(
                    type: certType,
                    subject: needsSubject ? subject : nil,
                    keyAlgo: keyAlgo,
                    validDays: Int(validDays) ?? 365,
                    caCertPEM: needsCA ? caCertPEM : nil,
                    caKeyPEM: needsCA ? caKeyPEM : nil,
                    csrPEM: needsCSR ? csrPEM : nil
                )
                DispatchQueue.main.async {
                    self.certOut = result.cert
                    self.keyOut = result.key
                    self.isGenerating = false
                }
            } catch {
                DispatchQueue.main.async {
                    self.error = error.localizedDescription
                    self.isGenerating = false
                }
            }
        }
    }
}

struct ToPFXView: View {
    @State private var certPEM = ""
    @State private var keyPEM = ""
    @State private var chainPEM = ""
    @State private var password = ""
    @State private var friendlyName = ""
    @State private var pfxData: Data?
    @State private var error: String?
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Export to PFX / P12")
                    .font(.title2.bold())
                
                Text("Bundle a certificate, private key, and optional chain into a PKCS#12 (.pfx / .p12) file")
                    .font(.caption)
                    .foregroundColor(.secondary)
                
                PEMInputField(label: "Certificate (PEM) *", placeholder: "-----BEGIN CERTIFICATE-----\n...", text: $certPEM)
                PEMInputField(label: "Private Key (PEM) *", placeholder: "-----BEGIN RSA PRIVATE KEY-----\n...", text: $keyPEM)
                PEMInputField(label: "Certificate Chain (PEM, optional)", placeholder: "-----BEGIN CERTIFICATE-----\n(intermediate)\n...", text: $chainPEM)
                
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Friendly Name (alias)")
                            .font(.system(size: 11, weight: .medium))
                            .foregroundColor(.secondary)
                        TextField("my-cert", text: $friendlyName)
                            .textFieldStyle(.roundedBorder)
                    }
                    
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Password (optional)")
                            .font(.system(size: 11, weight: .medium))
                            .foregroundColor(.secondary)
                        SecureField("password", text: $password)
                            .textFieldStyle(.roundedBorder)
                    }
                }
                
                HStack(spacing: 12) {
                    ActionButton(
                        title: "Build PFX",
                        icon: "shippingbox.fill",
                        action: buildPFX,
                        disabled: certPEM.isEmpty || keyPEM.isEmpty
                    )
                    
                    if pfxData != nil {
                        Button {
                            savePFX()
                        } label: {
                            HStack(spacing: 4) {
                                Image(systemName: "arrow.down.circle")
                                Text("Download .pfx")
                            }
                        }
                        .buttonStyle(.bordered)
                        
                        Text("✓ PFX ready — \(pfxData!.count) bytes")
                            .font(.system(size: 11))
                            .foregroundColor(.green)
                    }
                }
                
                if let error = error {
                    ErrorText(error: error)
                }
            }
            .padding()
        }
    }
    
    private func buildPFX() {
        error = nil
        pfxData = nil
        
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let data = try CertService.shared.createPKCS12(
                    certPEM: certPEM,
                    keyPEM: keyPEM,
                    chainPEM: chainPEM.isEmpty ? nil : chainPEM,
                    password: password,
                    friendlyName: friendlyName.isEmpty ? nil : friendlyName
                )
                DispatchQueue.main.async {
                    self.pfxData = data
                }
            } catch {
                DispatchQueue.main.async {
                    self.error = error.localizedDescription
                }
            }
        }
    }
    
    private func savePFX() {
        guard let data = pfxData else { return }
        
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "\(friendlyName.isEmpty ? "certificate" : friendlyName).pfx"
        panel.allowedContentTypes = [.data]
        
        if panel.runModal() == .OK, let url = panel.url {
            try? data.write(to: url)
        }
    }
}

struct KeyAlgoSelectorView: View {
    @Binding var config: KeyAlgoConfig
    
    var body: some View {
        GroupBox {
            VStack(spacing: 12) {
                Picker("Algorithm", selection: $config.kind) {
                    ForEach(KeyAlgoKind.allCases, id: \.self) { kind in
                        Text(kind.label).tag(kind)
                    }
                }
                .pickerStyle(.segmented)
                
                if config.kind == .rsa {
                    Picker("RSA Key Size", selection: $config.rsaBits) {
                        ForEach(RSABits.allCases, id: \.self) { bits in
                            Text(bits.rawValue + " bits").tag(bits)
                        }
                    }
                    .pickerStyle(.segmented)
                }
                
                if config.kind == .ec {
                    Picker("EC Curve", selection: $config.curve) {
                        ForEach(ECCurve.allCases, id: \.self) { curve in
                            Text(curve.rawValue).tag(curve)
                        }
                    }
                    .pickerStyle(.segmented)
                }
                
                Text("Selected: \(config.label)")
                    .font(.system(size: 10))
                    .foregroundColor(.secondary)
            }
        } label: {
            Text("Key Algorithm")
                .font(.system(size: 12, weight: .semibold))
        }
    }
}
