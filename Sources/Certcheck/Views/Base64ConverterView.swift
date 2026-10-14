import SwiftUI
import UniformTypeIdentifiers

/// Converts arbitrary files (certs, keys, keystores, etc.) to/from Base64 text.
struct Base64ConverterView: View {
    enum Mode: String, CaseIterable, Identifiable {
        case encode = "Encode (File → Base64)"
        case decode = "Decode (Base64 → File)"
        var id: String { rawValue }
    }

    @State private var mode: Mode = .encode

    // Encode state
    @State private var inputFilePath = ""
    @State private var inputFileData: Data?
    @State private var lineWrap = true
    @State private var base64Output = ""

    // Decode state
    @State private var base64Input = ""
    @State private var decodedData: Data?
    @State private var decodedKindLabel = ""

    @State private var error: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header

                Picker("", selection: $mode) {
                    ForEach(Mode.allCases) { m in Text(m.rawValue).tag(m) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .onChange(of: mode) { _ in error = nil }

                if let error = error { ErrorText(error: error) }

                switch mode {
                case .encode: encodeSection
                case .decode: decodeSection
                }
            }
            .padding()
        }
    }

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: "doc.plaintext")
                .font(.title2)
                .foregroundColor(Color(hue: 0.86, saturation: 0.60, brightness: 0.78))
            VStack(alignment: .leading, spacing: 2) {
                Text("Base64 File Converter").font(.title2.bold())
                Text("Convert certificates, keys, or keystores to/from Base64 text")
                    .font(.caption).foregroundColor(.secondary)
            }
        }
    }

    // MARK: - Encode

    @ViewBuilder
    private var encodeSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Button("Choose File…") { chooseInputFile() }.buttonStyle(.bordered)
                Text(inputFilePath.isEmpty ? "No file selected" : URL(fileURLWithPath: inputFilePath).lastPathComponent)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(inputFilePath.isEmpty ? .secondary : .primary)
                    .lineLimit(1)
                if let data = inputFileData {
                    Text("(\(byteCountString(data.count)))").font(.system(size: 10)).foregroundColor(.secondary)
                }
            }

            Toggle("Wrap at 64 characters (PEM-style)", isOn: $lineWrap)
                .toggleStyle(.checkbox)
                .font(.system(size: 11))

            ActionButton(
                title: "Encode to Base64",
                icon: "arrow.right.doc.on.clipboard",
                action: encode,
                disabled: inputFileData == nil
            )

            if !base64Output.isEmpty {
                InfoCard(title: "Base64 Output") {
                    AnyView(VStack(alignment: .leading, spacing: 8) {
                        ScrollView {
                            Text(base64Output)
                                .font(.system(size: 10, design: .monospaced))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .frame(maxHeight: 260)
                        HStack {
                            CopyButton(text: base64Output)
                            DownloadButton(filename: "\(baseName(inputFilePath)).b64.txt", content: base64Output)
                        }
                    })
                }
            }
        }
    }

    // MARK: - Decode

    @ViewBuilder
    private var decodeSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text("Base64 Text").font(.system(size: 11, weight: .medium)).foregroundColor(.secondary)
                    Spacer()
                    Button("Load File…") { loadBase64File() }.buttonStyle(.bordered).controlSize(.small)
                }
                TextEditor(text: $base64Input)
                    .font(.system(size: 10, design: .monospaced))
                    .frame(height: 160)
                    .padding(6)
                    .background(Color(nsColor: .textBackgroundColor))
                    .cornerRadius(6)
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.2), lineWidth: 1))
            }

            ActionButton(
                title: "Decode",
                icon: "arrow.left.doc.on.clipboard",
                action: decode,
                disabled: base64Input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            )

            if let data = decodedData {
                InfoCard(title: "Decoded File") {
                    AnyView(VStack(alignment: .leading, spacing: 8) {
                        FieldRow(label: "Size", value: byteCountString(data.count))
                        FieldRow(label: "Detected Type", value: decodedKindLabel)
                        Button {
                            saveDecodedFile(data)
                        } label: {
                            HStack(spacing: 4) {
                                Image(systemName: "arrow.down.circle")
                                Text("Save As…")
                            }
                        }
                        .buttonStyle(.bordered)
                    })
                }
            }
        }
    }

    // MARK: - Actions

    private func chooseInputFile() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.message = "Select any file to Base64-encode"
        if panel.runModal() == .OK, let url = panel.url {
            inputFilePath = url.path
            inputFileData = try? Data(contentsOf: url)
            base64Output = ""
            error = inputFileData == nil ? "Could not read the selected file." : nil
        }
    }

    private func encode() {
        error = nil
        guard let data = inputFileData else { return }
        let options: Data.Base64EncodingOptions = lineWrap ? [.lineLength64Characters, .endLineWithLineFeed] : []
        base64Output = data.base64EncodedString(options: options)
    }

    private func loadBase64File() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.message = "Select a text file containing Base64 data"
        if panel.runModal() == .OK, let url = panel.url, let text = try? String(contentsOf: url, encoding: .utf8) {
            base64Input = text
            error = nil
        }
    }

    private func decode() {
        error = nil; decodedData = nil; decodedKindLabel = ""
        // Tolerate pasted PEM blocks (strip armor) as well as raw Base64.
        let cleaned = base64Input
            .replacingOccurrences(of: "-----BEGIN [^-]+-----", with: "", options: .regularExpression)
            .replacingOccurrences(of: "-----END [^-]+-----", with: "", options: .regularExpression)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard let data = Data(base64Encoded: cleaned, options: .ignoreUnknownCharacters), !data.isEmpty else {
            error = "Invalid Base64 input — could not decode."
            return
        }
        decodedData = data
        decodedKindLabel = detectKind(data)
    }

    private func saveDecodedFile(_ data: Data) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "decoded\(suggestedExtension(for: data))"
        panel.allowedContentTypes = [.data]
        if panel.runModal() == .OK, let url = panel.url {
            try? data.write(to: url)
        }
    }

    // MARK: - Helpers

    private func byteCountString(_ count: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(count), countStyle: .file)
    }

    private func baseName(_ path: String) -> String {
        path.isEmpty ? "file" : URL(fileURLWithPath: path).deletingPathExtension().lastPathComponent
    }

    private func detectKind(_ data: Data) -> String {
        if data.count >= 4 {
            let magic = data.prefix(4).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
            if magic == 0xFEED_FEED { return "Java Keystore (JKS)" }
            if magic == 0xCECE_CECE { return "Java Keystore (JCEKS)" }
        }
        if let text = String(data: data.prefix(64), encoding: .utf8), text.contains("-----BEGIN") {
            return "PEM Text"
        }
        if let first = data.first, first == 0x30 {
            return "DER (PKCS#12 / PKCS#7 / X.509)"
        }
        return "Binary Data"
    }

    private func suggestedExtension(for data: Data) -> String {
        switch detectKind(data) {
        case "Java Keystore (JKS)":   return ".jks"
        case "Java Keystore (JCEKS)": return ".jceks"
        case "DER (PKCS#12 / PKCS#7 / X.509)": return ".p12"
        case "PEM Text":              return ".pem"
        default:                      return ".bin"
        }
    }
}
