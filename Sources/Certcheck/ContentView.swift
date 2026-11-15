import SwiftUI

enum TabID: String, CaseIterable, Identifiable {
    case certDecode  = "cert-decode"
    case csrDecode   = "csr-decode"
    case keyInspect  = "key-inspect"
    case certKey     = "cert-key"
    case certCSR     = "cert-csr"
    case csrKey      = "csr-key"
    case certDiff    = "cert-diff"
    case chainVerify = "chain"
    case caBundle    = "ca-bundle"
    case bundleCheck = "bundle-check"
    case keytoolOpen = "keytool-open"
    case keytoolOps  = "keytool-ops"
    case genCSR      = "gen-csr"
    case genCert     = "gen-cert"
    case certConvert = "cert-convert"
    case toPFX       = "to-pfx"
    case base64Convert = "base64-convert"

    var id: String { rawValue }

    var label: String {
        switch self {
        case .certDecode:  return "Cert Decode"
        case .csrDecode:   return "CSR Decode"
        case .keyInspect:  return "Key Inspect"
        case .certKey:     return "Cert ↔ Key"
        case .certCSR:     return "Cert ↔ CSR"
        case .csrKey:      return "CSR ↔ Key"
        case .certDiff:    return "Cert Diff"
        case .chainVerify: return "Chain Verify"
        case .caBundle:    return "CA Bundle"
        case .bundleCheck: return "Bundle Check"
        case .keytoolOpen: return "Keystore"
        case .keytoolOps:  return "KeytoolOp"
        case .genCSR:      return "Generate CSR"
        case .genCert:     return "Generate Cert"
        case .certConvert: return "Converter"
        case .toPFX:       return "To PFX / P12"
        case .base64Convert: return "Base64 Convert"
        }
    }

    var icon: String {
        switch self {
        case .certDecode:  return "doc.text.magnifyingglass"
        case .csrDecode:   return "key.viewfinder"
        case .keyInspect:  return "lock.open"
        case .certKey:     return "key"
        case .certCSR:     return "arrow.triangle.merge"
        case .csrKey:      return "link"
        case .certDiff:    return "arrow.left.arrow.right"
        case .chainVerify: return "shield.checkered"
        case .caBundle:    return "books.vertical"
        case .bundleCheck: return "checkmark.seal"
        case .keytoolOpen: return "lock.open.fill"
        case .keytoolOps:  return "slider.horizontal.3"
        case .genCSR:      return "pencil.and.list.clipboard"
        case .genCert:     return "checkmark.shield.fill"
        case .certConvert: return "arrow.2.squarepath"
        case .toPFX:       return "shippingbox"
        case .base64Convert: return "doc.plaintext"
        }
    }

    var group: NavGroup {
        switch self {
        case .certDecode, .csrDecode, .keyInspect: return .inspect
        case .certKey, .certCSR, .csrKey, .certDiff, .chainVerify: return .verify
        case .caBundle, .bundleCheck, .keytoolOpen, .keytoolOps: return .stores
        case .genCSR, .genCert, .certConvert, .toPFX, .base64Convert: return .generate
        }
    }
}

enum NavGroup: String, CaseIterable {
    case inspect  = "Inspect"
    case verify   = "Verify"
    case stores   = "Stores"
    case generate = "Generate"

    var color: Color {
        switch self {
        case .inspect:  return Color(hue: 0.68, saturation: 0.70, brightness: 0.75)
        case .verify:   return Color(hue: 0.46, saturation: 0.60, brightness: 0.58)
        case .stores:   return Color(hue: 0.11, saturation: 0.88, brightness: 0.82)
        case .generate: return Color(hue: 0.86, saturation: 0.60, brightness: 0.78)
        }
    }

    var tabs: [TabID] {
        TabID.allCases.filter { $0.group == self }
    }
}

struct ContentView: View {
    @StateObject private var workspace = Workspace()
    @State private var renamingSession: ToolSession?
    @State private var sessionTitle = ""

    private var selectedTool: Binding<TabID> {
        Binding(
            get: { workspace.selectedSession?.tool ?? .certDecode },
            set: { workspace.selectTool($0) }
        )
    }

    var body: some View {
        NavigationSplitView(columnVisibility: .constant(.all)) {
            SidebarView(selectedTab: selectedTool)
                .navigationSplitViewColumnWidth(min: 195, ideal: 210, max: 230)
        } detail: {
            VStack(spacing: 0) {
                sessionBar
                Divider()
                ZStack(alignment: .topLeading) {
                    ForEach(workspace.sessions) { session in
                        detailView(for: session.tool)
                            .environment(\.updateSessionResourceName) { subject, sans in
                                workspace.updateResourceName(session.id, subject: subject, sans: sans)
                            }
                            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                            .padding()
                            .opacity(workspace.selectedID == session.id ? 1 : 0)
                            .allowsHitTesting(workspace.selectedID == session.id)
                            .disabled(workspace.selectedID != session.id)
                            .accessibilityHidden(workspace.selectedID != session.id)
                            .zIndex(workspace.selectedID == session.id ? 1 : 0)
                    }
                    if workspace.sessions.isEmpty {
                        Button("New Certificate Tab", systemImage: "plus") {
                            workspace.newSession(for: .certDecode)
                        }
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .frame(minWidth: 880, minHeight: 580)
        .focusedSceneValue(\.workspace, workspace)
        .onChange(of: workspace.selectedID) { _ in
            NSApp.keyWindow?.makeFirstResponder(nil)
        }
        .sheet(item: $renamingSession) { session in
            VStack(alignment: .leading, spacing: 16) {
                Text("Rename Tab").font(.headline)
                TextField("Tab name", text: $sessionTitle)
                    .textFieldStyle(.roundedBorder)
                HStack {
                    Spacer()
                    Button("Cancel") { renamingSession = nil }
                        .keyboardShortcut(.cancelAction)
                    Button("Save") {
                        workspace.rename(session.id, title: sessionTitle)
                        renamingSession = nil
                    }
                    .keyboardShortcut(.defaultAction)
                    .disabled(sessionTitle.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
            .padding(24)
            .frame(width: 340)
        }
    }

    private var sessionBar: some View {
        HStack(spacing: 8) {
            ScrollViewReader { proxy in
                ScrollView(.horizontal) {
                    HStack(spacing: 4) {
                        ForEach(workspace.sessions) { session in
                            HStack(spacing: 4) {
                                Button {
                                    workspace.select(session.id)
                                } label: {
                                    Label(session.title, systemImage: session.tool.icon)
                                        .lineLimit(1)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                        .contentShape(Rectangle())
                                }
                                .buttonStyle(.plain)
                                .help(session.title)
                                Button {
                                    workspace.close(session.id)
                                } label: {
                                    Image(systemName: "xmark")
                                        .font(.system(size: 10, weight: .semibold))
                                        .frame(width: 22, height: 22)
                                        .contentShape(Rectangle())
                                }
                                .buttonStyle(.plain)
                                .help("Close Tab")
                                .accessibilityLabel("Close \(session.title)")
                            }
                            .font(.system(size: 12))
                            .padding(.horizontal, 8)
                            .frame(width: 180, height: 34)
                            .background(workspace.selectedID == session.id
                                ? session.tool.group.color.opacity(0.14)
                                : Color.secondary.opacity(0.06))
                            .clipShape(RoundedRectangle(cornerRadius: 6))
                            .id(session.id)
                            .contextMenu {
                                Button("Rename Tab") {
                                    sessionTitle = session.title
                                    renamingSession = session
                                }
                                Button("New Tab of This Type") {
                                    workspace.newSession(for: session.tool)
                                }
                                Button("Move Left") { workspace.move(session.id, by: -1) }
                                    .disabled(workspace.sessions.first?.id == session.id)
                                Button("Move Right") { workspace.move(session.id, by: 1) }
                                    .disabled(workspace.sessions.last?.id == session.id)
                                Divider()
                                Button("Close Tab") { workspace.close(session.id) }
                            }
                        }
                    }
                    .padding(.horizontal, 2)
                }
                .onChange(of: workspace.selectedID) { id in
                    if let id { proxy.scrollTo(id) }
                }
            }
            Button {
                workspace.newSession(for: workspace.selectedSession?.tool ?? .certDecode)
            } label: {
                Image(systemName: "plus").frame(width: 28, height: 28)
            }
            .help("New Tab of Current Type")
            .accessibilityLabel("New Tab of Current Type")
            Menu {
                ForEach(NavGroup.allCases, id: \.self) { group in
                    Section(group.rawValue) {
                        ForEach(group.tabs) { tool in
                            Button {
                                workspace.newSession(for: tool)
                            } label: {
                                Label(tool.label, systemImage: tool.icon)
                            }
                        }
                    }
                }
            } label: {
                Image(systemName: "chevron.down")
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .help("New Tab")
            .accessibilityLabel("Choose Tool for New Tab")
        }
        .padding(8)
        .frame(height: 50)
    }

    @ViewBuilder
    private func detailView(for tab: TabID) -> some View {
        switch tab {
        case .certDecode:  CertDecodeView()
        case .csrDecode:   CSRDecodeView()
        case .keyInspect:  KeyInspectView()
        case .certKey:     CertKeyView()
        case .certCSR:     CertCSRView()
        case .csrKey:      CSRKeyView()
        case .certDiff:    CertDiffView()
        case .chainVerify: ChainVerifyView()
        case .caBundle:    CABundleView()
        case .bundleCheck: BundleCheckView()
        case .keytoolOpen: OpenKeystoreView()
        case .keytoolOps:  KeytoolOperationsView()
        case .genCSR:      GenCSRView()
        case .genCert:     GenCertView()
        case .certConvert: CertConvertView()
        case .toPFX:       ToPFXView()
        case .base64Convert: Base64ConverterView()
        }
    }
}

struct WorkspaceFocusKey: FocusedValueKey {
    typealias Value = Workspace
}

extension FocusedValues {
    var workspace: Workspace? {
        get { self[WorkspaceFocusKey.self] }
        set { self[WorkspaceFocusKey.self] = newValue }
    }
}
