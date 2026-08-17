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
    case keystore    = "keystore"
    case genCSR      = "gen-csr"
    case genCert     = "gen-cert"
    case certConvert = "cert-convert"
    case toPFX       = "to-pfx"

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
        case .keystore:    return "Keystore"
        case .genCSR:      return "Generate CSR"
        case .genCert:     return "Generate Cert"
        case .certConvert: return "Converter"
        case .toPFX:       return "To PFX / P12"
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
        case .keystore:    return "cylinder"
        case .genCSR:      return "pencil.and.list.clipboard"
        case .genCert:     return "checkmark.shield.fill"
        case .certConvert: return "arrow.2.squarepath"
        case .toPFX:       return "shippingbox"
        }
    }

    var group: NavGroup {
        switch self {
        case .certDecode, .csrDecode, .keyInspect: return .inspect
        case .certKey, .certCSR, .csrKey, .certDiff, .chainVerify: return .verify
        case .caBundle, .bundleCheck, .keystore: return .stores
        case .genCSR, .genCert, .certConvert, .toPFX: return .generate
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
    @State private var selectedTab: TabID = .certDecode

    var body: some View {
        NavigationSplitView(columnVisibility: .constant(.all)) {
            SidebarView(selectedTab: $selectedTab)
                .navigationSplitViewColumnWidth(min: 195, ideal: 210, max: 230)
        } detail: {
            detailView(for: selectedTab)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                .padding()
        }
        .frame(minWidth: 880, minHeight: 580)
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
        case .keystore:    KeystoreView()
        case .genCSR:      GenCSRView()
        case .genCert:     GenCertView()
        case .certConvert: CertConvertView()
        case .toPFX:       ToPFXView()
        }
    }
}
