import Foundation

/// A single keystore file the user has opened, tracked by the shared registry so every
/// tab/operation can unambiguously reference "which file" is being acted on.
struct ManagedKeystore: Identifiable {
    let id = UUID()
    var path: String
    var storeType: KeystoreFormat
    var password: String
    var entries: [KeystoreEntryInfo] = []
    var isLoading = false
    var error: String?
    var rawListOutput: String = ""

    var displayName: String { URL(fileURLWithPath: path).lastPathComponent }

    var resolvedStoreType: KeystoreFormat {
        storeType == .auto ? KeytoolHelper.shared.detectStoreType(path: path) : storeType
    }
}

/// Central registry of keystores opened in this session. Shared (singleton) so the
/// "Open Keystore" tab and the "Keytool Operations" tab always agree on which named
/// file an operation targets, instead of relying on implicit/hidden shared state.
final class KeytoolRegistry: ObservableObject {
    static let shared = KeytoolRegistry()
    private init() {}

    @Published var keystores: [ManagedKeystore] = []
    @Published var selectedKeystoreID: UUID?

    var selected: ManagedKeystore? {
        keystores.first(where: { $0.id == selectedKeystoreID })
    }

    /// Opens (or re-selects, if already open) a keystore file and loads its entries.
    @discardableResult
    func openFile(path: String, storeType: KeystoreFormat, password: String, completion: (() -> Void)? = nil) -> UUID {
        if let idx = keystores.firstIndex(where: { $0.path == path }) {
            keystores[idx].storeType = storeType
            keystores[idx].password = password
            let id = keystores[idx].id
            selectedKeystoreID = id
            load(id: id, completion: completion)
            return id
        }
        let entry = ManagedKeystore(path: path, storeType: storeType, password: password)
        keystores.append(entry)
        selectedKeystoreID = entry.id
        load(id: entry.id, completion: completion)
        return entry.id
    }

    func load(id: UUID, completion: (() -> Void)? = nil) {
        guard let idx = keystores.firstIndex(where: { $0.id == id }) else { completion?(); return }
        keystores[idx].isLoading = true
        keystores[idx].error = nil
        let path = keystores[idx].path
        let type = keystores[idx].resolvedStoreType
        let pass = keystores[idx].password

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let raw = try KeytoolHelper.shared.rawList(keystorePath: path, storeType: type, password: pass)
                let result = try KeytoolHelper.shared.listEntries(keystorePath: path, storeType: type, password: pass)
                DispatchQueue.main.async {
                    guard let idx2 = self.keystores.firstIndex(where: { $0.id == id }) else { completion?(); return }
                    self.keystores[idx2].rawListOutput = raw
                    self.keystores[idx2].entries = result
                    self.keystores[idx2].isLoading = false
                    completion?()
                }
            } catch {
                DispatchQueue.main.async {
                    guard let idx2 = self.keystores.firstIndex(where: { $0.id == id }) else { completion?(); return }
                    self.keystores[idx2].error = error.localizedDescription
                    self.keystores[idx2].isLoading = false
                    completion?()
                }
            }
        }
    }

    func updatePassword(id: UUID, newPassword: String) {
        guard let idx = keystores.firstIndex(where: { $0.id == id }) else { return }
        keystores[idx].password = newPassword
    }

    func close(id: UUID) {
        keystores.removeAll { $0.id == id }
        if selectedKeystoreID == id { selectedKeystoreID = keystores.first?.id }
    }
}
