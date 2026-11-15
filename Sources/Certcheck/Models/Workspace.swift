import SwiftUI

struct ToolSession: Identifiable {
    let id = UUID()
    let tool: TabID
    var title: String
    var hasCustomTitle = false
}

@MainActor
final class Workspace: ObservableObject {
    @Published private(set) var sessions: [ToolSession] = []
    @Published private(set) var selectedID: UUID?
    private var lastSelected: [TabID: UUID] = [:]

    init() {
        newSession(for: .certDecode)
    }

    var selectedSession: ToolSession? {
        sessions.first { $0.id == selectedID }
    }

    func newSession(for tool: TabID) {
        let session = ToolSession(tool: tool, title: tool.label)
        sessions.append(session)
        select(session.id)
    }

    func select(_ id: UUID) {
        guard let session = sessions.first(where: { $0.id == id }) else { return }
        selectedID = id
        lastSelected[session.tool] = id
    }

    func selectTool(_ tool: TabID) {
        if let id = lastSelected[tool], sessions.contains(where: { $0.id == id }) {
            select(id)
        } else if let session = sessions.first(where: { $0.tool == tool }) {
            select(session.id)
        } else {
            newSession(for: tool)
        }
    }

    func close(_ id: UUID) {
        guard let index = sessions.firstIndex(where: { $0.id == id }) else { return }
        let removed = sessions.remove(at: index)
        if lastSelected[removed.tool] == id {
            lastSelected[removed.tool] = nil
        }
        if selectedID == id {
            if sessions.isEmpty {
                selectedID = nil
            } else {
                select(sessions[min(index, sessions.count - 1)].id)
            }
        }
    }

    func rename(_ id: UUID, title: String) {
        let trimmed = title.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              let index = sessions.firstIndex(where: { $0.id == id }) else { return }
        sessions[index].title = trimmed
        sessions[index].hasCustomTitle = true
    }

    func updateResourceName(_ id: UUID, subject: OrderedDN, sans: [String]) {
        guard let index = sessions.firstIndex(where: { $0.id == id }),
              !sessions[index].hasCustomTitle else { return }
        let commonName = subject.first { $0.key.caseInsensitiveCompare("CN") == .orderedSame }?.value
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let names = sans.map { name in
            let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.lowercased().hasPrefix("dns:")
                ? String(trimmed.dropFirst(4)).trimmingCharacters(in: .whitespacesAndNewlines)
                : trimmed
        }
        let name = commonName.flatMap { $0.isEmpty ? nil : $0 }
            ?? names.first { !$0.isEmpty }
        let title = name ?? sessions[index].tool.label
        if sessions[index].title != title {
            sessions[index].title = title
        }
    }

    func move(_ id: UUID, by offset: Int) {
        guard let index = sessions.firstIndex(where: { $0.id == id }) else { return }
        let destination = index + offset
        guard sessions.indices.contains(destination) else { return }
        let session = sessions.remove(at: index)
        sessions.insert(session, at: destination)
    }
}

private struct SessionResourceNameKey: EnvironmentKey {
    static let defaultValue: (OrderedDN, [String]) -> Void = { _, _ in }
}

extension EnvironmentValues {
    var updateSessionResourceName: (OrderedDN, [String]) -> Void {
        get { self[SessionResourceNameKey.self] }
        set { self[SessionResourceNameKey.self] = newValue }
    }
}
