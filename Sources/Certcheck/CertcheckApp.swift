import SwiftUI

@main
struct CertcheckApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .windowStyle(.titleBar)
        .commands {
            WorkspaceCommands()
        }
    }
}

struct WorkspaceCommands: Commands {
    @FocusedValue(\.workspace) private var workspace

    var body: some Commands {
        CommandGroup(after: .newItem) {
            Button("New Tab") {
                guard let workspace else { return }
                workspace.newSession(for: workspace.selectedSession?.tool ?? .certDecode)
            }
            .keyboardShortcut("t", modifiers: .command)
            .disabled(workspace == nil)

            Button("Close Tab") {
                guard let workspace, let id = workspace.selectedID else { return }
                workspace.close(id)
            }
            .keyboardShortcut("w", modifiers: [.command, .shift])
            .disabled(workspace?.selectedID == nil)
        }
    }
}
