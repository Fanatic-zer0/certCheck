import SwiftUI

struct SidebarView: View {
    @Binding var selectedTab: TabID
    
    var body: some View {
        List(selection: $selectedTab) {
            // Logo header
            VStack(spacing: 0) {
                HStack(spacing: 10) {
                    ZStack {
                        // Try to load custom icon from Resources, fallback to gradient badge
                        if let iconImage = NSImage(contentsOfFile: "./Resources/icon.png") {
                            Image(nsImage: iconImage)
                                .resizable()
                                .aspectRatio(contentMode: .fit)
                                .frame(width: 32, height: 32)
                                .clipShape(RoundedRectangle(cornerRadius: 8))
                                .shadow(color: Color.black.opacity(0.2), radius: 4, y: 2)
                        } else {
                            // Fallback gradient badge with "C"
                            RoundedRectangle(cornerRadius: 8)
                                .fill(
                                    LinearGradient(
                                        colors: [
                                            Color(hue: 0.68, saturation: 0.70, brightness: 0.68),
                                            Color(hue: 0.75, saturation: 0.65, brightness: 0.65)
                                        ],
                                        startPoint: .topLeading,
                                        endPoint: .bottomTrailing
                                    )
                                )
                                .frame(width: 28, height: 28)
                                .shadow(color: Color(hue: 0.68, saturation: 0.70, brightness: 0.70).opacity(0.4), radius: 4, y: 2)
                                .overlay(
                                    Text("C")
                                        .font(.system(size: 13, weight: .bold))
                                        .foregroundColor(.white)
                                )
                        }
                    }
                    
                    VStack(alignment: .leading, spacing: 1) {
                        Text("Certcheck")
                            .font(.system(size: 15, weight: .semibold))
                        Text("Certificate Utility")
                            .font(.system(size: 9.5))
                            .foregroundColor(.secondary)
                    }
                    Spacer()
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 14)
            }
            .listRowInsets(EdgeInsets())
            .listRowBackground(Color.clear)
            
            // Navigation groups
            ForEach(NavGroup.allCases, id: \.self) { group in
                Section(header: GroupHeader(group: group)) {
                    ForEach(group.tabs) { tab in
                        NavButton(tab: tab, isSelected: selectedTab == tab)
                            .tag(tab)
                    }
                }
            }
        }
        .listStyle(.sidebar)
        .navigationTitle("")
    }
}

struct GroupHeader: View {
    let group: NavGroup
    
    var body: some View {
        Text(group.rawValue)
            .font(.system(size: 10, weight: .semibold))
            .foregroundColor(.secondary)
            .textCase(.uppercase)
            .padding(.top, 8)
    }
}

struct NavButton: View {
    let tab: TabID
    let isSelected: Bool
    
    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: tab.icon)
                .font(.system(size: 12, weight: .medium))
                .foregroundColor(isSelected ? tab.group.color : .secondary)
                .frame(width: 16)
            
            Text(tab.label)
                .font(.system(size: 12))
                .foregroundColor(isSelected ? .primary : .secondary)
            
            Spacer()
        }
        .padding(.vertical, 6)
        .padding(.horizontal, 8)
        .background(
            RoundedRectangle(cornerRadius: 6)
                .fill(isSelected ? tab.group.color.opacity(0.12) : Color.clear)
        )
        .contentShape(Rectangle())
    }
}

// MARK: - Shared UI Components

struct SectionTitle: View {
    let title: String
    
    var body: some View {
        Text(title)
            .font(.system(size: 14, weight: .semibold))
            .padding(.bottom, 8)
    }
}

struct FieldRow: View {
    let label: String
    let value: String
    var isWide: Bool = false
    @State private var copied = false

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Text(label)
                .font(.system(size: 11, weight: .medium))
                .foregroundColor(.secondary)
                .frame(minWidth: 100, maxWidth: isWide ? .infinity : 160, alignment: .trailing)
                .lineLimit(nil)
                .fixedSize(horizontal: false, vertical: true)

            Text(value)
                .font(.system(size: 11, weight: .regular))
                .foregroundColor(.primary)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .lineLimit(nil)
                .fixedSize(horizontal: false, vertical: true)

            if !value.isEmpty {
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(value, forType: .string)
                    withAnimation { copied = true }
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { withAnimation { copied = false } }
                } label: {
                    Image(systemName: copied ? "checkmark" : "doc.on.doc")
                        .font(.system(size: 10))
                        .foregroundColor(copied ? .green : Color.secondary.opacity(0.5))
                }
                .buttonStyle(.plain)
                .frame(width: 18)
            }
        }
        .padding(.vertical, 4)
    }
}

struct MatchBadge: View {
    let match: Bool
    let yesText: String
    let noText: String
    
    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: match ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundColor(match ? .green : .red)
            Text(match ? yesText : noText)
                .font(.system(size: 12, weight: .medium))
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(match ? Color.green.opacity(0.1) : Color.red.opacity(0.1))
        )
    }
}

struct PEMInputField: View {
    let label: String
    let placeholder: String
    @Binding var text: String
    
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.system(size: 11, weight: .medium))
                .foregroundColor(.secondary)
            
            TextEditor(text: $text)
                .font(.system(size: 10, design: .monospaced))
                .frame(height: 120)
                .padding(6)
                .background(Color(nsColor: .textBackgroundColor))
                .cornerRadius(6)
                .overlay(
                    RoundedRectangle(cornerRadius: 6)
                        .stroke(Color.secondary.opacity(0.2), lineWidth: 1)
                )
                .overlay(alignment: .topLeading) {
                    if text.isEmpty {
                        Text(placeholder)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(.secondary.opacity(0.5))
                            .padding(12)
                            .allowsHitTesting(false)
                    }
                }
        }
    }
}

struct ActionButton: View {
    let title: String
    let icon: String?
    let action: () -> Void
    var disabled: Bool = false
    
    var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                if let icon = icon {
                    Image(systemName: icon)
                        .font(.system(size: 11))
                }
                Text(title)
                    .font(.system(size: 12, weight: .medium))
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
        }
        .buttonStyle(.borderedProminent)
        .disabled(disabled)
    }
}

struct InfoCard: View {
    let title: String
    let content: () -> AnyView
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.system(size: 13, weight: .semibold))
                .padding(.bottom, 4)
            
            content()
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
}

struct CopyButton: View {
    let text: String
    @State private var copied = false
    
    var body: some View {
        Button {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(text, forType: .string)
            copied = true
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                copied = false
            }
        } label: {
            HStack(spacing: 4) {
                Image(systemName: copied ? "checkmark" : "doc.on.doc")
                    .font(.system(size: 10))
                Text(copied ? "Copied" : "Copy")
                    .font(.system(size: 11))
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
        }
        .buttonStyle(.bordered)
    }
}

struct DownloadButton: View {
    let filename: String
    let content: String
    
    var body: some View {
        Button {
            let panel = NSSavePanel()
            panel.nameFieldStringValue = filename
            panel.allowedContentTypes = [.data]
            
            if panel.runModal() == .OK, let url = panel.url {
                try? content.write(to: url, atomically: true, encoding: .utf8)
            }
        } label: {
            HStack(spacing: 4) {
                Image(systemName: "arrow.down.circle")
                    .font(.system(size: 10))
                Text("Download")
                    .font(.system(size: 11))
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
        }
        .buttonStyle(.bordered)
    }
}

struct ErrorText: View {
    let error: String
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundColor(.orange)
                    .font(.system(size: 14))
                Text("Feature Not Available")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(.primary)
            }
            
            Text(error)
                .font(.system(size: 11))
                .foregroundColor(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            
            if error.contains("openssl") || error.contains("keytool") {
                HStack(spacing: 4) {
                    Image(systemName: "info.circle")
                        .font(.system(size: 10))
                    Text("See FEATURES.md for alternatives and integration guide")
                        .font(.system(size: 10))
                }
                .foregroundColor(.blue)
                .padding(.top, 4)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(Color.orange.opacity(0.08))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color.orange.opacity(0.3), lineWidth: 1)
        )
    }
}
