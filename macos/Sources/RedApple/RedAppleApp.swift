import SwiftUI
import AppKit
import RedAppleCore

@main
struct RedAppleApp: App {
    @StateObject private var model = AppModel()
    init() {
        if ProcessInfo.processInfo.arguments.contains("--verify-resources") {
            do {
                _ = try BountyCatalog.bundled()
                _ = try PatchDatabase.bundled()
                print("Packaged catalog and patches loaded.")
                exit(0)
            } catch {
                fputs("Packaged resources failed: \(error.localizedDescription)\n", stderr)
                exit(1)
            }
        }
        NSApplication.shared.setActivationPolicy(.regular)
    }
    var body: some Scene {
        WindowGroup {
            ContentView().environmentObject(model)
                .frame(minWidth: 1000, minHeight: 650)
                .tint(.red)
                .task {
                    while !Task.isCancelled {
                        model.reloadDiscovery()
                        do { try await Task.sleep(nanoseconds: 5_000_000_000) } catch { break }
                    }
                }
                .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in model.reloadDiscovery() }
        }
        .defaultSize(width: 1320, height: 850)
        .commands {
            CommandGroup(after: .newItem) {
                Button("Choose Workspace…") { model.chooseWorkspace() }.keyboardShortcut("o", modifiers: [.command, .shift])
                Button("Reveal Workspace") { model.revealWorkspace() }
            }
            CommandGroup(after: .toolbar) {
                Button("Reload Discovery") { model.reloadDiscovery() }.keyboardShortcut("r")
                Button("Refresh Apple Patches") { model.refreshPatches() }.disabled(model.refreshing)
            }
        }
        Settings { SettingsView().environmentObject(model) }
    }
}
