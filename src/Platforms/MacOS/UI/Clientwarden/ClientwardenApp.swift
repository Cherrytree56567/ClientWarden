import SwiftUI

class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        DispatchQueue.main.async {
            if let window = NSApplication.shared.windows.first {
                window.sharingType = .none
            }
        }
    }
}

@objc
enum WindowState: Int {
    case Login
    case Unlock
    case Vault
    case Empty
}

@objcMembers
@Observable
final class ClientwardenWindow: NSObject {
    static let instance = ClientwardenWindow()
    
    @objc public var state: WindowState = .Empty
    
    @objc public var cb_getState: (() -> WindowState)?
    @objc public var cb_lock: (() -> Bool)?
    
    func getState() {
        if let res = cb_getState?() {
            state = res
        } else {
            g_toastStore.toasts.append(Toast(message: "No callback set for getState"))
        }
    }
    
    func lock() {
        state = WindowState.Empty
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let res = self?.cb_lock?()

            DispatchQueue.main.async {
                if let r_res = res {
                    if (r_res) {
                        ClientwardenWindow.instance.state = WindowState.Unlock
                        SidePanel.instance.name = ""
                        SidePanel.instance.type = ItemType.Login
                        SidePanel.instance.icon = ClientwardenImage(type: ImageType.bundle, path: "profile1")
                        SidePanel.instance.favorite = false
                        SidePanel.instance.itemFields = []
                        SidePanel.instance.customFields = []
                        SidePanel.instance.itemHistory = []
                        SidePanel.instance.passwordHistory = []
                        SidePanel.instance.viewable = false
                        SidePanel.instance.notes = GenericItemData(title: "Notes", value: "", type: GenericItemType.ml_generic)
                        SidePanel.instance.s_name = ""
                        SidePanel.instance.s_favorite = false
                        SidePanel.instance.s_itemFields = []
                        SidePanel.instance.s_customFields = []
                        SidePanel.instance.s_itemHistory = []
                        SidePanel.instance.s_passwordHistory = []
                        SidePanel.instance.s_notes = GenericItemData(title: "Notes", value: "", type: GenericItemType.ml_generic)
                        ItemsPanel.instance.elements = []
                        ItemsPanel.instance.filteredElements = []
                        ItemsPanel.instance.searchQuery = ""
                    } else {
                        g_toastStore.toasts.append(Toast(message: "Failed to Lock Vault"))
                        ClientwardenWindow.instance.state = WindowState.Vault
                    }
                } else {
                    g_toastStore.toasts.append(Toast(message: "No callback set for lock"))
                    ClientwardenWindow.instance.state = WindowState.Vault
                }
            }
        }
    }
}

@main
struct ClientwardenApp: App {
    private var data: ClientwardenWindow = ClientwardenWindow.instance
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    
    var body: some Scene {
        WindowGroup("Clientwarden") {
            VStack {
                switch data.state {
                    case .Login:
                        LoginView()
                        .toast(
                            Binding(
                                get: { g_toastStore.toasts },
                                set: { g_toastStore.toasts = $0 }
                            )
                        )
                    case .Unlock:
                        UnlockView()
                        .toast(
                            Binding(
                                get: { g_toastStore.toasts },
                                set: { g_toastStore.toasts = $0 }
                            )
                        )
                    case .Vault:
                        HStack(spacing: 0) {
                            NavigationPanelView()
                            SidePanelView()
                        }
                        .frame(minWidth: 700, maxWidth: 700, minHeight: 400, maxHeight: 400)
                        .toast(
                            Binding(
                                get: { g_toastStore.toasts },
                                set: { g_toastStore.toasts = $0 }
                            )
                        )
                    case .Empty:
                        VStack {
                            ProgressView()
                                .controlSize(.large)
                        }
                        .frame(minWidth: 700, maxWidth: 700, minHeight: 400, maxHeight: 400)
                }
            }
            .onAppear {
                CWAppBridge.setupCallbacks()
                data.getState()
            }
        }
        .windowResizability(.contentSize)
        .commands {
            if (data.state == WindowState.Vault) {
                CommandMenu("Vault") {
                    Button("Lock") {
                        data.lock()
                    }
                    .keyboardShortcut("L", modifiers: [.command])
                }
            }
        }
        
        Settings {
            SettingsView()
        }
    }
}

#Preview {
    PreviewData().test1()
}
