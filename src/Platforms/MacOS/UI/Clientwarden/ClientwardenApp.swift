import SwiftUI

class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }
}

enum WindowState {
    case Login
    case Unlock
    case Vault
}

@Observable
final class ClientwardenWindow {
    static let instance = ClientwardenWindow()
    
    public var state: WindowState = .Login
    
    public var cb_getState: (() -> (WindowState, Bool))?
    public var cb_lock: (() -> (Bool))?
    
    func getState() {
        /*
         * Check if the var has a callback and check if
         * the callback was successful
         */
        if let res = cb_getState?() {
            if (res.1) {
                state = res.0
            } else {
                g_toastStore.toasts.append(Toast(message: "Failed to Get State"))
            }
        } else {
            g_toastStore.toasts.append(Toast(message: "No callback set for getState"))
        }
    }
    
    func lock() {
        /*
         * Check if the var has a callback and check if
         * the callback was successful
         */
        if let res = cb_lock?() {
            if (res) {
                state = WindowState.Unlock
            } else {
                g_toastStore.toasts.append(Toast(message: "Failed to Lock Vault"))
            }
        } else {
            g_toastStore.toasts.append(Toast(message: "No callback set for lock"))
        }
    }
}

@main
struct ClientwardenApp: App {
    private var data: ClientwardenWindow = ClientwardenWindow.instance
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    
    init() {
        data.getState()
    }
    
    var body: some Scene {
        WindowGroup("Clientwarden") {
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
