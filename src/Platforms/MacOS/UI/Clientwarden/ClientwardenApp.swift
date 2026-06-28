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
    
    public var cb_getState: (() -> WindowState)?
}

@main
struct ClientwardenApp: App {
    private var data: ClientwardenWindow = ClientwardenWindow.instance
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    
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
    }
}

#Preview {
    PreviewData().test1()
}
