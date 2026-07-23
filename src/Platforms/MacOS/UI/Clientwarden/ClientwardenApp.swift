import SwiftUI

class AppDelegate: NSObject, NSApplicationDelegate {
    private var screenCaptureTimer: Timer?

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }

    func applyScreenCaptureSetting() {
        DispatchQueue.main.async {
            for window in NSApplication.shared.windows {
                window.sharingType = SettingsPanel.instance.getScrshot() ? .readOnly : .none
            }
        }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        /*
         * We need to call this here since its used here before the Settings View
         */
        #if NON_XCODE_BUILD
            SettingsBridge.setupCallbacks()
        #endif
        SettingsPanel.instance.getInfo()

        applyScreenCaptureSetting()

        screenCaptureTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            self?.applyScreenCaptureSetting()
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
            ToastStore.instance.toasts.append(Toast(message: "No callback set for getState"))
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
                        SidePanel.instance.closeItem()
                        ItemsPanel.instance.elements = []
                        ItemsPanel.instance.filteredElements = []
                        ItemsPanel.instance.searchQuery = ""
                    } else {
                        ToastStore.instance.toasts.append(Toast(message: "Failed to Lock Vault"))
                        ClientwardenWindow.instance.state = WindowState.Vault
                    }
                } else {
                    ToastStore.instance.toasts.append(Toast(message: "No callback set for lock"))
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
                                get: { ToastStore.instance.toasts },
                                set: { ToastStore.instance.toasts = $0 }
                            )
                        )
                    case .Unlock:
                        UnlockView()
                        .toast(
                            Binding(
                                get: { ToastStore.instance.toasts },
                                set: { ToastStore.instance.toasts = $0 }
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
                                get: { ToastStore.instance.toasts },
                                set: { ToastStore.instance.toasts = $0 }
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
                #if NON_XCODE_BUILD
                    CWAppBridge.setupCallbacks()
                #endif
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
