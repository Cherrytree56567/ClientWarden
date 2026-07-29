import SwiftUI

class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
    private var screenCaptureTimer: Timer?

    /*
     * Close Application when a window is closed
    */
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }

    /*
     * Screen Capture stuff.
    */
    func applyScreenCaptureSetting() {
        DispatchQueue.main.async {
            for window in NSApplication.shared.windows {
                window.sharingType = SettingsPanel.instance.getScrshot() ? .readOnly : .none
            }
        }
    }

    /*
     * Screen Capture stuff + Window Closing Anim
    */
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

        /*
         * Window Closing Anim
         */
        for window in NSApplication.shared.windows {
            assignDelegate(window)
        }

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(windowSelected(_:)),
            name: NSWindow.didBecomeKeyNotification,
            object: nil
        )
    }

    /*
     * Needs to be exposed
     * argument of '#selector' refers to instance method 'windowSelected' that is not exposed to Objective-C
    */
    @objc func windowSelected(_ notification: Notification) {
        if let window = notification.object as? NSWindow {
            assignDelegate(window)
        }
    }

    func assignDelegate(_ window: NSWindow) {
        if (window.delegate !== self && window.title == "Clientwarden") {
            window.delegate = self
        }
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        if (sender.frame.width <= 1) {
            return true
        }

        sender.titleVisibility = .hidden
        
        var frame = sender.frame

        NSAnimationContext.runAnimationGroup({ context in
            context.duration = 0.3
            context.timingFunction = CAMediaTimingFunction(name: "easeIn")

            frame.size.width = 0

            sender.animator().setFrame(frame, display: true)
        }, completionHandler: {
            sender.close()
        })

        return false
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
    @Environment(\.openWindow) private var openWindow
    
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
            CommandGroup(replacing: .appInfo) {
                Button("About ClientWarden") {
                    openWindow(id: "about")
                }
            }
            if (data.state == WindowState.Vault) {
                CommandMenu("Vault") {
                    Button("Lock") {
                        withAnimation {
                            data.lock()
                        }
                    }
                    .keyboardShortcut("L", modifiers: [.command])
                }
            }
        }

        Window("About ClientWarden", id: "about") {
            AboutView()
        }
        .windowResizability(.contentSize)
        .defaultPosition(.center)
        .restorationBehavior(.disabled)
        
        Settings {
            SettingsView()
        }
    }
}

#Preview {
    PreviewData().test1()
}
