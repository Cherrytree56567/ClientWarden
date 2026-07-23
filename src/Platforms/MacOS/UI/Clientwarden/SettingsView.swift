import SwiftUI

@objcMembers
final class SettingsData: NSObject {
    public var clipboardDelay: Int

    public init(clipboardDelay: Int) {
        self.clipboardDelay = clipboardDelay
    }
}

@objcMembers
@Observable
final class SettingsPanel: NSObject {
    static let instance = SettingsPanel()
    
    public var clipboardDelay: Int = 30
    
    @objc public var cb_logout: (() -> Bool)?
    
    func getInfo() {
        clipboardDelay = Clipboard.instance.getDelay()
    }
    
    func setDelay() {
        Clipboard.instance.setDelay(clipboardDelay)
    }
    
    func logOut() {
        /*
         * Check if the var has a callback and check if
         * the callback was successful
         */
        if let info = cb_logout?() {
            if (info) {
                ClientwardenWindow.instance.getState()
                SidePanel.instance.closeItem()
                ItemsPanel.instance.elements = []
                ItemsPanel.instance.filteredElements = []
                ItemsPanel.instance.searchQuery = ""
            } else {
                ToastStore.instance.toasts.append(Toast(message: "Failed to Log Out"))
            }
        } else {
            ToastStore.instance.toasts.append(Toast(message: "No callback set for logOut"))
        }
    }
}

struct WindowAccessor: NSViewRepresentable {
    @Binding var window: NSWindow?

    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        DispatchQueue.main.async {
            self.window = view.window
        }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {}
}

struct SettingsView: View {
    @Bindable var data: SettingsPanel = SettingsPanel.instance
    @Environment(\.dismissWindow) private var dismissWindow
    @State private var showLogout: Bool = false
    @FocusState private var isFocused: Bool
    @State private var thisWindow: NSWindow?
    
    var body: some View {
        VStack(alignment: .leading) {
            Stepper("Clipboard Delay: \(data.clipboardDelay)s", value: Binding(
                get: { data.clipboardDelay },
                set: {
                    data.clipboardDelay = $0
                    data.setDelay()
                }
            ), in: 0...3600)
            .padding(6)
            .padding(.leading, 4)
            .textFieldStyle(.plain)
            .frame(width: 200)
            .glassEffect(.regular.interactive())
            .focused($isFocused)
            .onExitCommand {
                isFocused = false
            }
            
            Button {
                showLogout = true
            } label: {
                Label("Log Out", systemImage: "")
            }
            .padding(.leading, -4)
            .buttonStyle(BorderlessButtonStyle())
            .alert("Are you sure you want to log out?", isPresented: $showLogout) {
                Button("Cancel", role: .cancel) { }
                Button("Log Out", role: .destructive) {
                    let windowToClose = thisWindow
                    data.logOut()
                    windowToClose?.close()
                }
            } message: {
                Text("This will remove your local vault (and all your local changes) and force you to sign back in!")
            }
            
            Spacer()
        }
        .background(WindowAccessor(window: $thisWindow))
        .padding(8)
        .frame(minWidth: 300, maxWidth: 300, minHeight: 400, maxHeight: 400, alignment: .leading)
        .onAppear {
            SettingsBridge.setupCallbacks()
            data.getInfo()
        }
        .task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                if (!Task.isCancelled) {
                    data.getInfo()
                }
            }
        }
    }
}

#Preview {
    SettingsView()
}
