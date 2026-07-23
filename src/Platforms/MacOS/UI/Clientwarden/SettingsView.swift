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
    public var allowScreenshots: Bool = false
    
    @objc public var cb_logout: (() -> Bool)?
    @objc public var cb_getScrshot: (() -> Bool)?
    @objc public var cb_setScrshot: ((Bool) -> Bool)?
    
    var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "Unknown"
    }

    var buildNumber: String {
        Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "Unknown"
    }
    
    func getInfo() {
        clipboardDelay = Clipboard.instance.getDelay()
        allowScreenshots = getScrshot()
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
    
    func setScrshot(option: Bool) {
        /*
         * Check if the var has a callback and check if
         * the callback was successful
         */
        if let res = cb_setScrshot?(option) {
            if (res) {
            } else {
                ToastStore.instance.toasts.append(Toast(message: "Failed to Set Screenshot Value"))
            }
        } else {
            ToastStore.instance.toasts.append(Toast(message: "No callback set for Set Screenshot Option"))
        }
    }
    
    func getScrshot() -> Bool {
        /*
         * Check if the var has a callback and check if
         * the callback was successful
         */
        if let res = cb_getScrshot?() {
            return res
        }
        return false
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
            VStack(alignment: .leading) {
                HStack {
                    Text("Clipboard Delay")
                        .padding(12)
                    
                    Spacer()
                    
                    TextField("", text: Binding(
                        get: { String(data.clipboardDelay) },
                        set: { newValue in
                            if let value = Int(newValue) {
                                data.clipboardDelay = value
                                data.setDelay()
                            } else if newValue.isEmpty {
                                data.clipboardDelay = 30
                                data.setDelay()
                            }
                        }
                    ))
                    .frame(width: 60, alignment: .trailing)
                    .multilineTextAlignment(.trailing)
                    .textFieldStyle(.plain)
                    .padding(.trailing, 12)
                    .focused($isFocused)
                    .onExitCommand {
                        isFocused = false
                    }
                }
                .padding(.bottom, -10)
                
                Divider()
                
                HStack {
                    Text("Allow Screenshots")
                        .padding(12)
                    
                    Spacer()
                    
                    Toggle("Allow Screenshots", isOn: Binding(
                        get: {
                            return data.allowScreenshots
                        },
                        set: {
                            data.setScrshot(option: $0)
                            data.allowScreenshots = data.getScrshot()
                        }
                    ))
                    .toggleStyle(.switch)
                    .labelsHidden()
                    .padding(.trailing, 12)
                }
                .padding(.top, -10)
                .padding(.bottom, -10)
                
                Divider()
                
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
                .padding(10)
                .padding(.top, -10)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .glassEffect(.regular, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            
            Spacer()
            
            HStack {
                Text("Clientwarden \(data.buildNumber)")
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false)
                    .font(.caption)
                    .foregroundStyle(.gray)
                Text("Made By CT5")
                    .frame(maxWidth: .infinity, alignment: .trailing)
                    .foregroundStyle(.gray)
                    .font(.caption)
            }
        }
        .background(WindowAccessor(window: $thisWindow))
        .padding(8)
        .frame(minWidth: 300, maxWidth: 300, minHeight: 400, maxHeight: 400, alignment: .leading)
        .task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                if (!Task.isCancelled) {
                    data.getInfo()
                }
            }
        }
        .onChange(of: thisWindow) { _, newWindow in
            newWindow?.title = "Settings"
        }
    }
}

#Preview {
    SettingsView()
}
