import SwiftUI

@Observable
final class SettingsPanel {
    static let instance = SettingsPanel()
    
    public var clipboardDelay: String = "30"
    
    public var cb_getInfo: (() -> (String, Bool))?
    public var cb_setDelay: ((String) -> Bool)?
    public var cb_logout: (() -> Bool)?
    
    func getInfo() {
        /*
         * Check if the var has a callback and check if
         * the callback was successful
         */
        if let info = cb_getInfo?() {
            if (info.1) {
                clipboardDelay = info.0
            } else {
                ToastStore.instance.toasts.append(Toast(message: "Failed to Get Info"))
            }
        } else {
            ToastStore.instance.toasts.append(Toast(message: "No callback set for getInfo"))
        }
    }
    
    func setDelay() {
        /*
         * Check if the var has a callback and check if
         * the callback was successful
         */
        if let info = cb_setDelay?(clipboardDelay) {
            if (info) {
            } else {
                ToastStore.instance.toasts.append(Toast(message: "Failed to Set Clipboard Delay"))
            }
        } else {
            ToastStore.instance.toasts.append(Toast(message: "No callback set for setClipboardDelay"))
        }
    }
    
    func logOut() {
        /*
         * Check if the var has a callback and check if
         * the callback was successful
         */
        if let info = cb_logout?() {
            if (info) {
            } else {
                ToastStore.instance.toasts.append(Toast(message: "Failed to Log Out"))
            }
        } else {
            ToastStore.instance.toasts.append(Toast(message: "No callback set for logOut"))
        }
    }
}

struct SettingsView: View {
    @Bindable var data: SettingsPanel = SettingsPanel.instance
    @State private var showLogout: Bool = false
    @FocusState private var isFocused: Bool
    
    var body: some View {
        VStack(alignment: .leading) {
            Text("Clipboard Delay")
                .padding(.leading, 4)
            TextField("Clipboard Delay", text:
                Binding(
                    get: { data.clipboardDelay },
                    set: {
                        data.clipboardDelay = $0
                        data.setDelay()
                    }
                )
            )
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
                    data.logOut()
                }
            } message: {
                Text("This will remove your local vault and force you to sign back in!")
            }
            
            Spacer()
        }
        .padding(8)
        .frame(minWidth: 300, maxWidth: 300, minHeight: 400, maxHeight: 400, alignment: .leading)
        .onAppear {
            data.getInfo()
        }
    }
}

#Preview {
    SettingsView()
}
