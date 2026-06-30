import SwiftUI

@objcMembers
@Observable
final class Unlock: NSObject {
    static let instance = Unlock()
    
    public var password: String = ""
    @objc public var username: String = "Unknown"
    @objc public var profilePic: ClientwardenImage = ClientwardenImage(type: ImageType.bundle, path: "profile1")
    
    func clearData() {
        password = ""
        username = ""
    }
    
    @objc public var cb_getInfo: (() -> Bool)?
    @objc public var cb_unlock: ((String) -> Bool)?
    
    /*
     * Callback Functions
     */
    func getInfo() {
        if let res = cb_getInfo?() {
            if (res) {
            } else {
                g_toastStore.toasts.append(Toast(message: "Failed to get Profile Info"))
                ClientwardenWindow.instance.state = WindowState.Unlock
            }
        } else {
            g_toastStore.toasts.append(Toast(message: "No callback set for getInfo"))
            ClientwardenWindow.instance.state = WindowState.Unlock
        }
    }
    
    func unlock() {
        let password = self.password
        ClientwardenWindow.instance.state = WindowState.Empty
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let res = self?.cb_unlock?(password)

            DispatchQueue.main.async {
                if let r_res = res {
                    if (r_res) {
                    } else {
                        g_toastStore.toasts.append(Toast(message: "Failed to Unlock Vault"))
                        ClientwardenWindow.instance.state = WindowState.Unlock
                    }
                } else {
                    g_toastStore.toasts.append(Toast(message: "No callback set for unlock"))
                    ClientwardenWindow.instance.state = WindowState.Unlock
                }
            }
        }
    }
}

struct UnlockView: View {
    @Bindable private var data: Unlock = Unlock.instance
    
    var body: some View {
        HStack {
            Spacer()
            
            VStack {
                HStack {
                    if let img = data.profilePic.getImage() {
                        img
                            .resizable()
                            .frame(width: 28, height: 28)
                            .clipShape(RoundedRectangle(cornerRadius: 4))
                    }
                    
                    Text(data.username)
                        .lineLimit(1)
                        .font(.largeTitle.bold())
                }
                .frame(width: 200)
                SecureField("Password", text: $data.password)
                    .font(.subheadline)
                    .padding(6)
                    .textFieldStyle(.plain)
                    .frame(width: 200)
                    .glassEffect(.regular.interactive(), in: .rect(cornerRadius: 8))
                Button {
                    data.unlock()
                } label: {
                    Text(verbatim: "Unlock")
                        .font(.subheadline)
                        .foregroundStyle(Color.gray)
                        .frame(maxWidth: .infinity)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .padding(6)
                .frame(width: 200)
                .glassEffect(.regular.interactive(), in: .rect(cornerRadius: 8))
                .contentShape(Rectangle())
                .keyboardShortcut(.defaultAction)
            }
            
            Spacer()
        }
        .frame(minWidth: 300, maxWidth: 300, minHeight: 400, maxHeight: 400)
        .onAppear {
            UnlockBridge.setupCallbacks()
            data.getInfo()
        }
    }
}

#Preview {
    UnlockView()
        .frame(minWidth: 300, minHeight: 400)
}
