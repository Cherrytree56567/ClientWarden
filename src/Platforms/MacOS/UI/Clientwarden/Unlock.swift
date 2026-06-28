import SwiftUI

@Observable
final class Unlock {
    static let instance = Unlock()
    
    public var password: String = ""
    public var username: String = "Unknown"
    public var profilePic: ClientwardenImage = ClientwardenImage(type: ImageType.bundle, path: "profile1")
    
    func clearData() {
        password = ""
        username = ""
    }
    
    public var cb_getInfo: (() -> (String, ClientwardenImage, Bool))?
    public var cb_unlock: ((String) -> Bool)?
    
    /*
     * Callback Functions
     */
    func getInfo() {
        /*
         * Check if the var has a callback and check if
         * the callback was successful
         */
        if let res = cb_getInfo?() {
            if (res.2) {
            } else {
                g_toastStore.toasts.append(Toast(message: "Failed to get Profile Info"))
            }
        } else {
            g_toastStore.toasts.append(Toast(message: "No callback set for getInfo"))
        }
    }
    
    func unlock() {
        /*
         * Check if the var has a callback and check if
         * the callback was successful
         */
        if let res = cb_unlock?(password) {
            if (res) {
            } else {
                g_toastStore.toasts.append(Toast(message: "Failed to Unlock Vault"))
            }
        } else {
            g_toastStore.toasts.append(Toast(message: "No callback set for unlock"))
        }
    }
}

struct UnlockView: View {
    @Bindable private var data: Unlock = Unlock.instance
    
    init() {
        data.getInfo()
    }
    
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
                TextField("Password", text: $data.password)
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
                }
                .buttonStyle(.plain)
                .padding(6)
                .frame(width: 200)
                .glassEffect(.regular.interactive(), in: .rect(cornerRadius: 8))
            }
            
            Spacer()
        }
        .frame(minWidth: 300, maxWidth: 300, minHeight: 400, maxHeight: 400)
    }
}

#Preview {
    UnlockView()
        .frame(minWidth: 300, minHeight: 400)
}
