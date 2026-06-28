import SwiftUI

@Observable
final class Login {
    static let instance = Login()
    
    public var vaultURL: String = "https://vault.bitwarden.com" {
        didSet {
            if (!mainChanged) {
                _mainURL = vaultURL
            }
            if (!apiChanged) {
                _apiURL = vaultURL
            }
            if (!wssChanged) {
                _wssURL = "wss://" + removeProt(url: vaultURL)
            }
        }
    }
    
    public var _mainURL: String = "https://bitwarden.com"
    public var _apiURL: String = "https://api.bitwarden.com"
    public var _wssURL: String = "wss://vault.bitwarden.com"
    
    public var mainChanged: Bool = false
    public var apiChanged: Bool = false
    public var wssChanged: Bool = false
    
    var mainURL: String {
        get { _mainURL }
        set { _mainURL = newValue; mainChanged = true }
    }
    var apiURL: String {
        get { _apiURL }
        set { _apiURL = newValue; apiChanged = true }
    }
    var wssURL: String {
        get { _wssURL }
        set { _wssURL = newValue; wssChanged = true }
    }
    public var iconURL: String = "https://icons.bitwarden.net"
    
    private func removeProt(url: String) -> String {
        if let range = url.range(of: "://") {
            return String(url[range.upperBound...])
        }
        return url
    }
    
    public var EmailPasswordView: Bool = true
    
    public var email: String = ""
    public var password: String = ""
    public var totp: String = ""
    
    func clearData() {
        email = ""
        password = ""
        totp = ""
    }
    
    public var cb_login: ((String, String, String, String, String, String, String) -> Bool)?
    public var cb_submitTOTP: ((String) -> Bool)?
    
    /*
     * Callback Functions
     */
    func login() {
        /*
         * Check if the var has a callback and check if
         * the callback was successful
         */
        if let res = cb_login?(email, password, vaultURL, mainURL, apiURL, wssURL, iconURL) {
            if (res) {
            } else {
                g_toastStore.toasts.append(Toast(message: "Failed to login"))
            }
        } else {
            g_toastStore.toasts.append(Toast(message: "No callback set for login"))
        }
    }
    
    func submitTOTP() {
        /*
         * Check if the var has a callback and check if
         * the callback was successful
         */
        if let res = cb_submitTOTP?(totp) {
            if (res) {
            } else {
                g_toastStore.toasts.append(Toast(message: "Failed to submit Code"))
            }
        } else {
            g_toastStore.toasts.append(Toast(message: "No callback set for submitCode"))
        }
    }
}

struct LoginView: View {
    @Bindable private var data: Login = Login.instance
    
    var body: some View {
        HStack {
            VStack(alignment: .leading) {
                TabView {
                    Tab("Bitwarden", systemImage: "lock.open") {
                        Text("Vault URL")
                            .padding(.leading, 4)
                            .padding(.top, 4)
                            .font(.caption)
                            .frame(maxWidth: 200, alignment: .leading)
                        TextField("Vault URL", text: $data.vaultURL)
                            .onAppear {
                                data.vaultURL = "https://vault.bitwarden.com"
                                data._mainURL = "https://bitwarden.com"
                                data._apiURL = "https://api.bitwarden.com"
                                data._wssURL = "wss://someVault.com"
                                data.mainChanged = true
                                data.apiChanged = true
                                data.wssChanged = true
                            }
                        
                        Text("Main URL")
                            .padding(.leading, 4)
                            .padding(.top, 4)
                            .font(.caption)
                            .frame(maxWidth: 200, alignment: .leading)
                        TextField("Main URL", text: $data.mainURL)
                        
                        Text("API URL")
                            .padding(.leading, 4)
                            .padding(.top, 4)
                            .font(.caption)
                            .frame(maxWidth: 200, alignment: .leading)
                        TextField("API URL", text: $data.apiURL)
                        
                        Text("Icon URL")
                            .padding(.leading, 4)
                            .padding(.top, 4)
                            .font(.caption)
                            .frame(maxWidth: 200, alignment: .leading)
                        TextField("Icon URL", text: $data.iconURL)
                        
                        Text("WebSocket URL")
                            .padding(.leading, 4)
                            .padding(.top, 4)
                            .font(.caption)
                            .frame(maxWidth: 200, alignment: .leading)
                        TextField("WebSocket URL", text: $data.wssURL)
                        Spacer()
                    }
                    Tab("Server", systemImage: "server.rack") {
                        Text("Vault URL")
                            .padding(.leading, 4)
                            .padding(.top, 4)
                            .font(.caption)
                            .frame(maxWidth: 200, alignment: .leading)
                        TextField("Vault URL", text: $data.vaultURL)
                            .onAppear {
                                data.vaultURL = "https://someVault.com"
                                data._mainURL = "https://someVault.com"
                                data._apiURL = "https://someVault.com"
                                data._wssURL = "wss://someVault.com"
                                data.mainChanged = false
                                data.apiChanged = false
                                data.wssChanged = false
                            }
                        
                        Text("Main URL")
                            .padding(.leading, 4)
                            .padding(.top, 4)
                            .font(.caption)
                            .frame(maxWidth: 200, alignment: .leading)
                        TextField("Main URL", text: $data.mainURL)
                        
                        Text("API URL")
                            .padding(.leading, 4)
                            .padding(.top, 4)
                            .font(.caption)
                            .frame(maxWidth: 200, alignment: .leading)
                        TextField("API URL", text: $data.apiURL)
                        
                        Text("Icon URL")
                            .padding(.leading, 4)
                            .padding(.top, 4)
                            .font(.caption)
                            .frame(maxWidth: 200, alignment: .leading)
                        TextField("Icon URL", text: $data.iconURL)
                        
                        Text("WebSocket URL")
                            .padding(.leading, 4)
                            .padding(.top, 4)
                            .font(.caption)
                            .frame(maxWidth: 200, alignment: .leading)
                        TextField("WebSocket URL", text: $data.wssURL)
                        Spacer()
                    }
                }
                .tabViewStyle(.automatic)
            }
            .frame(maxWidth: 200, maxHeight: .infinity)
            .padding(8)
            .glassEffect(.regular.interactive(), in: .rect(cornerRadius: 8))
            .padding(8)
            
            Spacer()
            
            VStack {
                if (data.EmailPasswordView) {
                    Text("Clientwarden")
                        .font(.largeTitle.bold())
                    TextField("Email", text: $data.email)
                        .font(.subheadline)
                        .padding(6)
                        .textFieldStyle(.plain)
                        .frame(width: 200)
                        .glassEffect(.regular.interactive(), in: .rect(cornerRadius: 8))
                    TextField("Password", text: $data.password)
                        .font(.subheadline)
                        .padding(6)
                        .textFieldStyle(.plain)
                        .frame(width: 200)
                        .glassEffect(.regular.interactive(), in: .rect(cornerRadius: 8))
                    Button {
                        data.login()
                    } label: {
                        Text(verbatim: "Login")
                            .font(.subheadline)
                            .foregroundStyle(Color.gray)
                    }
                    .buttonStyle(.plain)
                    .padding(6)
                    .frame(width: 200)
                    .glassEffect(.regular.interactive(), in: .rect(cornerRadius: 8))
                } else {
                    Text("Clientwarden")
                        .font(.largeTitle.bold())
                    TextField("TOTP Code", text: .constant(""))
                        .font(.subheadline)
                        .padding(6)
                        .textFieldStyle(.plain)
                        .frame(width: 200)
                        .glassEffect(.regular.interactive(), in: .rect(cornerRadius: 8))
                    Button {
                        data.submitTOTP()
                    } label: {
                        Text(verbatim: "Submit")
                            .font(.subheadline)
                            .foregroundStyle(Color.gray)
                    }
                    .buttonStyle(.plain)
                    .padding(6)
                    .frame(width: 200)
                    .glassEffect(.regular.interactive(), in: .rect(cornerRadius: 8))
                }
            }
            
            Spacer()
        }
        .frame(minWidth: 700, maxWidth: 700, minHeight: 400, maxHeight: 400)
    }
}

#Preview {
    LoginView()
        .frame(minWidth: 700, minHeight: 400)
}
