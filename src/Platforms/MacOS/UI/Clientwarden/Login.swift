import SwiftUI

@objcMembers
@Observable
final class Login: NSObject {
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
    
    @objc public var EmailPasswordView: Bool = true

    public var selectedTab: Int = 0
    public var defaults: Bool = false
    
    public var email: String = ""
    public var password: String = ""
    public var code: String = ""
    
    func clearData() {
        email = ""
        password = ""
        code = ""
    }
    
    @objc public var cb_login: ((String, String, String, String, String, String, String) -> Bool)?
    @objc public var cb_submitCode: ((String) -> Bool)?
    
    /*
     * Callback Functions
     */
    func login() {
        let email = self.email
        let password = self.password
        let vaultURL = self.vaultURL
        let mainURL = self.mainURL
        let apiURL = self.apiURL
        let wssURL = self.wssURL
        let iconURL = self.iconURL
        self.password = ""
        self.code = ""
        ClientwardenWindow.instance.state = WindowState.Empty
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let res = self?.cb_login?(email, password, vaultURL, mainURL, apiURL, wssURL, iconURL)

            DispatchQueue.main.async {
                if let r_res = res {
                    if (r_res) {
                    } else {
                        /*
                         * We shouldn't need to put up a toast here
                         * since the toast will be handled by the func
                         * and there are diff toasts for diff situations
                        */
                        ClientwardenWindow.instance.state = WindowState.Login
                    }
                } else {
                    ToastStore.instance.toasts.append(Toast(message: "No callback set for submitCode"))
                    ClientwardenWindow.instance.state = WindowState.Login
                }
            }
        }
    }
    
    func submitCode() {
        let code = self.code
        self.password = ""
        self.code = ""
        ClientwardenWindow.instance.state = WindowState.Empty

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let res = self?.cb_submitCode?(code)

            DispatchQueue.main.async {
                if let r_res = res {
                    if (r_res) {
                    } else {
                        ToastStore.instance.toasts.append(Toast(message: "Failed to submit Code"))
                        ClientwardenWindow.instance.state = WindowState.Login
                    }
                } else {
                    ToastStore.instance.toasts.append(Toast(message: "No callback set for submitCode"))
                    ClientwardenWindow.instance.state = WindowState.Login
                }
            }
        }
    }
}

struct LoginView: View {
    @Bindable private var data: Login = Login.instance
    
    var body: some View {
        HStack {
            VStack(alignment: .leading) {
                TabView(selection: $data.selectedTab) {
                    Tab("Bitwarden", systemImage: "lock.open", value: 0) {
                        Text("Vault URL")
                            .padding(.leading, 4)
                            .padding(.top, 4)
                            .font(.caption)
                            .frame(maxWidth: 200, alignment: .leading)
                        TextField("Vault URL", text: $data.vaultURL)
                        
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
                    Tab("Server", systemImage: "server.rack", value: 1) {
                        Text("Vault URL")
                            .padding(.leading, 4)
                            .padding(.top, 4)
                            .font(.caption)
                            .frame(maxWidth: 200, alignment: .leading)
                        TextField("Vault URL", text: $data.vaultURL)
                        
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
                .onChange(of: data.selectedTab) { _, newTab in
                    if newTab == 0 {
                        data.vaultURL = "https://vault.bitwarden.com"
                        data._mainURL = "https://bitwarden.com"
                        data._apiURL = "https://api.bitwarden.com"
                        data._wssURL = "wss://vault.bitwarden.com"
                        data.mainChanged = true
                        data.apiChanged = true
                        data.wssChanged = true
                    } else if newTab == 1 {
                        data.vaultURL = "https://someVault.com"
                        data._mainURL = "https://someVault.com"
                        data._apiURL = "https://someVault.com"
                        data._wssURL = "wss://someVault.com"
                        data.mainChanged = false
                        data.apiChanged = false
                        data.wssChanged = false
                    }
                    data.defaults = true
                }
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
                    SecureField("Password", text: $data.password)
                        .font(.subheadline)
                        .padding(6)
                        .textFieldStyle(.plain)
                        .frame(width: 200)
                        .glassEffect(.regular.interactive(), in: .rect(cornerRadius: 8))
                    Button {
                        withAnimation {
                            data.login()
                        }
                    } label: {
                        Text(verbatim: "Login")
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
                } else {
                    Text("Clientwarden")
                        .font(.largeTitle.bold())
                    TextField("Code", text: $data.code)
                        .font(.subheadline)
                        .padding(6)
                        .textFieldStyle(.plain)
                        .frame(width: 200)
                        .glassEffect(.regular.interactive(), in: .rect(cornerRadius: 8))
                    Button {
                        withAnimation {
                            data.submitCode()
                        }
                    } label: {
                        Text(verbatim: "Submit")
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
            }
            
            Spacer()
        }
        .frame(minWidth: 700, maxWidth: 700, minHeight: 400, maxHeight: 400)
        .onAppear {
            #if NON_XCODE_BUILD
                LoginBridge.setupCallbacks()
            #endif
        }
    }
}

#Preview {
    LoginView()
        .frame(minWidth: 700, minHeight: 400)
}
