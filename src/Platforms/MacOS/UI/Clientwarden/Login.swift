import SwiftUI

@objc
enum LoginViewType: Int {
    case Login
    case TOTP
    case Passkey
}

enum LoginFields: Hashable {
    case Email
    case Password
    case Login
    
    case UsePasskey
    case CancelPasskey
    
    case Code
    case SubmitCode
    case VaultURL
    case MainURL
    case APIURL
    case IconURL
    case WebSocketURL
}

@objcMembers
@Observable
final class Login: NSObject {
    static let instance = Login()
    
    public var vaultURL: String = "https://vault.bitwarden.com" {
        didSet {
            if (!mainChanged && selectedTab == 1) {
                _mainURL = vaultURL
            }
            if (!apiChanged && selectedTab == 1) {
                _apiURL = vaultURL
            }
            if (!wssChanged && selectedTab == 1) {
                _wssURL = "wss://" + removeProt(url: vaultURL) + "/notifications"
            }
        }
    }
    
    public var _mainURL: String = "https://vault.bitwarden.com"
    public var _apiURL: String = "https://api.bitwarden.com"
    public var _wssURL: String = "wss://notifications.bitwarden.com"
    
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
    
    @objc public var ViewType: LoginViewType = .Login

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
    @objc public var cb_usePasskey: (() -> Bool)?
    
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
    
    func usePasskey() {
        if let res = cb_usePasskey?() {
            if (!res) {
                ToastStore.instance.toasts.append(Toast(message: "Failed to use Passkey"))
            }
        } else {
            ToastStore.instance.toasts.append(Toast(message: "No callback set for New Item"))
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
    @FocusState private var focusedField: LoginFields?
    
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
                            .focused($focusedField, equals: .VaultURL)
                        
                        Text("Main URL")
                            .padding(.leading, 4)
                            .padding(.top, 4)
                            .font(.caption)
                            .frame(maxWidth: 200, alignment: .leading)
                        TextField("Main URL", text: $data.mainURL)
                            .focused($focusedField, equals: .MainURL)
                        
                        Text("API URL")
                            .padding(.leading, 4)
                            .padding(.top, 4)
                            .font(.caption)
                            .frame(maxWidth: 200, alignment: .leading)
                        TextField("API URL", text: $data.apiURL)
                            .focused($focusedField, equals: .APIURL)
                        
                        Text("Icon URL")
                            .padding(.leading, 4)
                            .padding(.top, 4)
                            .font(.caption)
                            .frame(maxWidth: 200, alignment: .leading)
                        TextField("Icon URL", text: $data.iconURL)
                            .focused($focusedField, equals: .IconURL)
                        
                        Text("WebSocket URL")
                            .padding(.leading, 4)
                            .padding(.top, 4)
                            .font(.caption)
                            .frame(maxWidth: 200, alignment: .leading)
                        TextField("WebSocket URL", text: $data.wssURL)
                            .focused($focusedField, equals: .WebSocketURL)
                        Spacer()
                    }
                    Tab("Server", systemImage: "server.rack", value: 1) {
                        Text("Vault URL")
                            .padding(.leading, 4)
                            .padding(.top, 4)
                            .font(.caption)
                            .frame(maxWidth: 200, alignment: .leading)
                        TextField("Vault URL", text: $data.vaultURL)
                            .focused($focusedField, equals: .VaultURL)
                        
                        Text("Main URL")
                            .padding(.leading, 4)
                            .padding(.top, 4)
                            .font(.caption)
                            .frame(maxWidth: 200, alignment: .leading)
                        TextField("Main URL", text: $data.mainURL)
                            .focused($focusedField, equals: .MainURL)
                        
                        Text("API URL")
                            .padding(.leading, 4)
                            .padding(.top, 4)
                            .font(.caption)
                            .frame(maxWidth: 200, alignment: .leading)
                        TextField("API URL", text: $data.apiURL)
                            .focused($focusedField, equals: .APIURL)
                        
                        Text("Icon URL")
                            .padding(.leading, 4)
                            .padding(.top, 4)
                            .font(.caption)
                            .frame(maxWidth: 200, alignment: .leading)
                        TextField("Icon URL", text: $data.iconURL)
                            .focused($focusedField, equals: .IconURL)
                        
                        Text("WebSocket URL")
                            .padding(.leading, 4)
                            .padding(.top, 4)
                            .font(.caption)
                            .frame(maxWidth: 200, alignment: .leading)
                        TextField("WebSocket URL", text: $data.wssURL)
                            .focused($focusedField, equals: .WebSocketURL)
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
                        data._wssURL = "wss://someVault.com/notifications"
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
                if (data.ViewType == LoginViewType.Login) {
                    Text("Clientwarden")
                        .font(.largeTitle.bold())
                    TextField("Email", text: $data.email)
                        .font(.subheadline)
                        .padding(6)
                        .textFieldStyle(.plain)
                        .frame(width: 200)
                        .glassEffect(.regular.interactive(), in: .rect(cornerRadius: 8))
                        .focused($focusedField, equals: .Email)
                    SecureField("Password", text: $data.password)
                        .font(.subheadline)
                        .padding(6)
                        .textFieldStyle(.plain)
                        .frame(width: 200)
                        .glassEffect(.regular.interactive(), in: .rect(cornerRadius: 8))
                        .focused($focusedField, equals: .Password)
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
                    .focusable()
                    .focused($focusedField, equals: .Login)
                } else if (data.ViewType == LoginViewType.Passkey) {
                    Text("Clientwarden")
                        .font(.largeTitle.bold())
                        .padding(.bottom, 8)
                    Text("Use Passkey to Continue")
                        .font(.subheadline)
                    HStack {
                        Button {
                            withAnimation {
                                data.usePasskey()
                            }
                        } label: {
                            Text(verbatim: "Use Passkey")
                                .font(.subheadline)
                                .foregroundStyle(Color.gray)
                                .frame(maxWidth: .infinity)
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .padding(6)
                        .frame(width: 100)
                        .glassEffect(.regular.interactive(), in: .rect(cornerRadius: 8))
                        .contentShape(Rectangle())
                        .keyboardShortcut(.defaultAction)
                        .focusable()
                        .focused($focusedField, equals: .UsePasskey)
                        
                        Button {
                            withAnimation {
                                data.ViewType = .Login
                            }
                        } label: {
                            Text(verbatim: "Cancel")
                                .font(.subheadline)
                                .foregroundStyle(Color.gray)
                                .frame(maxWidth: .infinity)
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .padding(6)
                        .frame(width: 100)
                        .glassEffect(.regular.interactive(), in: .rect(cornerRadius: 8))
                        .contentShape(Rectangle())
                        .keyboardShortcut(.defaultAction)
                        .focusable()
                        .focused($focusedField, equals: .CancelPasskey)
                    }
                } else {
                    Text("Clientwarden")
                        .font(.largeTitle.bold())
                    TextField("Code", text: $data.code)
                        .font(.subheadline)
                        .padding(6)
                        .textFieldStyle(.plain)
                        .frame(width: 200)
                        .glassEffect(.regular.interactive(), in: .rect(cornerRadius: 8))
                        .focused($focusedField, equals: .Code)
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
                    .focusable()
                    .focused($focusedField, equals: .SubmitCode)
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
        .onKeyPress(.tab) {
            switch focusedField {
            case .Email where data.ViewType == .Login:
                focusedField = .Password
                return .handled
            case .Password where data.ViewType == .Login:
                focusedField = .Login
                return .handled
            case .Login where data.ViewType == .Login:
                focusedField = .VaultURL
                return .handled
            
            case .UsePasskey where data.ViewType == .Passkey:
                focusedField = .CancelPasskey
                return .handled
            case .CancelPasskey where data.ViewType == .Passkey:
                focusedField = .VaultURL
                return .handled
            
            case .Code where data.ViewType == .TOTP:
                focusedField = .SubmitCode
                return .handled
            case .SubmitCode where data.ViewType == .TOTP:
                focusedField = .VaultURL
                return .handled
            
            case .VaultURL:
                focusedField = .MainURL
                return .handled
            case .MainURL:
                focusedField = .APIURL
                return .handled
            case .APIURL:
                focusedField = .IconURL
                return .handled
            case .IconURL:
                focusedField = .WebSocketURL
                return .handled
            case .WebSocketURL:
                if (data.ViewType == .Login) {
                    focusedField = .Email
                } else if (data.ViewType == .Passkey) {
                    focusedField = .UsePasskey
                } else if (data.ViewType == .TOTP) {
                    focusedField = .Code
                }
                return .handled
            default:
                return .ignored
            }
        }
        .onExitCommand {
            focusedField = nil
        }
        .onChange(of: data.ViewType) { _, newValue in
            if (data.ViewType == .Login) {
                focusedField = .Email
            } else if (data.ViewType == .Passkey) {
                focusedField = .UsePasskey
            } else if (data.ViewType == .TOTP) {
                focusedField = .Code
            } else {
                focusedField = nil
            }
        }
        .onAppear {
            DispatchQueue.main.async {
                if (data.ViewType == .Login) {
                    focusedField = .Email
                } else if (data.ViewType == .Passkey) {
                    focusedField = .UsePasskey
                } else if (data.ViewType == .TOTP) {
                    focusedField = .Code
                } else {
                    focusedField = nil
                }
            }
        }
    }
}

#Preview {
    LoginView()
        .frame(minWidth: 700, minHeight: 400)
}
