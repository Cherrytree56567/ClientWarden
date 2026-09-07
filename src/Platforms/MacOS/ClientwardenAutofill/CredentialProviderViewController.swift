import os
import AppKit
import AuthenticationServices

/*
 * TODO: Add Mutex
 *  - Add
 */
class CredentialProviderViewController: ASCredentialProviderViewController {
    private var loginItems: [(uuid: String, title: String, username: String)] = []
    private var passkeyItems: [(uuid: String, title: String, username: String)] = []
    private var p_requestID: String = ""
    private var p_requestName: String = ""
    private var p_result: String?
    private var p_semaphore: DispatchSemaphore?
    private var c_relyingParty: String = ""
    private var c_clientDataHash: Data = Data()
    private var p_serviceIdentifers: [ASCredentialServiceIdentifier] = []

    @available(macOS 14.0, *)
    private var p_registration: (ASPasskeyCredentialRequest, ASPasskeyCredentialIdentity)?
    private var l_serviceIdentifiers: [ASCredentialServiceIdentifier] = []
    private var p_passwordIdentity: ASPasswordCredentialIdentity?
    
    let logger = Logger(subsystem: BundleInfo.sharedID, category: "AutoFill")

    /*
     * Clientwarden extension API stuff
     */
    func clientwardenAppRunning() -> Bool {
        return NSWorkspace.shared.runningApplications.contains {
            $0.bundleIdentifier == BundleInfo.appID
        }
    }

    func launchClientwardenApp() {
        guard let appURL = NSWorkspace.shared.urlForApplication(withBundleIdentifier: BundleInfo.appID) else {
            logger.error("Failed to locate Clientwarden App")
            return
        }

        guard let actionURL = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "clientwarden://autofillUnlock") else {
            logger.error("Failed to locate Clientwarden App")
            return
        }

        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = true

        NSWorkspace.shared.open([actionURL], withApplicationAt: appURL, configuration: configuration) { app, error in
            if let error {
                self.logger.error("Failed to launch Clientwarden App")
                return
            }
        }
    }

    func requestClientwarden(requestName: String, requestValue: String) -> String? {
        /*
         * Since the data that we share here can be sensitive, we must use
         * keychain for the request and data and stuff.
         *
         * btw Clientwarden used `com.ct5.clientwarden`, we must use
         * `app.ct5.clientwarden` for the extensions.
         */
        let requestID = UUID().uuidString
        
        p_requestID = requestID
        p_requestName = requestName
        p_result = nil
        p_semaphore = DispatchSemaphore(value: 0)
        
        let request: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccessGroup as String: BundleInfo.teamID + "." + BundleInfo.sharedID,
            kSecAttrAccount as String: requestID,
            kSecAttrService as String: BundleInfo.sharedID + "." + requestName,
            kSecValueData as String: requestValue.data(using: .utf8)!
        ]

        SecItemDelete(request as CFDictionary)
        SecItemAdd(request as CFDictionary, nil)

        /*
         * I had to use AI for this part. Only for some of it tho, not the response.
         *
         * To know if we have recieved data, we can setup a listener to let us
         * know if the request has been fulfilled. Then we can get the response,
         * set the result, delete the response and return.
         */
        let observer = UnsafeRawPointer(Unmanaged.passUnretained(self).toOpaque())
        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            observer,
            { _, p_observer, _, _, _ in
                guard let p_observer else {
                    return
                }
                
                let credProv = Unmanaged<CredentialProviderViewController>.fromOpaque(p_observer).takeUnretainedValue()
                
                let response: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrAccessGroup as String: BundleInfo.teamID + "." + BundleInfo.sharedID,
                    kSecAttrAccount as String: credProv.p_requestID,
                    kSecAttrService as String: BundleInfo.sharedID + "." + credProv.p_requestName,
                    kSecReturnData as String: true,
                    kSecMatchLimit as String: kSecMatchLimitOne
                ]

                var a_result: AnyObject?
                let status = SecItemCopyMatching(response as CFDictionary, &a_result)

                if status == errSecSuccess, let data = a_result as? Data {
                    credProv.p_result = String(data: data, encoding: .utf8)
                }

                credProv.p_semaphore?.signal()

                /*
                 * TODO: Put the actuall bundle id here
                 */
                let deleteRequest: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrAccessGroup as String: BundleInfo.teamID + "." + BundleInfo.sharedID,
                    kSecAttrAccount as String: credProv.p_requestID,
                    kSecAttrService as String: BundleInfo.sharedID + "." + credProv.p_requestName,
                ]

                SecItemDelete(deleteRequest as CFDictionary)
            },
            (BundleInfo.sharedID + "." + requestName) as CFString,
            nil,
            .deliverImmediately
        )

        /*
         * Post request notification to let ClientWarden know
         * that we need smth
         */
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName((BundleInfo.sharedID + ".request." + requestName) as CFString),
            nil, nil, true
        )

        /*
         * Wait for 1 s and then, either remove the listener
         * and fail or remove the listener and return the result
         */
        let w_result = p_semaphore?.wait(timeout: .now() + 1)

        CFNotificationCenterRemoveObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            observer,
            CFNotificationName((BundleInfo.sharedID + "." + requestName) as CFString),
            nil
        )

        if (w_result == .timedOut || w_result == nil) {
            logger.warning("Didn't Recieve response from App")
            return nil
        }

        return p_result
    }

    /*
     * Used to pass raw Data in B64 to the CW App
     */
    func requestClientwardenForData(requestName: String, requestValue: String) -> Data? {
        guard let s_res = requestClientwarden(requestName: requestName, requestValue: requestValue) else {
            return nil
        }
        return Data(base64Encoded: s_res)
    }
    
    /*
     * This func is used to know if the Vault is Locked or Unlocked
     */
    func clientwardenStatus() -> Bool {
        return requestClientwarden(requestName: "getState", requestValue: "") == "true"
    }

    private func getLogins(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        /*
         * Store a bunch of UUIDs for us to pass to the cw app to get the username's and title's
         * of the items.
         */
        var UUIDs: [String] = []

        /*
         * Loop through the websites that an app reports and ask the CW app for matching logins
         * and then add them to UUIDs
         */
        for serviceIdentifier in serviceIdentifiers {
            var s_UUIDs: String? = requestClientwarden(requestName: "getLogins", requestValue: serviceIdentifier.identifier);

            if let s_UUIDs, s_UUIDs != "" {
                UUIDs.append(contentsOf: s_UUIDs.components(separatedBy: ","))
            }
        }

        loginItems = []

        for l_uuid in UUIDs {
            var title: String? = requestClientwarden(requestName: "getTitle", requestValue: l_uuid);
            var username: String? = requestClientwarden(requestName: "getUsername", requestValue: l_uuid);

            loginItems.append((l_uuid, title ?? "Unknown", username ?? "Unknown"))
        }

        DispatchQueue.main.async {
            /*
             * First, we have to remove the
             * existing views
             */
            self.view.subviews.forEach { 
                $0.removeFromSuperview() 
            }
            
            /*
             * Show the items
             */
            let stack = NSStackView()
            stack.orientation = .vertical
            stack.alignment = .leading
            stack.spacing = 8
            stack.translatesAutoresizingMaskIntoConstraints = false

            for (index, item) in self.loginItems.enumerated() {
                let b_item = NSButton(title: (item.username.isEmpty ?
                                                  item.title :
                                                    "\(item.title) — \(item.username)"), target: self, action: #selector(self.passwordSelected(_:)))
                b_item.bezelStyle = .rounded
                b_item.tag = index
                stack.addArrangedSubview(b_item)
            }
            
            /*
             * From viewDidLoad
             */
            let button = NSButton(title: "Dismiss", target: self, action: #selector(self.cancel(_:)))
            button.bezelStyle = .rounded
            button.translatesAutoresizingMaskIntoConstraints = false
            stack.addArrangedSubview(button)
            
            self.view.addSubview(stack)
            
            NSLayoutConstraint.activate([
                stack.centerXAnchor.constraint(equalTo: self.view.centerXAnchor),
                stack.centerYAnchor.constraint(equalTo: self.view.centerYAnchor),
            ])
        }
    }

    @available(macOS 14.0, *)
    private func createPasskey(request: ASPasskeyCredentialRequest, identity: ASPasskeyCredentialIdentity) {
        /*
         * Generate a passkey here
         */
        var requestStr = identity.relyingPartyIdentifier.data(using: .utf8)!.base64EncodedString() + "," + 
                         identity.userName.data(using: .utf8)!.base64EncodedString() + "," + 
                         identity.userHandle.base64EncodedString() + "," + 
                         request.clientDataHash.base64EncodedString()
            
        var response: String? = requestClientwarden(requestName: "createPasskey", requestValue: requestStr);

        if (response != nil) {
            var responses = response!.components(separatedBy: ",")

            if (responses.count < 2) {
                extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.failed.rawValue))
                return
            }

            let credentialId = Data(base64Encoded: responses[0])
            let attestationObject = Data(base64Encoded: responses[1])

            if (credentialId == nil || attestationObject == nil) {
                extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.failed.rawValue))
                return
            }

            let credential = ASPasskeyRegistrationCredential(
                relyingParty: identity.relyingPartyIdentifier,
                clientDataHash: request.clientDataHash,
                credentialID: credentialId!,
                attestationObject: attestationObject!
            )

            extensionContext.completeRegistrationRequest(using: credential, completionHandler: nil)
        }
    }

    private func getPasskeys(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        /*
         * Store a bunch of UUIDs for us to pass to the cw app to get passkey's
         */
        var UUIDs: [String] = []

        /*
         * Loop through the websites that an app reports and ask the CW app for matching passkeys
         * and then add them to UUIDs
         */
        for serviceIdentifier in serviceIdentifiers {
            var s_UUIDs: String? = requestClientwarden(requestName: "getPasskeys", requestValue: serviceIdentifier.identifier);

            if let s_UUIDs, s_UUIDs != "" {
                UUIDs.append(contentsOf: s_UUIDs.components(separatedBy: ","))
            }
        }

        passkeyItems = []

        for l_uuid in UUIDs {
            var title: String? = requestClientwarden(requestName: "getTitle", requestValue: l_uuid);
            var username: String? = requestClientwarden(requestName: "getUsername", requestValue: l_uuid);

            passkeyItems.append((l_uuid, title ?? "Unknown", username ?? "Unknown"))
        }

        DispatchQueue.main.async {
            /*
             * First, we have to remove the
             * existing views
             */
            self.view.subviews.forEach { 
                $0.removeFromSuperview() 
            }
                
            /*
             * Show the items
             */
            let stack = NSStackView()
            stack.orientation = .vertical
            stack.alignment = .leading
            stack.spacing = 8
            stack.translatesAutoresizingMaskIntoConstraints = false

            for (index, item) in self.passkeyItems.enumerated() {
                let b_item = NSButton(title: (item.username.isEmpty ?
                                                  item.title :
                                                    "\(item.title) — \(item.username)"), target: self, action: #selector(self.passkeySelected(_:)))
                b_item.bezelStyle = .rounded
                b_item.tag = index
                stack.addArrangedSubview(b_item)
            }
                
            /*
             * From viewDidLoad
             */
            let button = NSButton(title: "Dismiss", target: self, action: #selector(self.cancel(_:)))
            button.bezelStyle = .rounded
            button.translatesAutoresizingMaskIntoConstraints = false
            stack.addArrangedSubview(button)
               
            self.view.addSubview(stack)
            
            NSLayoutConstraint.activate([
                stack.centerXAnchor.constraint(equalTo: self.view.centerXAnchor),
                stack.centerYAnchor.constraint(equalTo: self.view.centerYAnchor),
            ])
        }
    }

    /*
     * Mainly used for Quick Type
     * Assisted with Claude
     */
    private func getPassword(for credentialIdentity: ASPasswordCredentialIdentity) {
        guard let uuid = credentialIdentity.recordIdentifier, !uuid.isEmpty else {
            logger.error("Failed due to no record identifier")

            extensionContext.cancelRequest(
                withError: NSError(
                    domain: ASExtensionErrorDomain,
                    code: ASExtensionError.failed.rawValue
                )
            )
            return
        }
        /*
         * Fail if clientwarden isnt running or is locked
         */
        if (!clientwardenAppRunning() || clientwardenStatus()) {
            extensionContext.cancelRequest(
                withError: NSError(
                    domain: ASExtensionErrorDomain,
                    code: ASExtensionError.userInteractionRequired.rawValue
                )
            )
            return
        }

        /*
         * Get Username
         */
        guard let username = requestClientwarden(
            requestName: "getUsername",
            requestValue: uuid
        ) else {
            logger.error("Failed to get username")

            extensionContext.cancelRequest(
                withError: NSError(
                    domain: ASExtensionErrorDomain,
                    code: ASExtensionError.failed.rawValue
                )
            )

            return
        }

        /*
         * Get Password
         */
        guard let password = requestClientwarden(
            requestName: "getPassword",
            requestValue: uuid
        ) else {
            logger.error("Failed to get password")

            extensionContext.cancelRequest(
                withError: NSError(
                    domain: ASExtensionErrorDomain,
                    code: ASExtensionError.failed.rawValue
                )
            )
            return
        }

        /*
         * Create Cred
         */
        let credential = ASPasswordCredential(
            user: username,
            password: password
        )

        extensionContext.completeRequest(
            withSelectedCredential: credential,
            completionHandler: nil
        )
    }

    private func showLockedUI() {
        DispatchQueue.main.async {
            self.view.subviews.forEach { $0.removeFromSuperview() }

            let label = NSTextField(labelWithString: "Clientwarden is locked.\nUnlock to use AutoFill.")
            label.alignment = .center
            label.maximumNumberOfLines = 2

            let retryButton = NSButton(title: "Try Again", target: self, action: #selector(self.retryTapped(_:)))
            retryButton.bezelStyle = .rounded
            retryButton.keyEquivalent = "\r"

            let cancelButton = NSButton(title: "Cancel", target: self, action: #selector(self.cancel(_:)))
            cancelButton.bezelStyle = .rounded

            let stack = NSStackView(views: [label, retryButton, cancelButton])
            stack.orientation = .vertical
            stack.alignment = .centerX
            stack.spacing = 12
            stack.translatesAutoresizingMaskIntoConstraints = false

            self.view.addSubview(stack)
            NSLayoutConstraint.activate([
                stack.centerXAnchor.constraint(equalTo: self.view.centerXAnchor),
                stack.centerYAnchor.constraint(equalTo: self.view.centerYAnchor),
            ])
        }
    }

    /*
     * Cred Provider AutoFill Stuff
     */
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let button = NSButton(title: "Dismiss", target: self, action: #selector(cancel(_:)))
        button.bezelStyle = .rounded
        button.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(button)
        
        NSLayoutConstraint.activate([
            button.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            button.centerYAnchor.constraint(equalTo: view.centerYAnchor),
        ])
    }

    /*
     * Prepare your UI to list available credentials for the user to choose from. The items in
     * 'serviceIdentifiers' describe the service the user is logging in to, so your extension can
     * prioritize the most relevant credentials in the list.
     *
     *  * This one should be for getting Logins *
     */
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        l_serviceIdentifiers = serviceIdentifiers
        if (!clientwardenAppRunning() || clientwardenStatus()) { // Check if CW App is running but is locked
            showLockedUI()
            launchClientwardenApp()
        } else {
            getLogins(for: serviceIdentifiers)
        }
    }

    /*
     Implement this method if your extension supports showing credentials in the QuickType bar.
     When the user selects a credential from your app, this method will be called with the
     ASPasswordCredentialIdentity your app has previously saved to the ASCredentialIdentityStore.
     Provide the password by completing the extension request with the associated ASPasswordCredential.
     If using the credential would require showing custom UI for authenticating the user, cancel
     the request with error code ASExtensionError.userInteractionRequired.
    */
    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        getPassword(for: credentialIdentity)
    }
    

    /*
     Implement this method if provideCredentialWithoutUserInteraction(for:) can fail with
     ASExtensionError.userInteractionRequired. In this case, the system may present your extension's
     UI and call this method. Show appropriate UI for authenticating the user then provide the password
     by completing the extension request with the associated ASPasswordCredential.
    */
    override func prepareInterfaceToProvideCredential(for credentialIdentity: ASPasswordCredentialIdentity) {
        p_passwordIdentity = credentialIdentity

        if (!clientwardenAppRunning() || clientwardenStatus()) {
            showLockedUI()
            launchClientwardenApp()
        } else {
            p_passwordIdentity = nil
            getPassword(for: credentialIdentity)
        }
    }
    

    @objc
    func cancel(_ sender: AnyObject?) {
        self.extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userCanceled.rawValue))
    }

    @objc
    func passwordSelected(_ sender: AnyObject?) {
        if let button = sender as? NSButton {
            /*
             * Check if button has a valid
             * loginItem count thing.
             *
             * Then, we can get the item and
             * and the UUID which we can pass
             * to CW to retrieve the password
             */
            if (button.tag >= 0 && button.tag < loginItems.count) {
                var item = loginItems[button.tag]
                
                var password: String? = requestClientwarden(requestName: "getPassword", requestValue: item.uuid);
                
                if (password != nil) {
                    let p_cred = ASPasswordCredential(user: item.username, password: password!)
                    self.extensionContext.completeRequest(withSelectedCredential: p_cred, completionHandler: nil)
                    return
                }
            }
            
            /*
             * If we cant get the password
             * then we can return a failed
             * request
             */
            logger.error("Failed to get password")
            self.extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.failed.rawValue))
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    /*
     * Passkey Stuff
     * TODO: PLZ move this out
     */
    /*
     * From DashLane Example:
     * https://github.com/Dashlane/apple-credential-provider-example/blob/main/PasskeyProviderExtension/CredentialProviderViewController.swift
     * 
     * This is for generating a passkey
     */
    @available(macOS 14.0, *)
    override func prepareInterface(forPasskeyRegistration registrationRequest: ASCredentialRequest) {
        guard let request = registrationRequest as? ASPasskeyCredentialRequest,
              let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity else {
            extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.failed.rawValue))
            return
        }

        if (!clientwardenAppRunning() || clientwardenStatus()) { // Check if CW App is running but is locked
            p_registration = (request, identity)
            showLockedUI()
            launchClientwardenApp()
        } else {
            createPasskey(request: request, identity: identity)
        }
    }

    @objc private func retryTapped(_ sender: AnyObject?) {
        if let identity = p_passwordIdentity {
            p_passwordIdentity = nil
            getPassword(for: identity)
        } else if #available(macOS 14.0, *), let (request, identity) = p_registration {
            p_registration = nil
            createPasskey(request: request, identity: identity)
        } else if (!l_serviceIdentifiers.isEmpty) {
            getLogins(for: l_serviceIdentifiers)
        } else if #available(macOS 14.0, *), !p_serviceIdentifers.isEmpty {
            getPasskeys(for: p_serviceIdentifers)
        }
    }

    override func viewDidAppear() {
        super.viewDidAppear()
        NotificationCenter.default.removeObserver(self, name: NSApplication.didBecomeActiveNotification, object: nil)
        NotificationCenter.default.addObserver(
            self, selector: #selector(appBecameActive),
            name: NSApplication.didBecomeActiveNotification, object: nil
        )
    }

    @objc private func appBecameActive() {
        if (!clientwardenAppRunning() || clientwardenStatus()) {
            return
        }

        /*
         * Check if we should create a passkey or get Passkeys
         */
        if let identity = p_passwordIdentity {
            p_passwordIdentity = nil
            getPassword(for: identity)
        } else if #available(macOS 14.0, *), let (request, identity) = p_registration {
            p_registration = nil
            createPasskey(request: request, identity: identity)
        } else if #available(macOS 14.0, *), (!p_serviceIdentifers.isEmpty) {
            getPasskeys(for: p_serviceIdentifers)
        }
    }

    /*
     * This is for getting passkeys
     */
    @available(macOS 14.0, *)
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier], requestParameters: ASPasskeyCredentialRequestParameters) {        
        c_relyingParty = requestParameters.relyingPartyIdentifier
        c_clientDataHash = requestParameters.clientDataHash
        p_serviceIdentifers = serviceIdentifiers

        if (!clientwardenAppRunning() || clientwardenStatus()) { // Check if CW App is running but is locked
            showLockedUI()
            launchClientwardenApp()
        } else {
            getPasskeys(for: p_serviceIdentifers)
        }
    }

    /*
     * Get Passkey Data
     */
    @objc
    @available(macOS 14.0, *)
    func passkeySelected(_ sender: AnyObject?) {
        if let button = sender as? NSButton {
            /*
             * Check if button has a valid
             * loginItem count thing.
             *
             * Then, we can get the item and
             * and the UUID which we can pass
             * to CW to retrieve the passkey
             */
            if (button.tag >= 0 && button.tag < passkeyItems.count) {
                var item = passkeyItems[button.tag]
                
                var p_info: String? = requestClientwarden(requestName: "getPasskeyInfo", requestValue: item.uuid);
                
                if (p_info != nil) {
                    var responses = p_info!.components(separatedBy: ",")

                    if (responses.count < 4) {
                        logger.error("Failed to get response from getPasskeyInfo")
                        self.extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.failed.rawValue))
                    }

                    let userHandle = Data(base64Encoded: responses[0])
                    let signature = Data(base64Encoded: responses[1])
                    let authenticatorData = Data(base64Encoded: responses[2])
                    let credentialID = Data(base64Encoded: responses[3])

                    if (userHandle == nil || signature == nil || authenticatorData == nil || credentialID == nil) {
                        logger.error("Failed to get b64 Decoded stuff")
                        self.extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.failed.rawValue))
                        return
                    }

                    let p_cred = ASPasskeyAssertionCredential(
                        userHandle: userHandle!,
                        relyingParty: c_relyingParty,
                        signature: signature!,
                        clientDataHash: c_clientDataHash,
                        authenticatorData: authenticatorData!,
                        credentialID: credentialID!
                    )

                    self.extensionContext.completeAssertionRequest(using: p_cred, completionHandler: nil)
                    return
                }
            }
            
            /*
             * If we cant get the passkey
             * then we can return a failed
             * request
             */
            logger.error("Failed to get passkey")
            self.extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.failed.rawValue))
        }
    }
}
