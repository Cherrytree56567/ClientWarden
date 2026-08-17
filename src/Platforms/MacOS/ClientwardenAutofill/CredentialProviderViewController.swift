import AuthenticationServices

class CredentialProviderViewController: ASCredentialProviderViewController {

    /*
     * Clientwarden extension API stuff
     */
    func clientwardenAppRunning() -> Bool {
        return NSWorkspace.shared.runningApplications.contains {
            $0.bundleIdentifier == "com.ct5.clientwarden"
        }
    }

    func launchClientwardenApp() {
        guard let appURL = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.ct5.clientwarden") else {
            /*
             * Failed to locate Clientwarden App
             */
            return
        }

        guard let actionURL = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "clientwarden://autofillUnlock") else {
            /*
             * Failed to locate Clientwarden App
             */
            return
        }

        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = true

        NSWorkspace.shared.openApplication([actionURL], withApplicationAt: appURL, configuration: configuration) { app, error in
            if let error {
                /*
                 * Failed to launch Clientwarden App
                 */
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
        let request: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccessGroup as String: "ID.app.ct5.clientwarden",
            kSecAttrAccount as String: requestID,
            kSecAttrService as String: "app.ct5.clientwarden." + requestName,
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
        let semaphore = DispatchSemaphore(value: 0)
        var result: String?
        let observer = UnsafeRawPointer(Unmanaged.passUnretained(self).toOpaque())
        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            observer,
            { _, _, _, _, _ in
                let response: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrAccessGroup as String: "ID.app.ct5.clientwarden",
                    kSecAttrAccount as String: requestID,
                    kSecAttrService as String: "app.ct5.clientwarden." + requestName,
                    kSecReturnData as String: true,
                    kSecMatchLimit as String: kSecMatchLimitOne
                ]

                var a_result: AnyObject?
                let status = SecItemCopyMatching(response as CFDictionary, &a_result)

                if status == errSecSuccess, let data = a_result as? Data {
                    result = String(data: data, encoding: .utf8)
                }

                semaphore.signal()

                /*
                 * TODO: Put the actuall bundle id here
                 */
                let deleteRequest: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrAccessGroup as String: "ID.app.ct5.clientwarden",
                    kSecAttrAccount as String: requestID,
                    kSecAttrService as String: "app.ct5.clientwarden." + requestName,
                ]

                SecItemDelete(deleteRequest as CFDictionary)
            },
            ("app.ct5.clientwarden." + requestName) as CFString,
            nil,
            .deliverImmediately
        )

        /*
         * Post request notification to let ClientWarden know
         * that we need smth
         */
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName(("app.ct5.clientwarden.request." + requestName) as CFString),
            nil, nil, true
        )

        /*
         * Wait for 5 s and then, either remove the listener
         * and fail or remove the listener and return the result
         */
        let w_result = semaphore.wait(timeout: .now() + 5)

        CFNotificationCenterRemoveObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            observer,
            CFNotificationName(("app.ct5.clientwarden." + requestName) as CFString),
            nil
        )

        if (w_result == .timedOut) {
            return nil
        }

        return result
    }

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
     Prepare your UI to list available credentials for the user to choose from. The items in
     'serviceIdentifiers' describe the service the user is logging in to, so your extension can
     prioritize the most relevant credentials in the list.
    */
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        if (!clientwardenAppRunning()) {
            launchClientwardenApp()
        } else if (false) { // TODO: Check if CW App is running but is locked
            launchClientwardenApp()
        } else {
            /*
             * Store a bunch of UUIDs for us to pass to the cw app to get the username's and title's
             * of the items.
             */
            var UUIDs: [String]

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

            //               UUID  , Title , Username
            var loginItems: [(String, String, String)] = []

            for l_uuid in UUIDs {
                var title: String? = requestClientwarden(requestName: "getTitle", requestValue: l_uuid);
                var username: String? = requestClientwarden(requestName: "getUsername", requestValue: l_uuid);

                loginItems.append((l_uuid, title, username));
            }
        }
    }

    /*
     Implement this method if your extension supports showing credentials in the QuickType bar.
     When the user selects a credential from your app, this method will be called with the
     ASPasswordCredentialIdentity your app has previously saved to the ASCredentialIdentityStore.
     Provide the password by completing the extension request with the associated ASPasswordCredential.
     If using the credential would require showing custom UI for authenticating the user, cancel
     the request with error code ASExtensionError.userInteractionRequired.

    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        let databaseIsUnlocked = true
        if (databaseIsUnlocked) {
            let passwordCredential = ASPasswordCredential(user: "j_appleseed", password: "apple1234")
            self.extensionContext.completeRequest(withSelectedCredential: passwordCredential, completionHandler: nil)
        } else {
            self.extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code:ASExtensionError.userInteractionRequired.rawValue))
        }
    }
    */

    /*
     Implement this method if provideCredentialWithoutUserInteraction(for:) can fail with
     ASExtensionError.userInteractionRequired. In this case, the system may present your extension's
     UI and call this method. Show appropriate UI for authenticating the user then provide the password
     by completing the extension request with the associated ASPasswordCredential.

    override func prepareInterfaceToProvideCredential(for credentialIdentity: ASPasswordCredentialIdentity) {
    }
    */

    @objc
    func cancel(_ sender: AnyObject?) {
        self.extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userCanceled.rawValue))
    }

    @objc
    func passwordSelected(_ sender: AnyObject?) {
        let passwordCredential = ASPasswordCredential(user: "j_appleseed", password: "apple1234")
        self.extensionContext.completeRequest(withSelectedCredential: passwordCredential, completionHandler: nil)
    }

}
