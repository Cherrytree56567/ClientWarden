import Foundation

/*
 * TODO: Add the accessgroup from CMake
 *
 * also btw we need to use the const ver
 * of var bc of security
 */
@objcMembers
@Observable
final class SDKHandler: NSObject {
    static let instance = SDKHandler()
    
    private let accessGroup = "ID.app.ct5.clientwarden"
    /*
     * GetLogins requires a website as the arg and will return
     * a csv-like list of UUIDs like UUID1,UUID2,UUID3
     *
     * GetTitle, GetUsername and GetPassword all require a UUID
     * which will then return the correct value
     */
    private let requests = ["getLogins", "getTitle", "getUsername", "getPassword"]
    
    /*
     * Callbacks
     */
    @objc public var cb_getLogins: ((String) -> String)?
    @objc public var cb_getTitle: ((String) -> String)?
    @objc public var cb_getUsername: ((String) -> String)?
    @objc public var cb_getPassword: ((String) -> String)?
    
    func observe() {
        #if NON_XCODE_BUILD
            SDKHandlerBridge.setupCallbacks()
        #endif
        
        for request in requests {
            let observer = UnsafeRawPointer(Unmanaged.passUnretained(self).toOpaque())
            
            CFNotificationCenterAddObserver(
                CFNotificationCenterGetDarwinNotifyCenter(),
                observer,
                { _, p_observer, requestName, _, _ in
                    if let p_observer, let requestName {
                        let bridge = Unmanaged<SDKHandler>.fromOpaque(p_observer).takeUnretainedValue()
                        bridge.handleRequest(notificationName: requestName.rawValue as String)
                    }
                },
                ("app.ct5.clientwarden.request.\(request)") as CFString,
                nil,
                .deliverImmediately
            )
        }
    }
    
    func stopObserve() {
        let observer = UnsafeRawPointer(Unmanaged.passUnretained(self).toOpaque())
        CFNotificationCenterRemoveEveryObserver(CFNotificationCenterGetDarwinNotifyCenter(), observer)
    }
    
    private func handleRequest(notificationName: String) {
        let request = String(notificationName.split(separator: ".").last!)
        
        if (!requests.contains(request)) {
            /*
             * Post to log abt invalid request
             */
            return
        }
        
        let responseID = "app.ct5.clientwarden.\(request)"
        
        let requestQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccessGroup as String: accessGroup,
            kSecAttrService as String: responseID,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        /*
         * Get our requestID and requestValue
         */
        var result: AnyObject?
        let status = SecItemCopyMatching(requestQuery as CFDictionary, &result)

        var itemDict: [String: Any]?
        
        if (status == errSecSuccess) {
            itemDict = result as? [String: Any]
        }
        
        var requestID: String?
        var requestData: Data?
        
        if (itemDict != nil) {
            requestID = itemDict![kSecAttrAccount as String] as? String
            requestData = itemDict![kSecValueData as String] as? Data
        }
        
        var requestValue: String?
        
        if requestData != nil {
            requestValue = String(data: requestData!, encoding: .utf8)
        }
        
        var responseValue: String?
        
        if let requestID, let requestValue {
            switch request {
                case "getLogins":
                    responseValue = getLogins(website: requestValue)
                    break
                
                case "getTitle":
                    responseValue = getTitle(uuid: requestValue)
                    break
                
                case "getUsername":
                    responseValue = getUsername(uuid: requestValue)
                    break
                
                case "getPassword":
                    responseValue = getPassword(uuid: requestValue)
                    break
                
                default:
                    /*
                     * Log an error
                     */
                    break
            }
            
            let responseQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccessGroup as String: accessGroup,
                kSecAttrAccount as String: requestID,
                kSecAttrService as String: responseID
            ]
            
            let a_responseQuery: [String: Any] = [
                kSecValueData as String: (responseValue ?? "Unknown").data(using: .utf8)!
            ]

            let s_responseQuery = SecItemUpdate(responseQuery as CFDictionary, a_responseQuery as CFDictionary)

            if (s_responseQuery != errSecSuccess) {
                /*
                 * We shouldn't return here, bc we need
                 * to post the finished notif, but it
                 * should be fine since the requester
                 * has a semaphore timer, although
                 * it would cause lag
                 */
            }

            CFNotificationCenterPostNotification(
                CFNotificationCenterGetDarwinNotifyCenter(),
                CFNotificationName(responseID as CFString),
                nil, nil, true
            )
        } else {
            /*
             * Log an error here
             */
            CFNotificationCenterPostNotification(
                CFNotificationCenterGetDarwinNotifyCenter(),
                CFNotificationName(responseID as CFString),
                nil, nil, true
            )
        }
    }
    
    private func getLogins(website: String) -> String {
        if let res = cb_getLogins?(website) {
            return res
        } else {
            /*
             * Log Failure here
             */
            return ""
        }
    }
    
    private func getTitle(uuid: String) -> String {
        if let res = cb_getTitle?(uuid) {
            return res
        } else {
            /*
             * Log Failure here
             */
            return ""
        }
    }
    
    private func getUsername(uuid: String) -> String {
        if let res = cb_getUsername?(uuid) {
            return res
        } else {
            /*
             * Log Failure here
             */
            return ""
        }
    }
    
    private func getPassword(uuid: String) -> String {
        if let res = cb_getPassword?(uuid) {
            return res
        } else {
            /*
             * Log Failure here
             */
            return ""
        }
    }
}
