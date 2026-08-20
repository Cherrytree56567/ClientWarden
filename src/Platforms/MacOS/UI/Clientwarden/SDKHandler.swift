import Foundation
import os

/*
 * also btw we need to use the const ver
 * of var bc of security
 */
@objcMembers
@Observable
final class SDKHandler: NSObject {
    static let instance = SDKHandler()
    
    #if NON_XCODE_BUILD
        let logger = Logger(subsystem: BundleInfo.sharedID, category: "SDKHandler")
        
        private let accessGroup = BundleInfo.teamID + "." + BundleInfo.sharedID
        /*
         * GetLogins requires a website as the arg and will return
         * a csv-like list of UUIDs like UUID1,UUID2,UUID3
         *
         * GetTitle, GetUsername and GetPassword all require a UUID
         * which will then return the correct value
         */
        private let requests = ["getLogins", "getTitle", "getUsername", "getPassword", "getState"]
        
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
                    ("\(BundleInfo.sharedID).request.\(request)") as CFString,
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
                logger.error("Invalid Request: \(request)")
                return
            }
            
            let responseID = "\(BundleInfo.sharedID).\(request)"
            
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
                    
                    case "getState":
                        ClientwardenWindow.instance.getState()
                        responseValue = ClientwardenWindow.instance.p_state == .Vault ? "true" : "false"
                        break
                    
                    default:
                        logger.error("Invalid Request: \(request)")
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
                     logger.error("Failed to update response: \(s_responseQuery)")
                }

                CFNotificationCenterPostNotification(
                    CFNotificationCenterGetDarwinNotifyCenter(),
                    CFNotificationName(responseID as CFString),
                    nil, nil, true
                )
            } else {
                logger.error("Invalid requestID or value")
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
                logger.error("Failed to get Logins")
                return ""
            }
        }
        
        private func getTitle(uuid: String) -> String {
            if let res = cb_getTitle?(uuid) {
                return res
            } else {
                logger.error("Failed to get Title")
                return ""
            }
        }
        
        private func getUsername(uuid: String) -> String {
            if let res = cb_getUsername?(uuid) {
                return res
            } else {
                logger.error("Failed to get Username")
                return ""
            }
        }
        
        private func getPassword(uuid: String) -> String {
            if let res = cb_getPassword?(uuid) {
                return res
            } else {
                logger.error("Failed to get Password")
                return ""
            }
        }
    #endif
}
