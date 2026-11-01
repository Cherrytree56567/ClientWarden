import Foundation

@objcMembers
@Observable
final class UIFeatures: NSObject {
    static let instance = UIFeatures()
    @objc public var cb_checkAbove26_8_1: (() -> Bool)?
    
    func checkAbove26_8_1() -> Bool {
        if let result = cb_checkAbove26_8_1?() {
            return result
        } else {
            ToastStore.instance.toasts.append(Toast(message: "No callback set for checkAbove26_8_1"))
            return false
        }
    }
}
