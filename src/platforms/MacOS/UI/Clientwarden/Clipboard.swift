import Foundation

final class Clipboard {
    static let instance = Clipboard()
    
    #if NON_XCODE_BUILD
    private let bridge = CWClipboard()
    #endif
    
    private init() {}
    
    func copy(_ value: String) {
        #if NON_XCODE_BUILD
            return bridge.copy(value)
        #endif
    }
    
    func paste() -> String {
        #if NON_XCODE_BUILD
            bridge.paste()
        #else
            return ""
        #endif
    }
    
    func setDelay(_ seconds: Int) {
        #if NON_XCODE_BUILD
            bridge.setDelay(seconds)
        #endif
    }
    
    func getDelay() -> Int {
        #if NON_XCODE_BUILD
            return bridge.getDelay()
        #else
            return 30
        #endif
    }
}
