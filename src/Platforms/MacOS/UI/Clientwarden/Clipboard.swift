import Foundation

final class Clipboard {
    static let instance = Clipboard()
    
    private let bridge = CWClipboard()
    
    private init() {}
    
    func copy(_ value: String) {
        return bridge.copy(value)
    }
    
    func paste() -> String {
        bridge.paste()
    }
    
    func setDelay(_ seconds: Int) {
        bridge.setDelay(seconds)
    }
    
    func getDelay() -> Int {
        return bridge.getDelay()
    }
}
