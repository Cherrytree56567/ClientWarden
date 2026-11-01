import AppKit

@objcMembers
@Observable
final class ActivityMonitor: NSObject {
    static let instance = ActivityMonitor()
    private var lastActivityDate = Date()
    private var localMonitor: Any?

    @objc public var cb_setLastInactivity: ((Date) -> Bool)?
    
    func start() {
        localMonitor = NSEvent.addLocalMonitorForEvents(matching: [.mouseMoved, .leftMouseDown, .rightMouseDown, 
            .keyDown, .scrollWheel]) { [weak self] event in
            self?.lastActivityDate = Date()

            if let self, let res = self.cb_setLastInactivity?(self.lastActivityDate) {

            }

            return event
        }
    }

    deinit {
        if let localMonitor {
            NSEvent.removeMonitor(localMonitor)
        }
    }
}
