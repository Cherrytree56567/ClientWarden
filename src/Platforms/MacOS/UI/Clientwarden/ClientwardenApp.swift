import SwiftUI

class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }
}

@main
struct ClientwardenApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    
    var body: some Scene {
        WindowGroup("Clientwarden") {
            HStack(spacing: 0) {
                NavigationPanelView()
                SidePanelView()
            }
            .frame(minWidth: 700, minHeight: 400)
        }
    }
}

#Preview {
    PreviewData().test1()
}
