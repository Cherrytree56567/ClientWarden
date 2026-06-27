import SwiftUI

@main
struct ClientwardenApp: App {
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
