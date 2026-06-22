import SwiftUI

@main
struct ClientwardenApp: App {
    var body: some Scene {
        WindowGroup {
            HStack(spacing: 0) {
                NavigationPanel()
                SidePanel(name: "Google", uuid: UUID(), type: ItemType.Login, favorite: true)
            }
        }
    }
}

#Preview {
    HStack(spacing: 0) {
        NavigationPanel()
        SidePanel(name: "Google", uuid: UUID(), type: ItemType.Login, favorite: true)
    }
}
