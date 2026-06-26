import SwiftUI

@Observable
final class ToastStore {
    var toasts: [Toast] = []
}

let g_toastStore = ToastStore()

@main
struct ClientwardenApp: App {
    var body: some Scene {
        WindowGroup {
            HStack(spacing: 0) {
                NavigationPanelView()
                SidePanelView()
            }
        }
    }
}

#Preview {
    PreviewData().test1()
}
