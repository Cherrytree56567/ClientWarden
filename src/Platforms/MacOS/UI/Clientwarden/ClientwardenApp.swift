import SwiftUI

@Observable
final class ToastStore {
    var toasts: [Toast] = []
}

let g_toastStore = ToastStore()

/*
 * On Release:
 * Change code to:
 * HStack(spacing: 0) {
                NavigationPanelView()
                SidePanelView()
            }
            .frame(minWidth: 700, minHeight: 400)
 * Remove NavPanel and ItemsPanel Callback
 */
@main
struct ClientwardenApp: App {
    var body: some Scene {
        WindowGroup {
            PreviewData().test1()
        }
    }
}

#Preview {
    PreviewData().test1()
}
