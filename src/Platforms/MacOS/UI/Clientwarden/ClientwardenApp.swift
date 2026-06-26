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
            PreviewData().test1()
                .frame(minWidth: 700, minHeight: 400)
        }
    }
}

#Preview {
    PreviewData().test1()
}
