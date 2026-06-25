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
                NavigationPanel()
                SidePanel(name: "Google", uuid: UUID(), type: ItemType.Login, favorite: false, itemFields: [
                        GenericItemData(title: "Email", value: "test@example.com", type: GenericItemType.generic),
                        GenericItemData(title: "Password", value: "pass123", type: GenericItemType.password),
                        GenericItemData(title: "Two Factor Auth", value: "SFDD", type: GenericItemType.totp, cb_getTOTP: {
                                let now = Int64(Date().timeIntervalSince1970)
                                let step: Int64 = 30
                                let refreshDate = ((now / step) + 1) * step
                                let code = String(format: "%06d", Int.random(in: 0...999999))
                                return (refreshDate: refreshDate, maxTimer: 30, value: code)
                            }),
                        GenericItemData(title: "Websites", value: "google.com\nbing.com", type: GenericItemType.ml_generic),
                    ], customFields: [
                        FieldItemData(title: "Tes", value: "Some Val", type: FieldItemType.text, editable: false),
                        FieldItemData(title: "Hid", value: "Some T", type: FieldItemType.hidden, editable: false),
                        FieldItemData(title: "Chk", value: "false", type: FieldItemType.checkbox, editable: false),
                        FieldItemData(title: "Lin", value: "101", type: FieldItemType.linked, editable: false),
                    ], itemHistory: [
                        "Last Edited: idk",
                        "Created: Today lol",
                    ], notes: "Some Notes ig\nClientwarden avail soon", editable: false, cb_favorite: {_,_ in
                        return false
                    }
                )
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
