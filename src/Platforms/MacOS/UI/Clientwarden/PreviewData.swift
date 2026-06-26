import SwiftUI

struct PreviewData {
    func test1() -> some View {
        HStack(spacing: 0) {
            NavigationPanelView()
            SidePanelView()
                .onAppear {
                    SidePanel.instance.name = "Google"
                    SidePanel.instance.type = ItemType.Login
                    SidePanel.instance.favorite = false
                    SidePanel.instance.itemFields = [
                        GenericItemData(title: "Email", value: "test@example.com", type: GenericItemType.generic),
                        GenericItemData(title: "Password", value: "pass123", type:GenericItemType.password),
                        GenericItemData(title: "Two Factor Auth", value: "SFDD", type: GenericItemType.totp, cb_getTOTP: {
                            let now = Int64(Date().timeIntervalSince1970)
                            let step: Int64 = 30
                            let refreshDate = ((now / step) + 1) * step
                            let code = String(format: "%06d", Int.random(in: 0...999999))
                            return (refreshDate: refreshDate, maxTimer: 30, value: code)
                        }),
                        GenericItemData(title: "Websites", value: "google.com\nbing.com", type: GenericItemType.website),
                    ]
                    SidePanel.instance.customFields = [
                        FieldItemData(title: "Tes", value: "Some Val", type: FieldItemType.text),
                        FieldItemData(title: "Hid", value: "Some T", type: FieldItemType.hidden),
                        FieldItemData(title: "Chk", value: "false", type: FieldItemType.checkbox),
                        FieldItemData(title: "Lin", value: "101", type: FieldItemType.linked),
                    ]
                    SidePanel.instance.itemHistory = [
                        "Last Edited: idk",
                        "Created: Today lol",
                    ]
                    SidePanel.instance.passwordHistory = [
                        "Password 1",
                        "Some Old Password"
                    ]
                    SidePanel.instance.notes = GenericItemData(title: "Notes", value: "Some Notes ig\nClientwarden avail soon", type: GenericItemType.ml_generic)
                    SidePanel.instance.cb_favorite = {_,_ in
                        return true
                    }
                }
        }
    }
}

#Preview {
    PreviewData().test1()
}
