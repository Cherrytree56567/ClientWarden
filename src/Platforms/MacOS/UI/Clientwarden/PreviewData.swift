import SwiftUI

struct PreviewData {
    func test1() -> some View {
        HStack(spacing: 0) {
            NavigationSplitView {
                NavigationPanelView()
            } content: {
                ItemsPanelView()
                    .id(NavigationPanel.instance.refresh)
            } detail: {
                SidePanelView()
                    .onAppear {
                        SidePanel.instance.name = "Google"
                        SidePanel.instance.type = ItemType.Login
                        SidePanel.instance.icon = ClientwardenImage(type: ImageType.bundle, path: "profile1")
                        SidePanel.instance.favorite = false
                        SidePanel.instance.itemFields = [
                            GenericItemData(title: "Name", value: "Mr John Jones Smith", type: GenericItemType.generic_4),
                            GenericItemData(title: "Email", value: "test@example.com", type: GenericItemType.generic),
                            GenericItemData(title: "Password", value: "pass123", type:GenericItemType.password),
                            GenericItemData(title: "Two Factor Auth", value: "SFDD", type: GenericItemType.totp, cb_getTOTP: {
                                let now = Int64(Date().timeIntervalSince1970)
                                let step: Int64 = 30
                                let refreshDate = ((now / step) + 1) * step
                                let code = String(format: "%06d", Int.random(in: 0...999999))
                                return TOTPResult(refreshDate: refreshDate, maxTimer: 30, value: code)
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
                            PasswordHistoryItem(date: "21 Jan", password: "Password 1"),
                            PasswordHistoryItem(date: "21 Jan", password: "Some Old Password")
                        ]
                        SidePanel.instance.viewable = true
                        SidePanel.instance.editable = true
                        SidePanel.instance.notes = GenericItemData(title: "Notes", value: "Some Notes ig\nClientwarden avail soon", type: GenericItemType.ml_generic)
                        SidePanel.instance.cb_favorite = {_,_ in
                            return true
                        }
                                            
                        /*
                         * THis thing is AI, but I had to do some formatting stuff, this is
                         * only temp
                         */
                        ItemsPanel.instance.update(data: [
                            ItemElement(
                                name: "Google",
                                uuid: UUID(),
                                type: ItemType.Login,
                                image: ClientwardenImage(type: ImageType.bundle, path: "profile1")
                            ),
                            ItemElement(
                                name: "GitHub",
                                uuid: UUID(),
                                type: ItemType.Login,
                                image: ClientwardenImage(type: ImageType.bundle, path: "profile2")
                            ),
                            ItemElement(
                                name: "Visa Card",
                                uuid: UUID(),
                                type: ItemType.Card,
                                image: ClientwardenImage(type: ImageType.bundle, path: "card1")
                            ),
                            ItemElement(
                                name: "Personal Identity",
                                uuid: UUID(),
                                type: ItemType.Identity,
                                image: ClientwardenImage(type: ImageType.bundle, path: "identity1")
                            ),
                            ItemElement(
                                name: "Wifi Password",
                                uuid: UUID(),
                                type: ItemType.Note,
                                image: ClientwardenImage(type: ImageType.bundle, path: "note1")
                            ),
                            ItemElement(
                                name: "Server SSH Key",
                                uuid: UUID(),
                                type: ItemType.SSHKey,
                                image: ClientwardenImage(type: ImageType.bundle, path: "ssh1")
                            ),
                        ])
                                            
                        NavigationPanel.instance.folders = [
                            Folder(uuid: UUID(), name: "New Fold"),
                            Folder(uuid: UUID(), name: "Client Fold")
                        ]
                    }
            }
        }
        .frame(minWidth: 700, minHeight: 400)
    }
}

#Preview {
    PreviewData().test1()
}
