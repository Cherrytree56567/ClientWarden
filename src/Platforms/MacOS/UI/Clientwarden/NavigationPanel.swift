import SwiftUI

enum NavItems: Hashable {
    case all_items
    case favorites
    case trash
    case login
    case card
    case identity
    case note
    case sshkey
    case folder(UUID)
}

@Observable
final class NavigationPanel {
    static let instance = NavigationPanel()
    
    public var folders: [Folder] = []
    
    public var cb_createFolder: ((String) -> (result: Bool, id: UUID))?
    public var cb_deleteFolder: ((UUID) -> Bool)?
    
    public var cb_allItems: (() -> [ItemElement])? = {
        return [
            ItemElement(
                name: "GitHub",
                uuid: UUID(),
                type: .Login,
                image: ClientwardenImage(type: .bundle, path: "profile1")
            ),
            ItemElement(
                name: "Gmail",
                uuid: UUID(),
                type: .Login,
                image: ClientwardenImage(type: .bundle, path: "profile1")
            ),
            ItemElement(
                name: "Visa Card",
                uuid: UUID(),
                type: .Card,
                image: ClientwardenImage(type: .bundle, path: "profile1")
            ),
            ItemElement(
                name: "Personal Identity",
                uuid: UUID(),
                type: .Identity,
                image: ClientwardenImage(type: .bundle, path: "profile1")
            ),
            ItemElement(
                name: "Wifi Password",
                uuid: UUID(),
                type: .Note,
                image: ClientwardenImage(type: .bundle, path: "profile1")
            )
        ]
    }
    public var cb_favorites: (() -> [ItemElement])? = {
        return [
            ItemElement(
                name: "GitHub",
                uuid: UUID(),
                type: .Login,
                image: ClientwardenImage(type: .bundle, path: "profile1")
            ),
            ItemElement(
                name: "Gmail",
                uuid: UUID(),
                type: .Login,
                image: ClientwardenImage(type: .bundle, path: "profile1")
            ),
        ]
    }
    public var cb_trash: (() -> [ItemElement])?
    
    public var cb_login: (() -> [ItemElement])?
    public var cb_card: (() -> [ItemElement])?
    public var cb_identity: (() -> [ItemElement])?
    public var cb_note: (() -> [ItemElement])?
    public var cb_SSHKey: (() -> [ItemElement])?
    
    public var cb_folder: ((UUID) -> [ItemElement])?
}

struct NavigationPanelView: View {
    @State private var selection: NavItems = .all_items
    
    @Bindable var data: NavigationPanel = NavigationPanel.instance
    
    var body: some View {
        TabView(selection: $selection) {
            Tab("All Items", systemImage: "command", value: .all_items) {
                if let items = data.cb_allItems?() {
                    ItemsPanel(elements: items)
                } else {
                    EmptyView()
                        .onAppear {
                            g_toastStore.toasts.append(Toast(message: "No callback set for all Items"))
                        }
                }
            }
            
            Tab("Favorites", systemImage: "star", value: .favorites) {
                if let items = data.cb_favorites?() {
                    ItemsPanel(elements: items)
                } else {
                    EmptyView()
                        .onAppear {
                            g_toastStore.toasts.append(Toast(message: "No callback set for favorites"))
                        }
                }
            }
            
            Tab("Trash", systemImage: "trash", value: .trash) {
                if let items = data.cb_trash?() {
                    ItemsPanel(elements: items)
                } else {
                    EmptyView()
                        .onAppear {
                            g_toastStore.toasts.append(Toast(message: "No callback set for trash"))
                        }
                }
            }
            
            TabSection("Type") {
                Tab("Login", systemImage: "globe", value: NavItems.login) {
                    if let items = data.cb_login?() {
                        ItemsPanel(elements: items)
                    } else {
                        EmptyView()
                            .onAppear {
                                g_toastStore.toasts.append(Toast(message: "No callback set for login"))
                            }
                    }
                }
                
                Tab("Card", systemImage: "creditcard", value: NavItems.card) {
                    if let items = data.cb_card?() {
                        ItemsPanel(elements: items)
                    } else {
                        EmptyView()
                            .onAppear {
                                g_toastStore.toasts.append(Toast(message: "No callback set for card"))
                            }
                    }
                }
                
                Tab("Identity", systemImage: "person.text.rectangle", value: NavItems.identity) {
                    if let items = data.cb_identity?() {
                        ItemsPanel(elements: items)
                    } else {
                        EmptyView()
                            .onAppear {
                                g_toastStore.toasts.append(Toast(message: "No callback set for identity"))
                            }
                    }
                }
                
                Tab("Note", systemImage: "pad.header", value: NavItems.note) {
                    if let items = data.cb_note?() {
                        ItemsPanel(elements: items)
                    } else {
                        EmptyView()
                            .onAppear {
                                g_toastStore.toasts.append(Toast(message: "No callback set for note"))
                            }
                    }
                }
                
                Tab("SSH Key", systemImage: "key.viewfinder", value: NavItems.sshkey) {
                    if let items = data.cb_SSHKey?() {
                        ItemsPanel(elements: items)
                    } else {
                        EmptyView()
                            .onAppear {
                                g_toastStore.toasts.append(Toast(message: "No callback set for SSH Key"))
                            }
                    }
                }
            }
            
            TabSection("Folder") {
                /*
                 * We can dynamically add folders to the tab section
                 * by iterating through the `folders` array which contains
                 * a Folder struct that contains a name and uuid.
                 */
                ForEach(data.folders) { folder in
                    Tab(folder.name, systemImage: "folder", value: NavItems.folder(folder.id)) {
                        if let items = data.cb_folder?(folder.id) {
                            ItemsPanel(elements: items)
                        } else {
                            EmptyView()
                                .onAppear {
                                    g_toastStore.toasts.append(Toast(message: "No callback set for folder"))
                                }
                        }
                    }
                    .contextMenu {
                        Button(role: .destructive) {
                            /*
                             * Check if the var has a callback and check if
                             * the callback was successful
                             */
                            if let folderUUID = data.cb_deleteFolder?(folder.id) {
                                if (folderUUID) {
                                    data.folders.removeAll { $0.id == folder.id }
                                } else {
                                    g_toastStore.toasts.append(Toast(message: "Failed to delete folder"))
                                }
                            } else {
                                g_toastStore.toasts.append(Toast(message: "No callback set for deleteFolder"))
                            }
                        } label: {
                            Label("Delete", systemImage: "minus.circle")
                                .labelStyle(TitleAndIconLabelStyle())
                        }
                    }
                }
            }
        }
        .tabViewStyle(.sidebarAdaptable)
        .tabViewSidebarBottomBar {
            Button {
                /*
                 * Check if the var has a callback and check if
                 * the callback was successful
                 */
                if let folderUUID = data.cb_createFolder?("New Folder") {
                    if (folderUUID.result) {
                        data.folders.append(Folder(id: folderUUID.id, name: "New Folder"))
                    } else {
                        g_toastStore.toasts.append(Toast(message: "Failed to create folder"))
                    }
                } else {
                    g_toastStore.toasts.append(Toast(message: "No callback set for createFolder"))
                }
            } label: {
                Label("Add Folder", systemImage: "folder.badge.plus")
                    .labelStyle(TitleAndIconLabelStyle())
            }
            .padding(.vertical, 4)
            .padding(.horizontal, 4)
        }
        .toast(
            Binding(
                get: { g_toastStore.toasts },
                set: { g_toastStore.toasts = $0 }
            )
        )
    }
}

#Preview {
    PreviewData().test1()
}
