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
}

struct NavigationPanelView: View {
    @State private var selection: NavItems = .all_items
    
    @Bindable var data: NavigationPanel = NavigationPanel.instance
    
    var body: some View {
        TabView(selection: $selection) {
            Tab("All Items", systemImage: "command", value: .all_items) {
                Text("Items")
            }
            
            Tab("Favorites", systemImage: "star", value: .favorites) {
                Text("Items")
            }
            
            Tab("Trash", systemImage: "trash", value: .trash) {
                Text("Items")
            }
            
            TabSection("Type") {
                Tab("Login", systemImage: "globe", value: NavItems.login) {
                    Text("Items")
                }
                
                Tab("Card", systemImage: "creditcard", value: NavItems.card) {
                    Text("Items")
                }
                
                Tab("Identity", systemImage: "person.text.rectangle", value: NavItems.identity) {
                    Text("Items")
                }
                
                Tab("Note", systemImage: "pad.header", value: NavItems.note) {
                    Text("Items")
                }
                
                Tab("SSH Key", systemImage: "key.viewfinder", value: NavItems.sshkey) {
                    Text("Items")
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
                        Text("folder")
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
