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

struct NavigationPanel: View {
    @State private var selection: NavItems = .all_items
    @State public var folders: [Folder] = []
    @State private var toasts: [Toast] = []
    
    @State public var cb_createFolder: ((String) -> (result: Bool, id: UUID))?
    @State public var cb_deleteFolder: ((UUID) -> Bool)?
    
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
                ForEach(folders) { folder in
                    Tab(folder.name, systemImage: "folder", value: NavItems.folder(folder.id)) {
                        Text("folder")
                    }
                    .contextMenu {
                        Button(role: .destructive) {
                            /*
                             * Check if the var has a callback and check if
                             * the callback was successful
                             */
                            if let folderUUID = cb_deleteFolder?(folder.id) {
                                if folderUUID {
                                    folders.removeAll { $0.id == folder.id }
                                } else {
                                    toasts.append(Toast(message: "Failed to delete folder"))
                                }
                            } else {
                                toasts.append(Toast(message: "No callback set for deleteFolder"))
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
                if let folderUUID = cb_createFolder?("New Folder") {
                    if folderUUID.result {
                        folders.append(Folder(id: folderUUID.id, name: "New Folder"))
                    } else {
                        toasts.append(Toast(message: "Failed to create folder"))
                    }
                } else {
                    toasts.append(Toast(message: "No callback set for createFolder"))
                }
            } label: {
                Label("Add Folder", systemImage: "folder.badge.plus")
                    .labelStyle(TitleAndIconLabelStyle())
            }
            .padding(.vertical, 4)
            .padding(.horizontal, 4)
        }
        .toast($toasts)
    }
}

#Preview {
    HStack(spacing: 0) {
        NavigationPanel()
        SidePanel(name: "Google", uuid: UUID(), type: ItemType.Login, favorite: true)
    }
}
