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

/*
 * TODO: Make the liquid glass bg to always be there and move No Items to the center
 */
@Observable
final class NavigationPanel {
    static let instance = NavigationPanel()
    
    public var refresh: Int = 0
    
    public var folders: [Folder] = []
    
    public var cb_createFolder: ((String) -> (result: Bool, id: UUID))?
    public var cb_deleteFolder: ((UUID) -> Bool)?
    
    public var cb_allItems: (() -> [ItemElement])?
    public var cb_favorites: (() -> [ItemElement])?
    public var cb_trash: (() -> [ItemElement])?
    
    public var cb_login: (() -> [ItemElement])?
    public var cb_card: (() -> [ItemElement])?
    public var cb_identity: (() -> [ItemElement])?
    public var cb_note: (() -> [ItemElement])?
    public var cb_SSHKey: (() -> [ItemElement])?
    
    public var cb_folder: ((UUID) -> [ItemElement])?
    
    func refreshItems() {
        self.refresh += 1
    }
}

struct NavigationPanelView: View {
    @State private var selection: NavItems = .all_items
    @State private var refreshToken: Int = 0
    
    @Bindable var data: NavigationPanel = NavigationPanel.instance
    
    private func loadTabElements(tab: NavItems, prev: NavItems) {
        var elements: [ItemElement]?
        
        switch tab {
            case .all_items:
                elements = data.cb_allItems?()
            case .favorites:
                elements = data.cb_favorites?()
            case .trash:
                elements = data.cb_trash?()
            case .login:
                elements = data.cb_login?()
            case .card:
                elements = data.cb_card?()
            case .identity:
                elements = data.cb_identity?()
            case .note:
                elements = data.cb_note?()
            case .sshkey:
                elements = data.cb_SSHKey?()
            case .folder(let uuid):
                elements = data.cb_folder?(uuid)
        }
        
        if let elements {
            ItemsPanel.instance.update(data: elements)
        } else {
            g_toastStore.toasts.append(Toast(message: "No callback set for \(tab)"))
            selection = prev
        }
    }
    
    var body: some View {
        TabView(selection: $selection) {
            Tab("All Items", systemImage: "command", value: .all_items) {
                ItemsPanelView()
                    .id(refreshToken)
            }
            
            Tab("Favorites", systemImage: "star", value: .favorites) {
                ItemsPanelView()
                    .id(refreshToken)
            }
            
            Tab("Trash", systemImage: "trash", value: .trash) {
                ItemsPanelView()
                    .id(refreshToken)
            }
            
            TabSection("Type") {
                Tab("Login", systemImage: "globe", value: NavItems.login) {
                    ItemsPanelView()
                        .id(refreshToken)
                }
                
                Tab("Card", systemImage: "creditcard", value: NavItems.card) {
                    ItemsPanelView()
                        .id(refreshToken)
                }
                
                Tab("Identity", systemImage: "person.text.rectangle", value: NavItems.identity) {
                    ItemsPanelView()
                        .id(refreshToken)
                }
                
                Tab("Note", systemImage: "pad.header", value: NavItems.note) {
                    ItemsPanelView()
                        .id(refreshToken)
                }
                
                Tab("SSH Key", systemImage: "key.viewfinder", value: NavItems.sshkey) {
                    ItemsPanelView()
                        .id(refreshToken)
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
                        ItemsPanelView()
                            .id(refreshToken)
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
            .animation(.spring(response: 0.4, dampingFraction: 0.8))
        }
        .onChange(of: data.refresh) { _, newVal in
            refreshToken = newVal
        }
        .onChange(of: selection) { oldValue, newValue in
            SidePanel.instance.closeItem()
            loadTabElements(tab: newValue, prev: oldValue)
        }
        .onAppear() {
            loadTabElements(tab: selection, prev: selection)
        }
    }
}

#Preview {
    PreviewData().test1()
}
