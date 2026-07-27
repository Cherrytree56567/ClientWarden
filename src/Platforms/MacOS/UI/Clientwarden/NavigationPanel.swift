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

@objcMembers
@Observable
final class NavigationPanel: NSObject {
    static let instance = NavigationPanel()
    
    public var refresh: Int = 0
    public var selection: NavItems = .all_items
    
    public var folders: [Folder] = []
    
    @objc public var cb_createFolder: ((String) -> UUID?)?
    @objc public var cb_deleteFolder: ((UUID) -> Bool)?
    @objc public var cb_renameFolder: ((UUID, String) -> Bool)?
    
    @objc public var cb_allItems: (() -> [ItemElement])?
    @objc public var cb_favorites: (() -> [ItemElement])?
    @objc public var cb_trash: (() -> [ItemElement])?
    
    @objc public var cb_login: (() -> [ItemElement])?
    @objc public var cb_card: (() -> [ItemElement])?
    @objc public var cb_identity: (() -> [ItemElement])?
    @objc public var cb_note: (() -> [ItemElement])?
    @objc public var cb_SSHKey: (() -> [ItemElement])?
    
    @objc public var cb_folder: ((UUID) -> [ItemElement])?

    @objc public var cb_getFolders: (() -> [Folder])?

    func getFolders() {
        if (ClientwardenWindow.instance.state != .Vault) {
            return
        }
        if let c_folders = cb_getFolders?() {
            folders = c_folders
            folders
                .filter { $0.id != UUID.empty }
                .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        } else {
            ToastStore.instance.toasts.append(Toast(message: "No callback set for getFolders"))
        }
    }

    func renameFolder(folderId: UUID, str: String) {
        if let res = cb_renameFolder?(folderId, str) {
            if (res) {
                if let index = folders.firstIndex(where: { $0.id == folderId }) {
                    folders[index].name = str
                }
            } else {
                ToastStore.instance.toasts.append(Toast(message: "Failed to rename folder"))
            }
        } else {
            ToastStore.instance.toasts.append(Toast(message: "No callback set for renameFolder"))
        }
    }
    
    func refreshItems() {
        self.refresh += 1
    }

    func loadCurrentTab(refresh: Bool = false) -> Bool {
        if (ClientwardenWindow.instance.state != .Vault) {
            return true // It should return false, but I dont want it to show the callback thign
        }
        var elements: [ItemElement]?
        
        switch selection {
            case .all_items:
                elements = cb_allItems?()
            case .favorites:
                elements = cb_favorites?()
            case .trash:
                elements = cb_trash?()
            case .login:
                elements = cb_login?()
            case .card:
                elements = cb_card?()
            case .identity:
                elements = cb_identity?()
            case .note:
                elements = cb_note?()
            case .sshkey:
                elements = cb_SSHKey?()
            case .folder(let uuid):
                elements = cb_folder?(uuid)
        }
        
        if let elements {
            if (refresh) {
                ItemsPanel.instance.refresh(data: elements)
            } else {
                ItemsPanel.instance.update(data: elements)
            }
            return true
        } else {
            ToastStore.instance.toasts.append(Toast(message: "No callback set for \(selection)"))
            return false
        }
    }
}

struct NavigationPanelView: View {
    @State private var refreshToken: Int = 0
    @State private var showRenameAlert: Bool = false
    @State private var renameAlertId: UUID = UUID()
    @State private var folderName: String = ""
    
    @Bindable var data: NavigationPanel = NavigationPanel.instance
    
    private func loadTabElements(tab: NavItems, prev: NavItems) {
        if (!data.loadCurrentTab()) {
            data.selection = prev
        }
    }
    
    var body: some View {
        TabView(selection: $data.selection) {
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
                    if (folder.id != UUID.empty) {
                        Tab(folder.name, systemImage: "folder", value: NavItems.folder(folder.id)) {
                            ItemsPanelView()
                                .id(refreshToken)
                        }
                        .contextMenu {
                            Button(role: .destructive) {
                                if let folderUUID = data.cb_deleteFolder?(folder.id) {
                                    if (folderUUID) {
                                        data.folders.removeAll { $0.id == folder.id }
                                    } else {
                                        ToastStore.instance.toasts.append(Toast(message: "Failed to delete folder"))
                                    }
                                } else {
                                    ToastStore.instance.toasts.append(Toast(message: "No callback set for deleteFolder"))
                                }
                            } label: {
                                Label("Delete", systemImage: "minus.circle")
                                    .labelStyle(TitleAndIconLabelStyle())
                            }
                            Button {
                                showRenameAlert = true
                                renameAlertId = folder.id
                                folderName = folder.name
                            } label: {
                                Label("Rename", systemImage: "character.cursor.ibeam")
                                    .labelStyle(TitleAndIconLabelStyle())
                            }
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
                if (data.cb_createFolder != nil) {
                    if let folderUUID = data.cb_createFolder!("New Folder") {
                        data.folders.append(Folder(uuid: folderUUID, name: "New Folder"))
                    } else {
                        ToastStore.instance.toasts.append(Toast(message: "Failed to create folder"))
                    }
                } else {
                    ToastStore.instance.toasts.append(Toast(message: "No callback set for createFolder"))
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
        .onChange(of: data.selection) { oldValue, newValue in
            SidePanel.instance.closeItem()
            loadTabElements(tab: newValue, prev: oldValue)
        }
        .onAppear() {
            #if NON_XCODE_BUILD
                NavPanelBridge.setupCallbacks()
            #endif
            data.getFolders()
            loadTabElements(tab: data.selection, prev: data.selection)
        }
        .alert("Rename", isPresented: $showRenameAlert) {
            TextField("Folder Name", text: $folderName)
            Button("Cancel", role: .cancel) { }
            Button("Confirm") {
                data.renameFolder(folderId: renameAlertId, str: folderName)
            }
        } message: {
            Text("Rename Folder.")
        }
        .task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                if (!Task.isCancelled) {
                    data.getFolders()
                }
            }
        }
    }
}

#Preview {
    PreviewData().test1()
}
