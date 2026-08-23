import SwiftUI

enum NavItems: Hashable {
    case all_items
    case favorites
    case trash
    case archived
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
    @objc public var cb_archived: (() -> [ItemElement])?
    
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
            case .archived:
                elements = cb_archived?()
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
    @State private var showRenameAlert: Bool = false
    @State private var showDeleteAlert: Bool = false
    @State private var showDeleteFolder: Folder = Folder(uuid: UUID.empty, name: "")
    @State private var renameAlertId: UUID = UUID()
    @State private var folderName: String = ""
    
    @Bindable var data: NavigationPanel = NavigationPanel.instance
    
    private func loadTabElements(tab: NavItems, prev: NavItems) {
        if (!data.loadCurrentTab()) {
            data.selection = prev
        }
    }
    
    var body: some View {
        List(selection: $data.selection) {
            Label("All Items", systemImage: "command")
                .tag(NavItems.all_items)
                .dropDestination(for: DragableItemElement.self) { droppedItems, location in
                    /*
                    * Found on:
                    * https://developer.apple.com/documentation/swiftui/adopting-drag-and-drop-using-swiftui
                    */
                    
                    if (data.selection == .favorites) {
                        for uuid in (droppedItems.flatMap{$0.uuids}) {
                            if let result = SidePanel.instance.cb_favorite?(false, uuid) {
                                if (result) {
                                } else {
                                    ToastStore.instance.toasts.append(Toast(message: "Failed to favorite items"))
                                }
                            } else {
                                ToastStore.instance.toasts.append(Toast(message: "No callback set for favorite Items"))
                            }
                        }
                    } else if (data.selection == .trash) {
                        if let result = SidePanel.instance.cb_restoreMultiple?(droppedItems.flatMap{$0.uuids}) {
                            if (result) {
                            } else {
                                ToastStore.instance.toasts.append(Toast(message: "Failed to restore items"))
                            }
                        } else {
                            ToastStore.instance.toasts.append(Toast(message: "No callback set for restore Items"))
                        }
                    } else if (data.selection == .archived) {
                        if let result = SidePanel.instance.cb_unarchiveMultiple?(droppedItems.flatMap{$0.uuids}) {
                            if (result) {
                            } else {
                                ToastStore.instance.toasts.append(Toast(message: "Failed to unarchive items"))
                            }
                        } else {
                            ToastStore.instance.toasts.append(Toast(message: "No callback set for unarchive Items"))
                        }
                    } else if case .folder(let folderId) = data.selection {
                        for uuid in (droppedItems.flatMap{$0.uuids}) {
                            if let result = SidePanel.instance.cb_moveToFolder?(UUID.empty, uuid) {
                                if (result) {
                                } else {
                                    ToastStore.instance.toasts.append(Toast(message: "Failed to move items to folder"))
                                }
                            } else {
                                ToastStore.instance.toasts.append(Toast(message: "No callback set for move items to folder"))
                            }
                        }
                    }
                    
                    NavigationPanel.instance.loadCurrentTab(refresh: true)
                }
            
            Label("Favorites", systemImage: "star")
                .tag(NavItems.favorites)
                .dropDestination(for: DragableItemElement.self) { droppedItems, location in
                    for uuid in (droppedItems.flatMap{$0.uuids}) {
                        if let result = SidePanel.instance.cb_favorite?(true, uuid) {
                            if (result) {
                            } else {
                                ToastStore.instance.toasts.append(Toast(message: "Failed to favorite items"))
                            }
                        } else {
                            ToastStore.instance.toasts.append(Toast(message: "No callback set for favorite Items"))
                        }
                    }
                    NavigationPanel.instance.loadCurrentTab(refresh: true)
                }
            
            Label("Trash", systemImage: "trash")
                .tag(NavItems.trash)
                .dropDestination(for: DragableItemElement.self) { droppedItems, location in
                    if let result = SidePanel.instance.cb_deleteMultiple?(droppedItems.flatMap{$0.uuids}) {
                        if (result) {
                            NavigationPanel.instance.loadCurrentTab(refresh: true)
                        } else {
                            ToastStore.instance.toasts.append(Toast(message: "Failed to delete items"))
                        }
                    } else {
                        ToastStore.instance.toasts.append(Toast(message: "No callback set for delete Items"))
                    }
                }
            
            Label("Archived", systemImage: "archivebox")
                .tag(NavItems.archived)
                .dropDestination(for: DragableItemElement.self) { droppedItems, location in
                    if (data.selection == NavItems.trash) {
                        if let result = SidePanel.instance.cb_restoreMultiple?(droppedItems.flatMap{$0.uuids}) {
                            if (result) {
                            } else {
                                ToastStore.instance.toasts.append(Toast(message: "Failed to restore items"))
                            }
                        } else {
                            ToastStore.instance.toasts.append(Toast(message: "No callback set for restore Items"))
                        }
                    }
                    if let result = SidePanel.instance.cb_archiveMultiple?(droppedItems.flatMap{$0.uuids}) {
                        if (result) {
                            NavigationPanel.instance.loadCurrentTab(refresh: true)
                        } else {
                            ToastStore.instance.toasts.append(Toast(message: "Failed to archive items"))
                        }
                    } else {
                        ToastStore.instance.toasts.append(Toast(message: "No callback set for archive Items"))
                    }
                }

            Section("Type") {
                Label("Login", systemImage: "globe")
                    .tag(NavItems.login)
                
                Label("Card", systemImage: "creditcard")
                    .tag(NavItems.card)
                
                Label("Identity", systemImage: "person.text.rectangle")
                    .tag(NavItems.identity)
                
                Label("Note", systemImage: "pad.header")
                    .tag(NavItems.note)
                
                Label("SSH Key", systemImage: "key.viewfinder")
                    .tag(NavItems.sshkey)
            }
            
            Section("Folder") {
                /*
                 * We can dynamically add folders to the tab section
                 * by iterating through the `folders` array which contains
                 * a Folder struct that contains a name and uuid.
                 */
                ForEach(data.folders) { folder in
                    if (folder.id != UUID.empty) {
                        Label(folder.name, systemImage: "folder")
                            .tag(NavItems.folder(folder.id))
                            .contextMenu {
                                Button(role: .destructive) {
                                    showDeleteFolder = folder
                                    showDeleteAlert = true
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
                            .dropDestination(for: DragableItemElement.self) { droppedItems, location in
                                for uuid in (droppedItems.flatMap{$0.uuids}) {
                                    if let result = SidePanel.instance.cb_moveToFolder?(folder.id, uuid) {
                                        if (result) {
                                        } else {
                                            ToastStore.instance.toasts.append(Toast(message: "Failed to move items to folder"))
                                        }
                                    } else {
                                        ToastStore.instance.toasts.append(Toast(message: "No callback set for move items to folder"))
                                    }
                                }
                                NavigationPanel.instance.loadCurrentTab(refresh: true)
                            }
                    }
                }
            }
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .bottom) {
            Button {
                /*
                 * Check if the var has a callback and check if
                 * the callback was successful
                 */
                if (data.cb_createFolder != nil) {
                    if let folderUUID = data.cb_createFolder!("New Folder") {
                        data.folders.append(Folder(uuid: folderUUID, name: "New Folder"))
                    }
                } else {
                    ToastStore.instance.toasts.append(Toast(message: "No callback set for createFolder"))
                }
            } label: {
                Label("Add Folder", systemImage: "folder.badge.plus")
                    .labelStyle(TitleAndIconLabelStyle())
                    .foregroundStyle(Color.gray)
                    .font(.subheadline.bold())
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 8)
                    .padding(.leading, 12)
                    .padding(.trailing, 8)
            }
            .buttonStyle(.plain)
            .frame(maxWidth: .infinity)
            .glassEffect(.regular, in: .rect(cornerRadius: 0))
            .clipShape(
                .rect(
                    topLeadingRadius: 0,
                    bottomLeadingRadius: 10,
                    bottomTrailingRadius: 10,
                    topTrailingRadius: 0
                )
            )
            .overlay(
                UnevenRoundedRectangle(
                    topLeadingRadius: 0,
                    bottomLeadingRadius: 10,
                    bottomTrailingRadius: 10,
                    topTrailingRadius: 0
                )
                .stroke(Color.gray.opacity(0.3), lineWidth: 0.5)
            )
            .animation(.spring(response: 0.4, dampingFraction: 0.8))
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
            Text("Rename a folder")
        }
        .alert("Delete", isPresented: $showDeleteAlert) {
            Button("Cancel", role: .cancel) { }
            Button("Delete", role: .destructive) {
                if let result = data.cb_deleteFolder?(showDeleteFolder.id) {
                    if (result) {
                        data.folders.removeAll { $0.id == showDeleteFolder.id }
                    } else {
                        ToastStore.instance.toasts.append(Toast(message: "Failed to delete folder"))
                    }
                } else {
                    ToastStore.instance.toasts.append(Toast(message: "No callback set for deleteFolder"))
                }
            }
        } message: {
            Text("Are you sure you would like to delete this folder? This will move all items out of your folder!")
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
