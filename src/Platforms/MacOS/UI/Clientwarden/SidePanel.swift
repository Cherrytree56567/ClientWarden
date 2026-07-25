import SwiftUI

/*
 * So the way Swift works, is it keeps recreating the View for each frame, kinda.
 * Essentially, the SidePanelView is just the stuff thats being displayed, and SidePanel
 * is just the data. Since there is always only 1 Side Panel, Its a good idea to separate
 * the SidePanel View and the SidePanel Data.
 */

@objcMembers
final class PasswordHistoryItem: NSObject {
    public var date: String
    public var password: String

    public init(date: String, password: String) {
        self.date = date
        self.password = password
    }
}

@objcMembers
final class FolderItem: NSObject {
    public var name: String
    public var uuid: String

    public init(name: String, uuid: String) {
        self.name = name
        self.uuid = uuid
    }
}

@objcMembers
@Observable
final class SidePanel: NSObject {
    static let instance = SidePanel()
    override public init() {
        super.init()
    }
    
    public var repromptPassword: String = ""
    public var isReprompt: Bool = false
    public var repromptFailed: Bool = false
    
    public var name: String = ""
    public var uuid: UUID = UUID()
    public var folderUUID: UUID = UUID.empty
    public var type: ItemType = ItemType.Login
    public var icon: ClientwardenImage = ClientwardenImage(type: ImageType.bundle, path: "profile1")
    public var editable: Bool = false
    public var viewable: Bool = false
    public var favorite: Bool = false
    
    public var itemFields: [GenericItemData] = []
    public var customFields: [FieldItemData] = []
    public var itemHistory: [String] = []
    public var passwordHistory: [PasswordHistoryItem] = []
    public var attachmentItems: [AttachmentItemData] = []
    public var notes: GenericItemData = GenericItemData(title: "Notes", value: "", type: GenericItemType.ml_generic)
    
    /*
     * Callbacks
     */
    @objc public var cb_favorite: ((Bool, UUID) -> Bool)?
    
    @objc public var cb_duplicate: ((UUID, ItemType) -> ItemElement)?
    @objc public var cb_delete: ((UUID) -> Bool)?
    @objc public var cb_save: ((UUID, String, ItemType, UUID, [GenericItemData], [FieldItemData], String) -> Bool)?
    
    @objc public var cb_restore: ((UUID) -> Bool)?
    @objc public var cb_permDel: ((UUID) -> Bool)?
    
    @objc public var cb_sidebar: ((UUID) -> Bool)?
    @objc public var cb_sidebarReprompt: ((UUID, String) -> Bool)?
    
    @objc public var cb_downloadAttachment: ((UUID, String) -> Bool)?
    @objc public var cb_removeAttachment: ((UUID, String) -> Bool)?
    @objc public var cb_uploadAttachment: ((UUID) -> Bool)?
    
    func closeItem() {
        viewable = false
        editable = false
        name = ""
        type = ItemType.Login
        icon = ClientwardenImage(type: ImageType.bundle, path: "profile1")
        folderUUID = UUID.empty
        favorite = false
        itemFields = []
        customFields = []
        itemHistory = []
        passwordHistory = []
        notes = GenericItemData(title: "Notes", value: "", type: GenericItemType.ml_generic)
        s_name = ""
        s_itemFields = []
        s_customFields = []
        s_notes = GenericItemData(title: "Notes", value: "", type: GenericItemType.ml_generic)
    }
    
    func viewItem(name: String, uuid: UUID, type: ItemType, icon: ClientwardenImage, folderUUID: UUID, favorite: Bool, itemFields: [GenericItemData], customFields: [FieldItemData], itemHistory: [String], passwordHistory: [PasswordHistoryItem], attachmentItems: [AttachmentItemData], notes: String) {
        self.viewable = true
        self.editable = false
        self.name = name
        self.uuid = uuid
        self.type = type
        self.icon = icon
        self.folderUUID = folderUUID
        self.favorite = favorite
        self.itemFields = itemFields
        self.customFields = customFields
        self.itemHistory = itemHistory
        self.passwordHistory = passwordHistory
        self.attachmentItems = attachmentItems
        self.notes = GenericItemData(title: "Notes", value: notes, type: GenericItemType.ml_generic)
    }
    
    /*
     * Snapshots
     */
    public var s_name: String = ""
    
    public var s_itemFields: [GenericItemData] = []
    public var s_customFields: [FieldItemData] = []
    public var s_notes: GenericItemData = GenericItemData(title: "Notes", value: "", type: GenericItemType.ml_generic)
    public var s_folderUUID: UUID = UUID.empty
    
    func saveSnapshot() {
        s_name = name
        s_itemFields = itemFields.map { $0._copy() }
        s_customFields = customFields
        s_notes = notes._copy()
        s_folderUUID = folderUUID
    }
    
    func pullSnapshot() {
        name = s_name
        itemFields = s_itemFields.map { $0._copy() }
        customFields = s_customFields
        notes = s_notes._copy()
        folderUUID = s_folderUUID
    }
    
    func deleteSnapshot() {
        s_name = ""
        s_itemFields = []
        s_customFields = []
        s_notes = GenericItemData(title: "Notes", value: "", type: GenericItemType.ml_generic)
        s_folderUUID = UUID.empty
    }
    
    /*
     * Callback Functions
     */
    func toggleFavorite() {
        /*
         * Check if the var has a callback and check if
         * the callback was successful
         */
        if let result = cb_favorite?(!favorite, uuid) {
            if (result) {
                favorite.toggle()
            } else {
                ToastStore.instance.toasts.append(Toast(message: "Failed to set favorite"))
            }
        } else {
            ToastStore.instance.toasts.append(Toast(message: "No callback set for favorite"))
        }
    }
    
    func saveItem() -> Bool {
        /*
         * Check if the var has a callback and check if
         * the callback was successful
         */
        if let result = cb_save?(uuid, name, type, folderUUID, itemFields, customFields, notes.value) {
            if (result) {
                NavigationPanel.instance.loadCurrentTab(refresh: true)
                return true
            } else {
                ToastStore.instance.toasts.append(Toast(message: "Failed to save item"))
            }
        } else {
            ToastStore.instance.toasts.append(Toast(message: "No callback set for save Item"))
        }
        return false
    }
    
    func duplicateItem() {
        /*
         * Check if the var has a callback and check if
         * the callback was successful
         */
        if let result = cb_duplicate?(uuid, type) {
            if (result != nil) {
                ItemsPanel.instance.elements.append(result)
                NavigationPanel.instance.loadCurrentTab(refresh: true)
            }
        } else {
            ToastStore.instance.toasts.append(Toast(message: "No callback set for duplicate Item"))
        }
    }
    
    func deleteItem() {
        /*
         * Check if the var has a callback and check if
         * the callback was successful
         */
        if let result = cb_delete?(uuid) {
            if (result) {
                editable = false
                viewable = false
                NavigationPanel.instance.loadCurrentTab(refresh: true)
            } else {
                ToastStore.instance.toasts.append(Toast(message: "Failed to delete item"))
            }
        } else {
            ToastStore.instance.toasts.append(Toast(message: "No callback set for delete Item"))
        }
    }
    
    func viewItem(cb_uuid: UUID) {
        /*
         * Check if the var has a callback and check if
         * the callback was successful
         */
        if let result = cb_sidebar?(cb_uuid) {
            if (result) {
            } else {
                ToastStore.instance.toasts.append(Toast(message: "Failed to view item"))
            }
        } else {
            ToastStore.instance.toasts.append(Toast(message: "No callback set for view Item"))
        }
    }
    
    func viewItemReprompt() {
        /*
         * Check if the var has a callback and check if
         * the callback was successful
         */
        if let result = cb_sidebarReprompt?(uuid, repromptPassword) {
            if (result) {
            } else {
                ToastStore.instance.toasts.append(Toast(message: "Failed to view item"))
            }
        } else {
            ToastStore.instance.toasts.append(Toast(message: "No callback set for view Item"))
        }
        
        repromptPassword = ""
    }
    
    func downloadAttachment(id: String) {
        /*
         * Check if the var has a callback and check if
         * the callback was successful
         */
        if let result = cb_downloadAttachment?(uuid, id) {
            if (result) {
            } else {
                ToastStore.instance.toasts.append(Toast(message: "Failed to download Attachment"))
            }
        } else {
            ToastStore.instance.toasts.append(Toast(message: "No callback set for downloadAttachment"))
        }
    }
    
    func removeAttachment(id: String) {
        /*
         * Check if the var has a callback and check if
         * the callback was successful
         */
        if let result = cb_removeAttachment?(uuid, id) {
            if (result) {
            } else {
                ToastStore.instance.toasts.append(Toast(message: "Failed to remove Attachment"))
            }
        } else {
            ToastStore.instance.toasts.append(Toast(message: "No callback set for removeAttachment"))
        }
    }
    
    func uploadAttachment() {
        /*
         * Check if the var has a callback and check if
         * the callback was successful
         */
        if let result = cb_uploadAttachment?(uuid) {
            if (result) {
            } else {
                ToastStore.instance.toasts.append(Toast(message: "Failed to upload Attachment"))
            }
        } else {
            ToastStore.instance.toasts.append(Toast(message: "No callback set for uploadAttachment"))
        }
    }
    
    func restoreItem() {
        /*
         * Check if the var has a callback and check if
         * the callback was successful
         */
        if let result = cb_restore?(uuid) {
            if (result) {
                editable = false
                viewable = false
                NavigationPanel.instance.loadCurrentTab(refresh: true)
            } else {
                ToastStore.instance.toasts.append(Toast(message: "Failed to restore item"))
            }
        } else {
            ToastStore.instance.toasts.append(Toast(message: "No callback set for restore"))
        }
    }
    
    func permDeleteItem() {
        /*
         * Check if the var has a callback and check if
         * the callback was successful
         */
        if let result = cb_permDel?(uuid) {
            if (result) {
                editable = false
                viewable = false
                NavigationPanel.instance.loadCurrentTab(refresh: true)
            } else {
                ToastStore.instance.toasts.append(Toast(message: "Failed to Permanantly Delete Item"))
            }
        } else {
            ToastStore.instance.toasts.append(Toast(message: "No callback set for permDelete"))
        }
    }
    
    /*
     * Callback Helpers
     */
    func updateProgress(id: String, progress: Double) {
        if let index = attachmentItems.firstIndex(where: { $0.AttachID == id }) {
            attachmentItems[index].progress = progress
        }
    }

    func updateAttachID(id: String, attachID: String) {
        if let index = attachmentItems.firstIndex(where: { $0.AttachID == id }) {
            attachmentItems[index].AttachID = attachID
        }
    }
    
    func deleteAttachmentView(id: String) {
        attachmentItems.removeAll { $0.AttachID == id }
    }

    func addAttachmentItem(_ item: AttachmentItemData) {
        attachmentItems.append(item)
    }
}

struct SidePanelView: View {
    @State private var showPasswordHistory: Bool = false
    @State private var showNewFieldCallout: Bool = false
    @State private var showDeleteCallout: Bool = false
    
    @Bindable var data: SidePanel = SidePanel.instance
    
    var body: some View {
        VStack(alignment: .leading) {
            if (!data.viewable) {
                ContentUnavailableView(
                    "Clientwarden",
                    systemImage: "text.viewfinder",
                    description: Text("Select an item to view its details")
                )
                .imageScale(.large)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    HStack {
                        if let image = data.icon.getImage() {
                            image
                                .resizable()
                                .aspectRatio(contentMode: .fit)
                                .frame(width: 32, height: 32)
                                .clipShape(RoundedRectangle(cornerRadius: 4))
                        } else {
                            Image("profile1")
                                .resizable()
                                .frame(width: 32, height: 32)
                                .clipShape(RoundedRectangle(cornerRadius: 4))
                        }
                        
                        VStack(alignment: .leading) {
                            if (data.editable) {
                                TextField("Title", text: $data.name)
                                    .font(.system(size: 18, weight: .bold))
                                    .padding(.top, 4)
                            } else {
                                Text(data.name)
                                    .font(.system(size: 18, weight: .bold))
                                    .padding(.top, -2)
                            }
                            Text(data.type.description)
                                .font(.system(size: 8))
                                .foregroundStyle(.secondary)
                                .padding(.top, -10)
                        }
                        
                        Spacer()
                        
                        Button {
                            data.toggleFavorite()
                        } label: {
                            if (data.favorite) {
                                Image(systemName: "star.fill")
                                    .font(.subheadline)
                                    .padding(8)
                                    .foregroundStyle(Color.orange)
                            } else {
                                Image(systemName: "star")
                                    .font(.subheadline)
                                    .padding(8)
                            }
                        }
                        .buttonStyle(.plain)
                        .glassEffect(.regular.interactive(), in: Circle())
                    }
                    
                    Picker("Folder Picker", selection: $data.folderUUID) {
                        ForEach(NavigationPanel.instance.folders, id: \.uuid) { option in
                            Text(option.name).tag(option.uuid)
                        }
                    }
                    .labelsHidden()
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .pickerStyle(.menu)
                    .padding(.top, 4)
                    .disabled(!data.editable)
                    
                    Divider()
                        .padding(.top, 4)
                    
                    ForEach($data.itemFields) { $itemField in
                        GenericItem(data: $itemField, edit: data.editable)
                    }
                    
                    if (!data.itemFields.isEmpty) {
                        Divider()
                            .padding(.top, 4)
                    }
                    
                    GenericItem(data: $data.notes, edit: data.editable)
                    
                    Divider()
                        .padding(.top, 4)
                    
                    if (data.editable) {
                        HStack {
                            Text("Fields")
                                .font(.caption)
                                .padding(.leading, 2)
                            Spacer()
                            Button() {
                                showNewFieldCallout = true
                            } label: {
                                Image(systemName: "plus")
                                    .padding(3)
                            }
                            .buttonStyle(BorderlessButtonStyle())
                            .glassEffect(in: Circle())
                            .padding(.top, 0)
                            .popover(isPresented: $showNewFieldCallout, arrowEdge: .leading) {
                                Menu {
                                    Button("Text Field") {
                                        data.customFields.append(FieldItemData(title: "New Field", value: "", type: .text))
                                        showNewFieldCallout = false
                                    }
                                    Button("Hidden Field") {
                                        data.customFields.append(FieldItemData(title: "New Field", value: "", type: .hidden))
                                        showNewFieldCallout = false
                                    }
                                    Button("Checkbox") {
                                        data.customFields.append(FieldItemData(title: "New Field", value: "false", type: .checkbox))
                                        showNewFieldCallout = false
                                    }
                                    Button("Linked Field") {
                                        data.customFields.append(FieldItemData(title: "New Field", value: "", type: .linked))
                                        showNewFieldCallout = false
                                    }
                                } label: {
                                    Label("Add field", systemImage: "plus.circle")
                                }
                                .menuStyle(.borderlessButton)
                                .padding(.top, 5)
                                .padding(.bottom, 5)
                            }
                        }
                    }
                    
                    ForEach($data.customFields) { $customField in
                        FieldItem(data: $customField, itemType: data.type, edit: data.editable)
                    }
                    
                    if (!data.customFields.isEmpty || data.editable) {
                        Divider()
                            .padding(.top, 4)
                    }
                    
                    if (data.editable) {
                        HStack {
                            Text("Attachments")
                                .font(.caption)
                                .padding(.leading, 2)
                            Spacer()
                            Button() {
                                data.uploadAttachment()
                            } label: {
                                Image(systemName: "plus")
                                    .padding(3)
                            }
                            .buttonStyle(BorderlessButtonStyle())
                            .glassEffect(in: Circle())
                            .padding(.top, 0)
                        }
                    }
                    
                    ForEach($data.attachmentItems) { $attachment in
                        AttachmentItem(data: $attachment, editable: data.editable)
                    }
                    
                    if (!data.attachmentItems.isEmpty) {
                        Divider()
                            .padding(.top, 4)
                    }
                    
                    ForEach(data.itemHistory, id: \.self) { itemHist in
                        Text(verbatim: itemHist)
                            .font(.caption)
                            .foregroundStyle(Color.gray)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    
                    if (data.type == ItemType.Login && !data.passwordHistory.isEmpty) {
                        Button {
                            showPasswordHistory = true
                        } label: {
                            Text(verbatim: "View Password History")
                                .font(.caption)
                                .foregroundStyle(Color.gray)
                        }
                        .buttonStyle(.plain)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .sheet(isPresented: $showPasswordHistory) {
                            VStack {
                                HStack {
                                    Text("Password History")
                                    Spacer()
                                    Button() {
                                        showPasswordHistory = false
                                    } label: {
                                        Image(systemName: "xmark.circle.fill")
                                    }
                                    .buttonStyle(BorderlessButtonStyle())
                                }
                                ForEach($data.passwordHistory, id: \.self) {$val in
                                    GenericItem(data: .constant(GenericItemData(title: val.date, value: val.password, type: .password)), edit: false)
                                }
                            }
                            .padding()
                        }
                    }
                }
                .scrollIndicators(.never)
                .padding(.bottom, 8)
            }
        }
        .padding(16)
        .padding(.bottom, -16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background {
            RoundedRectangle(cornerRadius: 0, style: .continuous)
                .stroke(lineWidth: 0)
                .glassEffect(.regular.interactive(), in: .rect(cornerRadius: 0))
        }
        .padding(.top, -1)
        .padding(.trailing, -1)
        .padding(.bottom, -1)
        .toolbar {
            if (data.viewable) {
                if (NavigationPanel.instance.selection == NavItems.trash) {
                    ToolbarItem {
                        Button {
                            showDeleteCallout = true
                        } label: {
                            Image(systemName: "minus.circle")
                        }
                        .glassEffect(.regular.interactive(), in: Circle())
                    }
                    .sharedBackgroundVisibility(.hidden)
                    ToolbarItem {
                        Button {
                            data.restoreItem()
                        } label: {
                            Image(systemName: "arrow.uturn.backward")
                                .imageScale(.medium)
                        }
                        .glassEffect(.regular.interactive(), in: Circle())
                    }
                    .sharedBackgroundVisibility(.hidden)
                } else if (!data.editable) {
                    /*
                     * Edit Button
                     * It should turn on editable and set editable for each generic item
                     * and field
                     * When edit is pressed, editable will be set to true. If the save button
                     * is pressed then the edit_* fields (eg: edit_itemFields) will be copied
                     * to the normal field (eg: itemFields). If cancel is pressed, then edit_*
                     * fields will be discarded
                     */
                    ToolbarItem {
                        Button {
                            data.editable = true
                            data.saveSnapshot()
                        } label: {
                            Image(systemName: "pencil")
                        }
                        .glassEffect(.regular.interactive(), in: Circle())
                    }
                    .sharedBackgroundVisibility(.hidden)
                    ToolbarItem {
                        Button {
                            data.duplicateItem()
                        } label: {
                            Image(systemName: "document.on.document")
                                .imageScale(.medium)
                        }
                        .glassEffect(.regular.interactive(), in: Circle())
                    }
                    .sharedBackgroundVisibility(.hidden)
                    ToolbarItem {
                        Button {
                            data.deleteItem()
                        } label: {
                            Image(systemName: "trash")
                                .imageScale(.medium)
                        }
                        .glassEffect(.regular.interactive(), in: Circle())
                    }
                    .sharedBackgroundVisibility(.hidden)
                } else {
                    ToolbarItem {
                        Button {
                            if (data.saveItem()) {
                                data.editable = false
                                data.deleteSnapshot()
                            } else {
                                data.editable = false
                                data.pullSnapshot()
                            }
                        } label: {
                            Image(systemName: "square.and.arrow.down")
                        }
                        .glassEffect(.regular.interactive(), in: Circle())
                    }
                    .sharedBackgroundVisibility(.hidden)
                    ToolbarItem {
                        Button {
                            data.editable = false
                            data.pullSnapshot()
                        } label: {
                            Image(systemName: "eraser")
                        }
                        .glassEffect(.regular.interactive(), in: Circle())
                    }
                }
            }
        }
        .alert("Are you sure you would like to Permanantly Delete this item?", isPresented: $showDeleteCallout) {
            Button("Cancel", role: .cancel) { }
            Button("Confirm", role: .destructive) {
                data.permDeleteItem()
            }
        } message: {
            Text("This action cannot be undone.")
        }
        .onAppear {
            #if NON_XCODE_BUILD
                SidePanelBridge.setupCallbacks()
            #endif
        }
        .sheet(isPresented: $data.isReprompt) {
            VStack {
                Text("Enter Password to see Item")
                    .padding(.top, 8)
                SecureField("Password", text: $data.repromptPassword)
                    .padding(.leading, 4)
                    .padding(.trailing, 4)
                    .frame(width: 180)
                Text("Wrong Password")
                    .font(.caption)
                    .foregroundColor(data.repromptFailed ? .red : .clear)
                HStack {
                    Spacer()
                    Button("Cancel", role: .cancel) {
                        data.isReprompt = false
                    }
                    Button("Confirm") {
                        data.viewItemReprompt()
                    }
                    Spacer()
                }
                .padding(.trailing, 4)
                .padding(.bottom, 8)
            }
            .frame(width: 200)
        }
    }
}

#Preview {
    PreviewData().test1()
}
