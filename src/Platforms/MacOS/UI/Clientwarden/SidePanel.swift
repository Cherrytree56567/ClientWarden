import SwiftUI

/*
 * So the way Swift works, is it keeps recreating the View for each frame, kinda.
 * Essentially, the SidePanelView is just the stuff thats being displayed, and SidePanel
 * is just the data. Since there is always only 1 Side Panel, Its a good idea to separate
 * the SidePanel View and the SidePanel Data.
 */

@Observable
final class SidePanel {
    static let instance = SidePanel()
    public init() {}
    
    public var name: String = ""
    public var uuid: UUID = UUID()
    public var type: ItemType = ItemType.Login
    public var icon: ClientwardenImage = ClientwardenImage(type: ImageType.bundle, path: "profile1")
    public var editable: Bool = false
    public var favorite: Bool = false
    
    public var itemFields: [GenericItemData] = []
    public var customFields: [FieldItemData] = []
    public var itemHistory: [String] = []
    public var passwordHistory: [String] = []
    public var notes: GenericItemData = GenericItemData(title: "Notes", value: "", type: GenericItemType.ml_generic)
    
    public var cb_favorite: ((Bool, UUID) -> Bool)?
    
    public var cb_duplicate: ((UUID) -> Bool)?
    public var cb_delete: ((UUID) -> Bool)?
    public var cb_save: ((UUID) -> Bool)?
    
    public var cb_sidebar: ((UUID) -> Bool)?
    
    public var s_name: String = ""
    public var s_favorite: Bool = false
    
    public var s_itemFields: [GenericItemData] = []
    public var s_customFields: [FieldItemData] = []
    public var s_itemHistory: [String] = []
    public var s_passwordHistory: [String] = []
    public var s_notes: GenericItemData = GenericItemData(title: "Notes", value: "", type: GenericItemType.ml_generic)
    
    func saveSnapshot() {
        s_name = name
        s_favorite = favorite
        s_itemFields = itemFields
        s_customFields = customFields
        s_itemHistory = itemHistory
        s_passwordHistory = passwordHistory
        s_notes = notes
    }
    
    func pullSnapshot() {
        name = s_name
        favorite = s_favorite
        itemFields = s_itemFields
        customFields = s_customFields
        itemHistory = s_itemHistory
        passwordHistory = s_passwordHistory
        notes = s_notes
    }
    
    func deleteSnapshot() {
        s_name = ""
        s_favorite = false
        s_itemFields = []
        s_customFields = []
        s_itemHistory = []
        s_passwordHistory = []
        s_notes = GenericItemData(title: "Notes", value: "", type: GenericItemType.ml_generic)
    }
    
    func toggleFavorite() {
        /*
         * Check if the var has a callback and check if
         * the callback was successful
         */
        if let fav = cb_favorite?(favorite, uuid) {
            if (fav) {
                favorite.toggle()
            } else {
                g_toastStore.toasts.append(Toast(message: "Failed to set favorite"))
            }
        } else {
            g_toastStore.toasts.append(Toast(message: "No callback set for favorite"))
        }
    }
    
    func saveItem() -> Bool {
        /*
         * Check if the var has a callback and check if
         * the callback was successful
         */
        if let sav = cb_save?(uuid) {
            if (sav) {
                return true
            } else {
                g_toastStore.toasts.append(Toast(message: "Failed to save item"))
            }
        } else {
            g_toastStore.toasts.append(Toast(message: "No callback set for save Item"))
        }
        return true
    }
    
    func duplicateItem() {
        /*
         * Check if the var has a callback and check if
         * the callback was successful
         */
        if let dup = cb_duplicate?(uuid) {
            if (dup) {
            } else {
                g_toastStore.toasts.append(Toast(message: "Failed to duplicate item"))
            }
        } else {
            g_toastStore.toasts.append(Toast(message: "No callback set for duplicate Item"))
        }
    }
    
    func deleteItem() {
        /*
         * Check if the var has a callback and check if
         * the callback was successful
         */
        if let del = cb_delete?(uuid) {
            if (del) {
            } else {
                g_toastStore.toasts.append(Toast(message: "Failed to delete item"))
            }
        } else {
            g_toastStore.toasts.append(Toast(message: "No callback set for delete Item"))
        }
    }
    
    func viewItem(cb_uuid: UUID) {
        /*
         * Check if the var has a callback and check if
         * the callback was successful
         */
        if let side = cb_sidebar?(cb_uuid) {
            if (side) {
            } else {
                g_toastStore.toasts.append(Toast(message: "Failed to view item"))
            }
        } else {
            g_toastStore.toasts.append(Toast(message: "No callback set for view Item"))
        }
    }
}

struct SidePanelView: View {
    @State private var showPasswordHistory: Bool = false
    @State private var showNewFieldCallout: Bool = false
    
    @Bindable var data: SidePanel = SidePanel.instance
    
    var body: some View {
        VStack(alignment: .leading) {
            ScrollView {
                HStack {
                    if let image = data.icon.getImage() {
                        image
                            .resizable()
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
                
                if (!data.customFields.isEmpty) {
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
                            ForEach($data.passwordHistory, id: \.self) {$password in
                                GenericItem(data: .constant(GenericItemData(title: "Password", value: password, type: .password)), edit: false)
                            }
                        }
                        .padding()
                    }
                }
            }
            .scrollIndicators(.never)
        }
        .padding(16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background {
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .stroke(lineWidth: 0)
                .glassEffect(in: .rect(cornerRadius: 16))
        }
        .padding(.vertical, 8)
        .padding(.trailing, 8)
        .toolbar {
            if (!data.editable) {
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
}

#Preview {
    PreviewData().test1()
}
