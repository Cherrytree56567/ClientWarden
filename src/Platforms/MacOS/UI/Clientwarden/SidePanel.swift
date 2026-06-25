import SwiftUI

struct SidePanel: View {
    @State private var favorite: Bool
    private var name: String
    private var uuid: UUID
    private var type: ItemType
    
    private var itemFields: [GenericItemData] = []
    private var customFields: [FieldItemData] = []
    private var itemHistory: [String] = []
    private var notes: String = ""
    private var editable: Bool = false
    
    public var cb_favorite: ((Bool, UUID) -> Bool)?
    
    init(name: String, uuid: UUID, type: ItemType, favorite: Bool) {
        self.favorite = favorite
        self.name = name
        self.type = type
        self.uuid = uuid
    }
    
    init(name: String, uuid: UUID, type: ItemType, favorite: Bool, itemFields: [GenericItemData], customFields: [FieldItemData], itemHistory: [String], notes: String, editable: Bool, cb_favorite: ((Bool, UUID) -> Bool)?) {
        self.favorite = favorite
        self.name = name
        self.type = type
        self.uuid = uuid
        self.itemFields = itemFields
        self.customFields = customFields
        self.itemHistory = itemHistory
        self.cb_favorite = cb_favorite
        self.notes = notes
        self.editable = editable
    }
    
    var body: some View {
        VStack(alignment: .leading) {
            ScrollView {
                HStack {
                    Image("profile1")
                        .resizable()
                        .frame(width: 32, height: 32)
                        .clipShape(RoundedRectangle(cornerRadius: 4))
                    
                    VStack(alignment: .leading) {
                        Text("Google")
                            .font(.system(size: 18, weight: .bold))
                            .padding(.top, -2)
                        Text("Login")
                            .font(.system(size: 8))
                            .foregroundStyle(.secondary)
                            .padding(.top, -10)
                    }
                    
                    Spacer()
                    
                    Button {
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
                    } label: {
                        if (favorite) {
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
                
                ForEach(itemFields) { itemField in
                    GenericItem(data: itemField)
                }
                
                if !itemFields.isEmpty {
                    Divider()
                        .padding(.top, 4)
                }
                
                GenericItem(data: GenericItemData(title: "Notes", value: notes, type: editable ? GenericItemType.ml_editable : GenericItemType.ml_generic))
                
                Divider()
                    .padding(.top, 4)
                
                ForEach(customFields) { customField in
                    FieldItem(data: customField, itemType: type)
                }
                
                if !customFields.isEmpty {
                    Divider()
                        .padding(.top, 4)
                }
                
                ForEach(itemHistory, id: \.self) { itemHist in
                    Text(verbatim: itemHist)
                        .font(.caption)
                        .foregroundStyle(Color.gray)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            
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
    }
}

#Preview {
    HStack(spacing: 0) {
        NavigationPanel()
        SidePanel(name: "Google", uuid: UUID(), type: ItemType.Login, favorite: true)
    }
}
