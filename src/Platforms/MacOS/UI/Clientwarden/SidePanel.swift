import SwiftUI

struct SidePanel: View {
    @State private var toasts: [Toast] = []
    
    @State private var favorite: Bool
    @State private var name: String
    @State private var uuid: UUID
    @State private var type: ItemType
    
    @State private var itemFields: [GenericItemData] = []
    @State private var customFields: [FieldItemData] = [
        FieldItemData(title: "Text", value: "Some Text", type: FieldItemType.text),
        FieldItemData(title: "Hidden", value: "@abc12345", type: FieldItemType.hidden),
        FieldItemData(title: "Checkbox", value: "true", type: FieldItemType.checkbox),
        FieldItemData(title: "Linked", value: "100", type: FieldItemType.linked)
    ]
    
    @State public var cb_favorite: ((Bool, UUID) -> Bool)?
    
    init(name: String, uuid: UUID, type: ItemType, favorite: Bool) {
        self.favorite = favorite
        self.name = name
        self.type = type
        self.uuid = uuid
    }
    
    var body: some View {
        VStack(alignment: .leading) {
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
                        if fav {
                            favorite.toggle()
                        } else {
                            toasts.append(Toast(message: "Failed to create folder"))
                        }
                    } else {
                        toasts.append(Toast(message: "No callback set for createFolder"))
                    }
                } label: {
                    if favorite {
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
            
            ForEach(customFields) { customField in
                FieldItem(data: customField, itemType: type)
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
        .toast($toasts)
    }
}

#Preview {
    HStack(spacing: 0) {
        NavigationPanel()
        SidePanel(name: "Google", uuid: UUID(), type: ItemType.Login, favorite: false)
    }
}
