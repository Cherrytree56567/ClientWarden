import SwiftUI

struct ItemElement: Identifiable, Equatable {
    public var id: UUID { uuid }
    
    public var name: String
    public var uuid: UUID
    public var type: ItemType
    public var image: ClientwardenImage?
    
    static func == (old: ItemElement, new: ItemElement) -> Bool {
        old.uuid == new.uuid &&
        old.name == new.name &&
        old.type == new.type &&
        old.image === new.image
    }
}

struct ItemElementView: View {
    @State var data: ItemElement
    
    var body: some View {
        Button {
            SidePanel.instance.viewItem(cb_uuid: data.uuid)
        } label: {
            HStack {
                Image(data.image?.path ?? "")
                    .resizable()
                    .frame(width: 30, height: 30)
                    .clipShape(RoundedRectangle(cornerRadius: 4))
                
                VStack(alignment: .leading) {
                    Text(data.name)
                        .font(.system(size: 14, weight: .bold))
                        .padding(.top, -2)
                        .lineLimit(1)
                    Text(data.type.description)
                        .font(.system(size: 8))
                        .foregroundStyle(.secondary)
                        .padding(.top, -10)
                }
                
                Spacer()
            }
            .padding(8)
            .contentShape(Rectangle())
        }
        .buttonStyle(PlainButtonStyle())
    }
}

#Preview {
    ItemElementView(data: ItemElement(name: "Item1", uuid: UUID(), type: ItemType.Login, image: ClientwardenImage(type: ImageType.bundle, path: "profile1")))
}
