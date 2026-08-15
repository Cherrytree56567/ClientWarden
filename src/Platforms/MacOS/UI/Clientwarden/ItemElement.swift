import SwiftUI

@objcMembers
class ItemElement: NSObject, Identifiable {
    public var id: UUID { uuid }
    
    public var name: String
    public var uuid: UUID
    public var type: ItemType
    public var image: ClientwardenImage?

    init(name: String, uuid: UUID, type: ItemType, image: ClientwardenImage? = nil) {
        self.name = name
        self.uuid = uuid
        self.type = type
        self.image = image
    }
    
    static func == (old: ItemElement, new: ItemElement) -> Bool {
        old.uuid == new.uuid &&
        old.name == new.name &&
        old.type == new.type &&
        old.image === new.image
    }
}

struct ItemElementView: View {
    var data: ItemElement
    var selected: Bool = false
    
    var body: some View {
        HStack {
            if let img = data.image?.getImage() {
                if data.image?.type == .systemImage {
                    img
                        .font(.system(size: 24))
                        .frame(width: 32, height: 32)
                } else {
                    img
                        .resizable()
                        .scaledToFill()
                        .frame(width: 24, height: 24)
                        .clipShape(RoundedRectangle(cornerRadius: 4))
                        .frame(width: 32, height: 32)
                    }
                } else {
                    Image(systemName: "viewfinder")
                        .font(.system(size: 24))
                        .frame(width: 32, height: 32)
                }
                
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
            .padding(4)
            .contentShape(Rectangle())
            .background {
                GeometryReader { geo in
                    Circle()
                        .fill(Color.blue.opacity(0.6))
                        .frame(width: geo.size.height * 1.4, height: geo.size.height * 1.4)
                        .blur(radius: 24)
                        .position(x: geo.size.width, y: geo.size.height / 2)
                        .opacity(selected ? 1 : 0)
                }
            }
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            .animation(.easeInOut(duration: 0.25), value: selected)
    }
}

#Preview {
    //ItemElementView(data: ItemElement(name: "Item1", uuid: UUID(), type: ItemType.Login, image: ClientwardenImage(type: ImageType.bundle, path: "profile1")))
    PreviewData().test1()
}
