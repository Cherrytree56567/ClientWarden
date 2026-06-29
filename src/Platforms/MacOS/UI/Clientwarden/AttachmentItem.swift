import SwiftUI

struct AttachmentItemData : Identifiable, Hashable {
    public var id: UUID
    public var name: String
    public var progress: Double = 0.0
    
    init(id: UUID, name: String) {
        self.id = id
        self.name = name
    }
}

struct AttachmentItem: View {
    @Binding var data: AttachmentItemData
    public var editable: Bool
    
    init(data: Binding<AttachmentItemData>, editable: Bool) {
        self._data = data
        self.editable = editable
    }
    
    var body: some View {
        VStack(alignment: .leading) {
            Text("Attachment")
                .font(.caption)
                .foregroundColor(Color.gray)
                .padding(.bottom, -6)
                .padding(.leading, 2)
            
            Divider()
            
            HStack {
                /*
                 * Hidden items need a show reveal button
                 * Checkbox needs a toggle w/o divider and the title
                 * next to the toggle
                 * Text items are normal.
                 * Linked needs a specific value per number
                 */
                Image(systemName: "doc")
                    .padding(.trailing, -2)
                
                if (editable) {
                    TextField("Name", text: $data.name)
                } else {
                    Text(verbatim: data.name)
                }
                
                Spacer()
                
                if (editable) {
                    Button {
                        SidePanel.instance.downloadAttachment(id: data.id)
                    } label: {
                        Image(systemName: "trash")
                            .padding(.horizontal, 4)
                            .padding(.top, -4)
                    }
                    .buttonStyle(.plain)
                } else {
                    Button {
                        SidePanel.instance.downloadAttachment(id: data.id)
                    } label: {
                        Image(systemName: "square.and.arrow.down")
                            .padding(.horizontal, 4)
                            .padding(.top, -4)
                            .padding(.bottom, -4)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.top, 1)
            
            if (data.progress != 0.0) {
                ProgressView(value: data.progress)
                    .progressViewStyle(.linear)
                    .scaleEffect(x: 1, y: 0.5, anchor: .center)
                    .padding(.top, -10)
            }
        }
        .padding(2)
        .background {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(lineWidth: 0)
        }
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .clipped()
    }
}

#Preview {
    PreviewData().test1()
}
