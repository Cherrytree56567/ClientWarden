import SwiftUI

/*
 * generic - Non-Editable Title and Value
 * password - Non-Editable Title and Hidden Value with Reveal button
 * ml_generic - Non-Editable Title and Multiline Value
 * editable - Non-Editable Title and Editable Value
 * ml_editable - Non-Editable Title and Editable Multiline Value
 * t_editable - Editable Title and value
 */
enum FieldItemType {
    case text
    case hidden
    case checkbox
    case linked
}

struct FieldItemData : Identifiable, Hashable {
    let id = UUID()
    public var title: String
    public var value: String
    public var type: FieldItemType
    
    init(title: String, value: String, type: FieldItemType) {
        self.title = title
        self.value = value
        self.type = type
    }
}

/*
 * TODO: Fix multiline liquid glass color
 */
struct FieldItem: View {
    @State private var data: FieldItemData
    @State private var revealed: Bool
    @State public var editable: Bool
    
    init(data: FieldItemData) {
        self.data = data
        self.revealed = true
        self.editable = false
    }
    
    init(data: FieldItemData, editable: Bool) {
        self.data = data
        self.revealed = true
        self.editable = editable
    }
    
    var body: some View {
        VStack(alignment: .leading) {
            if (editable) {
                TextField("Title", text: $data.title)
                    .font(.caption)
                    .foregroundColor(Color.gray)
                    .padding(.bottom, -6)
                    .padding(-4)
            } else {
                Text(data.title)
                    .font(.caption)
                    .foregroundColor(Color.gray)
                    .padding(.bottom, -6)
            }
            
            Divider()
            
            HStack {
                if (data.type == FieldItemType.hidden) {
                    Text(verbatim: revealed ? data.value : String(repeating: "•", count: data.value.count))
                        .font(.system(.body, design: .monospaced))
                    
                    Spacer()
                    
                    /*
                     * The button reveals or hides the text via bool
                     * as well as creating a nice glow when the value
                     * is revealed
                     */
                    Button {
                        revealed.toggle()
                    } label: {
                        if revealed {
                            Image(systemName: "eye.fill")
                                .font(.caption)
                                .padding(.horizontal, 4)
                        } else {
                            Image(systemName: "eye")
                                .font(.caption)
                                .padding(.horizontal, 4)
                        }
                    }
                    .buttonStyle(.plain)
                    .background {
                        LinearGradient(
                            gradient: Gradient(colors: [.clear, .blue.opacity(0.6)]),
                            startPoint: .leading,
                            endPoint: .trailing
                        )
                        .opacity(revealed ? 1 : 0)
                        .blur(radius: 8)
                        .frame(maxHeight: .infinity)
                        .scaleEffect(x: 4.0, y: 1.40)
                        .offset(x: revealed ? 0 : 60)
                    }
                    .animation(.easeInOut(duration: 0.25), value: revealed)
                } else {
                    if (editable) {
                        TextField("Title", text: Binding(get: { data.value }, set: { data.value = $0 }), axis: .vertical)
                            .lineLimit(6)
                            .padding(-4)
                    } else {
                        Text(verbatim: data.value)
                    }
                }
            }
            .padding(.top, 1)
            .padding(.bottom, 1)
        }
        .padding(8)
        .background {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(lineWidth: 0)
        }
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .clipped()
        .contentShape(Rectangle())
        .onTapGesture {
            /*
             * TODO: X1FE - Use Clipboard Swift Bridge to copy the value
             */
        }
    }
}

#Preview {
    HStack(spacing: 0) {
        NavigationPanel()
        SidePanel(name: "Google", uuid: UUID(), type: ItemType.Login, favorite: false)
    }
}
