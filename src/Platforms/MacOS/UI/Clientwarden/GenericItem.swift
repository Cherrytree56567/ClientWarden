import SwiftUI

/*
 * generic - Non-Editable Title and Value
 * password - Non-Editable Title and Hidden Value with Reveal button
 * ml_generic - Non-Editable Title and Multiline Value
 * editable - Non-Editable Title and Editable Value
 * ml_editable - Non-Editable Title and Editable Multiline Value
 * t_editable - Editable Title and value
 */
enum GenericItemType {
    case generic
    case password
    case ml_generic
    case ml_password
    case editable
    case ml_editable
    case t_editable
}

struct GenericItemData : Identifiable, Hashable {
    let id = UUID()
    public var title: String
    public var value: String
    public var type: GenericItemType
    
    init(title: String, value: String, type: GenericItemType) {
        self.title = title
        self.value = value
        self.type = type
    }
    
    func isMultiline() -> Bool {
        switch type {
            case .ml_generic, .ml_password, .ml_editable:
                return true
            default:
                return false
        }
    }
    
    func isEditable() -> Bool {
        switch type {
            case .editable, .ml_editable:
                return true
            default:
                return false
        }
    }
    
    func d_value() -> String {
        if (isMultiline()) {
            return value
        } else {
            return value.replacingOccurrences(of: "\n", with: " ")
        }
    }
}

/*
 * TODO: Fix multiline liquid glass color
 */
struct GenericItem: View {
    @State private var data: GenericItemData
    @State private var revealed: Bool
    @State public var transparent: Bool
    
    init(data: GenericItemData) {
        self.data = data
        self.revealed = true
        self.transparent = false
    }
    
    init(data: GenericItemData, transparent: Bool) {
        self.data = data
        self.revealed = true
        self.transparent = transparent
    }
    
    var body: some View {
        VStack(alignment: .leading) {
            if (data.type == GenericItemType.t_editable) {
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
                if (data.type == GenericItemType.password) {
                    Text(verbatim: revealed ? data.d_value() : String(repeating: "•", count: data.d_value().count))
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
                    if (data.isEditable()) {
                        TextField("Title", text: Binding(get: { data.d_value() }, set: { data.value = $0 }), axis: .vertical)
                            .lineLimit(6)
                            .padding(-4)
                    } else {
                        Text(verbatim: data.d_value())
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
                .fill(transparent ? AnyShapeStyle(Color.clear) : AnyShapeStyle(Material.ultraThinMaterial))
                .stroke(Color.gray.opacity(transparent ? 0.0 : (data.isMultiline() ? 0.5 : 0.3)), lineWidth: 0.5)
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
