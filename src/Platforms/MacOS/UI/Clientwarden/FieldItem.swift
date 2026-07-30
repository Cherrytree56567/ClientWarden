import SwiftUI

@objc
enum FieldItemType: Int {
    case text
    case hidden
    case checkbox
    case linked
}

@objcMembers
@Observable
class FieldItemData : NSObject, Identifiable {
    let id = UUID()
    @objc public var title: String
    @objc public var value: String
    @objc public var type: FieldItemType
    
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
    @Binding var data: FieldItemData
    @State private var revealed: Bool
    private var itemType: ItemType
    public var editable: Bool
    var onRemove: (() -> Void)?
    
    private var loginLinkedBinding: Binding<LoginLinkedIDs> {
        Binding(
            get: {
                let raw = Int(data.value) ?? -1
                return LoginLinkedIDs(rawValue: raw) ?? LoginLinkedIDs.Username
            },
            set: { newVal in
                data.value = String(newVal.rawValue)
            }
        )
    }
    
    private var cardLinkedBinding: Binding<CardLinkedIDs> {
        Binding(
            get: {
                let raw = Int(data.value) ?? -1
                return CardLinkedIDs(rawValue: raw) ?? CardLinkedIDs.CardholderName
            },
            set: { newVal in
                data.value = String(newVal.rawValue)
            }
        )
    }
    
    private var identityLinkedBinding: Binding<IdentityLinkedIDs> {
        Binding(
            get: {
                let raw = Int(data.value) ?? -1
                return IdentityLinkedIDs(rawValue: raw) ?? IdentityLinkedIDs.Email
            },
            set: { newVal in
                data.value = String(newVal.rawValue)
            }
        )
    }
    
    init(data: Binding<FieldItemData>, itemType: ItemType, edit: Bool, onRemove: (() -> Void)?) {
        self._data = data
        self.revealed = false
        self.itemType = itemType
        self.editable = edit
        self.onRemove = onRemove
    }
    
    var body: some View {
        VStack(alignment: .leading) {
            if (data.type != FieldItemType.checkbox) {
                if (editable) {
                    TextField("Title", text: $data.title)
                        .font(.caption)
                        .foregroundColor(Color.gray)
                        .padding(.bottom, -6)
                        .padding(.leading, 2)
                        .padding(.trailing, 2)
                } else {
                    Text(data.title)
                        .font(.caption)
                        .foregroundColor(Color.gray)
                        .padding(.bottom, -6)
                }
                
                Divider()
            }
            
            HStack {
                /*
                 * Hidden items need a show reveal button
                 * Checkbox needs a toggle w/o divider and the title
                 * next to the toggle
                 * Text items are normal.
                 * Linked needs a specific value per number
                 */
                if (data.type == FieldItemType.checkbox) {
                    HStack {
                        Toggle("", isOn: Binding(get: {
                            data.value == "true" ? true : false
                        }, set: {
                            if (editable) {
                                data.value = ($0 ? "true" : "false")
                            }
                        }))
                        .labelsHidden()
                        .padding(.trailing, -2)
                        if (editable) {
                            HStack {
                                TextField("Value", text: $data.title)
                                Button {
                                    onRemove?()
                                } label: {
                                    Image(systemName: "xmark.circle.fill")
                                }
                                .buttonStyle(.plain)
                            }
                        } else {
                            Text(verbatim: data.title)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                } else if (data.type == FieldItemType.hidden) {
                    if (editable) {
                        HStack {
                            TextField("Value", text: $data.value, axis: .vertical)
                                .lineLimit(6)
                                .padding(.top, -4)
                            Button {
                                onRemove?()
                            } label: {
                                Image(systemName: "xmark.circle.fill")
                            }
                            .buttonStyle(.plain)
                        }
                    } else {
                        Text(verbatim: revealed ? data.value : String(repeating: "•", count: data.value.count))
                            .font(.system(.body, design: .monospaced))
                            .privacySensitive()
                        
                        Spacer()
                        
                        /*
                         * The button reveals or hides the text via bool
                         * as well as creating a nice glow when the value
                         * is revealed
                         */
                        Button {
                            revealed.toggle()
                        } label: {
                            if (revealed) {
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
                    }
                } else if (data.type == FieldItemType.linked) {
                    if (editable) {
                        /*
                         * Create a Picker that used bindings for each type of item
                         */
                        HStack {
                            if (itemType == ItemType.Login) {
                                Picker("", selection: loginLinkedBinding) {
                                    ForEach(LoginLinkedIDs.allCases, id: \.self) { id in
                                        Text(id.description).tag(id)
                                    }
                                }
                                .pickerStyle(.menu)
                                .labelsHidden()
                                .padding(-4)
                            } else if (itemType == ItemType.Card) {
                                Picker("", selection: cardLinkedBinding) {
                                    ForEach(CardLinkedIDs.allCases, id: \.self) { id in
                                        Text(id.description).tag(id)
                                    }
                                }
                                .pickerStyle(.menu)
                                .labelsHidden()
                                .padding(-4)
                            } else if (itemType == ItemType.Identity) {
                                Picker("", selection: identityLinkedBinding) {
                                    ForEach(IdentityLinkedIDs.allCases, id: \.self) { id in
                                        Text(id.description).tag(id)
                                    }
                                }
                                .pickerStyle(.menu)
                                .labelsHidden()
                                .padding(-4)
                            }
                            
                            Spacer()
                            
                            Button {
                                onRemove?()
                            } label: {
                                Image(systemName: "xmark.circle.fill")
                            }
                            .buttonStyle(.plain)
                        }
                    } else {
                        /*
                         * We need to convert the text to Int and then
                         * to the enum and get the desc
                         */
                        if (itemType == ItemType.Login) {
                            Text(verbatim: {
                                guard let rawVal = Int(data.value),
                                      let linkedId = LoginLinkedIDs(rawValue: rawVal) else {
                                    return "Unknown"
                                }
                                return linkedId.description
                            }())
                        } else if (itemType == ItemType.Card) {
                            Text(verbatim: {
                                guard let rawVal = Int(data.value),
                                      let linkedId = CardLinkedIDs(rawValue: rawVal) else {
                                    return "Unknown"
                                }
                                return linkedId.description
                            }())
                        } else if (itemType == ItemType.Identity) {
                            Text(verbatim: {
                                guard let rawVal = Int(data.value),
                                      let linkedId = IdentityLinkedIDs(rawValue: rawVal) else {
                                    return "Unknown"
                                }
                                return linkedId.description
                            }())
                        }
                    }
                } else {
                    if (editable) {
                        HStack {
                            TextField("Value", text: Binding(get: { data.value }, set: { data.value = $0 }), axis: .vertical)
                                .lineLimit(6)
                                .padding(.top, -4)
                            
                            Button {
                                onRemove?()
                            } label: {
                                Image(systemName: "xmark.circle.fill")
                            }
                            .buttonStyle(.plain)
                        }
                    } else {
                        Text(verbatim: data.value)
                    }
                }
            }
            .padding(.top, 1)
            .padding(.bottom, 1)
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
