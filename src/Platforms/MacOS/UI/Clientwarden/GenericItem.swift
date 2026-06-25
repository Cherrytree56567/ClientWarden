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
    case totp
    case ml_generic
    case ml_password
    case editable
    case ml_editable
    case t_editable
    case website_editable
}

struct GenericItemData : Identifiable {
    let id = UUID()
    public var title: String
    public var value: String
    public var type: GenericItemType
    public var cb_getTOTP: (() -> (refreshDate: Int64, maxTimer: Int, value: String))?
    
    init(title: String, value: String, type: GenericItemType) {
        self.title = title
        self.value = value
        self.type = type
    }
    
    init(title: String, value: String, type: GenericItemType, cb_getTOTP: (() -> (refreshDate: Int64, maxTimer: Int, value: String))?) {
        self.title = title
        self.value = value
        self.type = type
        self.cb_getTOTP = cb_getTOTP
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

struct TOTPTimerModifier: ViewModifier {
    let active: Bool
    let cb_getTOTP: (() -> (refreshDate: Int64, maxTimer: Int, value: String))?
    @Binding var left: Double
    @Binding var maxValue: Int
    @Binding var value: String
    
    func body(content: Content) -> some View {
        content
            .task(id: active) {
                guard active, let cb_getTOTP else { return }
                
                var refresh: Int64 = 0
                
                while !Task.isCancelled {
                    let now = Int64(Date().timeIntervalSince1970)
                    
                    if (now >= refresh) {
                        let res = cb_getTOTP()
                        value = res.value
                        maxValue = res.maxTimer
                        refresh = res.refreshDate
                    }

                    left = max(0, Double(refresh - now))

                    try? await Task.sleep(for: .seconds(1))
                }
            }
    }
}

struct GenericItem: View {
    @State private var data: GenericItemData
    @State private var revealed: Bool
    @State private var transparent: Bool
    
    @State private var totpValue: String = ""
    @State private var totpLeft: Double = 0
    @State private var totpMax: Int = 30
    
    private var websiteBinding: Binding<[String]> {
        Binding(
            get: { data.value.components(separatedBy: .newlines) },
            set: { data.value = $0.joined(separator: "\n") }
        )
    }
    
    init(data: GenericItemData) {
        self.data = data
        self.revealed = false
        self.transparent = false
    }
    
    init(data: GenericItemData, transparent: Bool) {
        self.data = data
        self.revealed = false
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
                } else if (data.type == GenericItemType.totp) {
                    Text(verbatim: totpValue.isEmpty ? data.d_value() : totpValue)
                    
                    Spacer()
                    
                    /*
                     * Since I wanted to have a UI and UI Bridge, I decided to use a totp
                     * callback which gets called everytime the totp needs to be refreshed.
                     */
                    if (data.cb_getTOTP != nil && totpMax > 0) {
                        let progress = totpMax > 0 ? totpLeft / Double(totpMax) : 0
                        let slabel = String(Int(totpLeft))
                        Gauge(value: progress) {
                        } currentValueLabel: {
                            Text(slabel)
                        }
                        .gaugeStyle(.accessoryCircular)
                        .scaleEffect(0.35)
                        .padding(-20)
                        .padding(.trailing, 4)
                        .tint(totpLeft < 10 ? Color.red.opacity(0.8) : .accentColor)
                    }
                } else {
                    if (data.isEditable()) {
                        TextField("Title", text: Binding(get: { data.d_value() }, set: { data.value = $0 }), axis: .vertical)
                            .lineLimit(6)
                            .padding(-4)
                    } else if (data.type == GenericItemType.website_editable) {
                        VStack {
                            List {
                                ForEach(websiteBinding.wrappedValue.indices, id: \.self) { index in
                                    HStack {
                                        TextField("Website", text: Binding(
                                            get: { websiteBinding.wrappedValue[index] },
                                            set: { newVal in
                                                var val = websiteBinding.wrappedValue
                                                val[index] = newVal
                                                data.value = val.joined(separator: "\n")
                                            }
                                        ))
                                        
                                        Button {
                                            var val = websiteBinding.wrappedValue
                                            val.remove(at: index)
                                            data.value = val.joined(separator: "\n")
                                        } label: {
                                            Image(systemName: "minus.circle")
                                        }
                                        .buttonStyle(BorderlessButtonStyle())
                                    }
                                }
                                .onMove { index, offset in
                                    var val = websiteBinding.wrappedValue
                                    val.move(fromOffsets: index, toOffset: offset)
                                    data.value = val.joined(separator: "\n")
                                }
                                .onDelete { offset in
                                    var val = websiteBinding.wrappedValue
                                    val.remove(atOffsets: offset)
                                    data.value = val.joined(separator: "\n")
                                }
                            }
                            .scrollContentBackground(.hidden)
                            .listStyle(.plain)
                            .frame(height: max(CGFloat(websiteBinding.wrappedValue.count) * 24 + 8, 0))
                            
                            Button {
                                var val = websiteBinding.wrappedValue
                                val.append("")
                                data.value = val.joined(separator: "\n")
                            } label: {
                                Label("Add website", systemImage: "plus.circle")
                                    .font(.caption)
                                    .frame(maxWidth: .infinity, alignment: .center)
                            }
                        }
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
            g_toastStore.toasts.append(Toast(message: "Copied to clipboard", icon: "document.on.document").setColor(color: Color.clear))
        }
        .modifier(
            TOTPTimerModifier(
                active: data.type == .totp,
                cb_getTOTP: data.cb_getTOTP,
                left: $totpLeft,
                maxValue: $totpMax,
                value: $totpValue
            )
        )
    }
}

#Preview {
    HStack(spacing: 0) {
        NavigationPanel()
        SidePanel(name: "Google", uuid: UUID(), type: ItemType.Login, favorite: false)
    }
}

