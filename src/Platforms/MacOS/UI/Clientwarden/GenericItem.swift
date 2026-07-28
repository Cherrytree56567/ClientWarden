import SwiftUI
import Combine

/*
 * Generic Item is used for all main fields in an item.
 * The title cannot be changed in a Generic Item.
 * All Generic Items use a simple Text Field when editable is set, except for
 * website, which uses a custom re-arrangable Text Field List.
 * To use the TOTP Field, a totp callback must be set which will be called,
 * after the TOTP Code expires.
 *
 * generic - Title and Value
 * password - Title and Hidden Value with Reveal Button
 * totp - Title and Value (not displayed) with TOTP
 * website - Title and Multiline Value
 * ml_generic - Title and Multiline Value
 * ml_password - Title and Hidden Multiline Value with Reveal Button
 */
@objc
enum GenericItemType: Int {
    case generic
    case password
    case totp
    case website
    case ml_generic
    case ml_password
    case date
}

@objcMembers
class TOTPResult: NSObject {
    @objc public let refreshDate: Int64
    @objc public let maxTimer: Int
    @objc public let value: String

    init(refreshDate: Int64, maxTimer: Int, value: String) {
        self.refreshDate = refreshDate
        self.maxTimer = maxTimer
        self.value = value
    }
}

@objcMembers
class GenericItemData : NSObject, Identifiable, ObservableObject {
    let id = UUID()
    @objc @Published public var title: String
    @objc @Published public var value: String
    @objc @Published public var type: GenericItemType
    @objc public var cb_getTOTP: (() -> TOTPResult)?
    
    init(title: String, value: String, type: GenericItemType) {
        self.title = title
        self.value = value
        self.type = type
    }
    
    init(title: String, value: String, type: GenericItemType, cb_getTOTP: (() -> TOTPResult)?) {
        self.title = title
        self.value = value
        self.type = type
        self.cb_getTOTP = cb_getTOTP
    }
    
    func isMultiline() -> Bool {
        switch type {
            case .ml_generic, .ml_password, .website:
                return true
            default:
                return false
        }
    }
    
    /*
     * Formatted Value
     * When the type isn't a Multi-Line Type, the newline values are replaced with a space.
     */
    func f_value() -> String {
        if (isMultiline()) {
            return value
        } else {
            return value.replacingOccurrences(of: "\n", with: " ")
        }
    }

    func _copy() -> GenericItemData {
        GenericItemData(title: title, value: value, type: type, cb_getTOTP: cb_getTOTP)
    }
}

/*
 * Used as a TOTP Callback Timer
 * First, it calls the TOTP Callback and gets the refreshDate, maxTimer and value.
 * After the refreshDate is reached, the callback is called again to refresh the values
 */
struct TOTPTimerModifier: ViewModifier {
    let active: Bool
    let cb_getTOTP: (() -> TOTPResult)?
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
    @ObservedObject var data: GenericItemData
    @State private var revealed: Bool
    
    @State private var totpValue: String = ""
    @State private var totpLeft: Double = 0
    @State private var totpMax: Int = 30
    @State private var passwordGenTab: Int = 0
    @State private var numbers: Bool = false
    @State private var symbols: Bool = false
    @State private var caps: Bool = false
    @State private var size: Int = 16
    public var editable: Bool
    
    private var websiteBinding: Binding<[String]> {
        Binding(
            get: { data.value.components(separatedBy: .newlines) },
            set: { data.value = $0.joined(separator: "\n") }
        )
    }
    private var dateBinding: Binding<Date> {
        Binding(
            get: {
                let formatter = DateFormatter()
                formatter.dateFormat = "MM/yyyy"
                return formatter.date(from: data.value) ?? Date()
            },
            set: { newDate in
                let formatter = DateFormatter()
                formatter.dateFormat = "MM/yyyy"
                data.value = formatter.string(from: newDate)
            }
        )
    }
    
    init(data: Binding<GenericItemData>, edit: Bool) {
        self.data = data.wrappedValue
        self.revealed = false
        self.editable = edit
    }
    
    var body: some View {
        VStack(alignment: .leading) {
            if (data.type == GenericItemType.password && editable && data.title == "Password") {
                HStack {
                    Text("Password Generator")
                        .padding(.leading, 8)
                    Spacer()
                    Picker("", selection: $passwordGenTab) {
                        Text("Random")
                            .font(.caption)
                            .tag(0)
                        Text("Simple")
                            .font(.caption)
                            .tag(1)
                        Text("Pin")
                            .font(.caption)
                            .tag(2)
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .controlSize(.small)
                    .padding(.trailing, 8)
                    .onChange(of: passwordGenTab) { _, newTab in
                        switch newTab {
                            case 0: 
                                size = 16
                            case 1: 
                                size = 4
                            case 2: 
                                size = 8
                            default: 
                                break
                        }
                    }
                }
                
                HStack(alignment: .center) {
                    Text("\(size)")
                        .font(.caption)
                        .padding(.leading, 8)
                    
                    Slider(value: Binding(
                        get: {
                            let maxVal = passwordGenTab == 0 ? 100.0 : 32.0
                            return Double(size) / maxVal
                        },
                        set: { newPercent in
                            let maxVal = passwordGenTab == 0 ? 100.0 : 32.0
                            size = Int(newPercent * maxVal)
                        }
                    ), in: 0...1)
                    .padding(.trailing, 2)
                    .animation(.easeInOut(duration: 1), value: passwordGenTab)
                    
                    Button {
                        data.value = SidePanel.instance.generatePassword(passwordType: passwordGenTab, numbers: numbers, symbols: symbols, caps: caps, size: size)
                    } label: {
                        Image(systemName: "escape")
                            .padding(6)
                    }
                    .buttonStyle(BorderlessButtonStyle())
                    .glassEffect(in: Circle())
                    .padding(.trailing, 8)
                }
                .padding(.bottom, passwordGenTab == 2 ? 8 : 0)
                
                HStack {
                    if (passwordGenTab == 0) {
                        Toggle("Numbers", isOn: $numbers)
                            .transition(.opacity.combined(with: .move(edge: .leading)))
                        Toggle("Symbols", isOn: $symbols)
                            .transition(.opacity.combined(with: .move(edge: .leading)))
                    }
                    
                    if (passwordGenTab == 0 || passwordGenTab == 1) {
                        Toggle("Caps", isOn: $caps)
                            .transition(.opacity.combined(with: .move(edge: .leading)))
                    }
                }
                .padding(.leading, 8)
                .padding(.trailing, 8)
                .animation(.easeInOut(duration: 0.25), value: passwordGenTab)
            }
            
            VStack(alignment: .leading) {
                Text(data.title)
                    .font(.caption)
                    .foregroundColor(Color.gray)
                    .padding(.bottom, -6)
                
                Divider()
                
                HStack {
                    if (editable) {
                        if (data.type == GenericItemType.website) {
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
                                    websiteBinding.wrappedValue = val
                                } label: {
                                    Label("Add website", systemImage: "plus.circle")
                                        .font(.caption)
                                        .frame(maxWidth: .infinity, alignment: .center)
                                }
                            }
                        } else if (data.type == GenericItemType.date) {
                            DatePicker(
                                "",
                                selection: dateBinding,
                                displayedComponents: [.date]
                            )
                            .datePickerStyle(.compact)
                            .labelsHidden()
                        } else if (data.type == .ml_generic || data.type == .ml_password) {
                            TextEditor(text: Binding(get: { data.f_value() }, set: { data.value = $0 }))
                                .frame(minHeight: 100)
                                .scrollContentBackground(.hidden)
                        } else {
                            TextField("Value", text: Binding(get: { data.f_value() }, set: { data.value = $0 }), axis: .vertical)
                                .lineLimit(6)
                                .padding(-4)
                        }
                    } else {
                        if (data.type == GenericItemType.password || data.type == GenericItemType.ml_password) {
                            Text(verbatim: revealed ? data.f_value() : String(repeating: "•", count: data.f_value().count))
                                .font(.system(.body, design: .monospaced))
                                .privacySensitive()
                                .lineLimit(revealed ? 10 : 1)
                            
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
                            Text(verbatim: totpValue.isEmpty ? data.f_value() : totpValue)
                            
                            Spacer()
                            
                            /*
                             * Since I wanted to have a UI and UI Bridge, I decided to use a totp
                             * callback which gets called everytime the totp needs to be refreshed.
                             */
                            if (data.cb_getTOTP != nil && totpMax > 0 && !data.value.isEmpty && !totpValue.isEmpty) {
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
                            Text(verbatim: data.f_value())
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
                    .fill(AnyShapeStyle(Material.ultraThinMaterial))
                    .stroke(Color.gray.opacity(data.isMultiline() ? 0.5 : 0.3), lineWidth: 0.5)
            }
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            .clipped()
            .contentShape(Rectangle())
            .onTapGesture {
                /*
                 * TODO: X1FD - Use Clipboard Swift Bridge to copy the value
                 */
                Clipboard.instance.copy(data.value)
                ToastStore.instance.toasts.append(Toast(message: "Copied to clipboard", icon: "document.on.document").setColor(color: Color.clear))
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
        .padding(.top, data.type == GenericItemType.password && editable ? 8 : 0)
        .background {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(lineWidth: 0)
                .fill(AnyShapeStyle(Material.ultraThinMaterial))
                .stroke(Color.gray.opacity(data.isMultiline() ? 0.5 : 0.3), lineWidth: 0.5)
                .overlay(Color.black.opacity(0.15))
        }
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .clipped()
        .contentShape(Rectangle())
    }
}

#Preview {
    PreviewData().test1()
}
