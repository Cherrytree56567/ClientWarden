import SwiftUI

/*
 * This struct is AI, but the rest shouldn't dw
 */
struct Shake: GeometryEffect {
    var amount: CGFloat = 8
    var shakesPerUnit: CGFloat = 3
    var animatableData: CGFloat

    func effectValue(size: CGSize) -> ProjectionTransform {
        ProjectionTransform(CGAffineTransform(
            translationX: amount * sin(animatableData * .pi * shakesPerUnit),
            y: 0
        ))
    }
}

/*
 * I had no idea how to make this WindowConfigurator thing
 * so I had to ask claude. dw, it doesnt break anything, and
 * I have verified it.
 */
struct WindowConfigurator: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView {
        let view = NSVisualEffectView()
        view.wantsLayer = true
        view.layer?.backgroundColor = .clear
        DispatchQueue.main.async {
            guard let window = view.window else { return }
            window.standardWindowButton(.closeButton)?.isHidden = true
            window.standardWindowButton(.miniaturizeButton)?.isHidden = true
            window.standardWindowButton(.zoomButton)?.isHidden = true
            window.titlebarAppearsTransparent = true
            window.titleVisibility = .hidden
            window.styleMask = [.borderless]
            window.isMovableByWindowBackground = true
            window.backgroundColor = .clear
            window.isOpaque = false
            window.hasShadow = true
            window.level = .floating
            window.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
            
            if let contentView = window.contentView {
                contentView.wantsLayer = true
                contentView.layer?.backgroundColor = .clear
                contentView.layer?.isOpaque = false
            }
        }
        return view
    }
    
    func updateNSView(_ nsView: NSView, context: Context) {}
}

struct AutofillUnlockView: View {
    @Environment(\.dismissWindow) private var dismissWindow
    @State private var shakeAmount: CGFloat = 0
    
    var body: some View {
        VStack(alignment: .leading) {
            Image(systemName: "lock.square.dashed")
                .font(.system(size: 48))
            
            Text("Clientwarden")
                .padding(.top, 12)
                .padding(.leading, 4)
                .font(Font.headline)
            
            Text("Clientwarden needs you to unlock your Vault to use Autofill.")
                .padding(.top, 4)
                .padding(.leading, 4)
                .font(.callout)
            
            Text("Unlock your vault to continue.")
                .padding(.top, 4)
                .padding(.leading, 4)
                .font(.callout)
            
            Spacer()
            
            SecureField("Password",
                text: Binding(
                    get: { Unlock.instance.password },
                    set: { Unlock.instance.password = $0 }
                ))
                .font(.subheadline)
                .padding(6)
                .textFieldStyle(.plain)
                .glassEffect(.regular.interactive(), in: .rect(cornerRadius: 16))
            
            HStack(alignment: .center) {
                if (SettingsPanel.instance.getBioUnlock()) {
                    Button {
                        Unlock.instance.unlockBio { result in
                            if (result) {
                                dismissWindow(id: "autofillUnlock")
                            }
                        }
                    } label: {
                        Image(systemName: "faceid")
                            .font(.subheadline)
                            .symbolRenderingMode(.monochrome)
                            .padding(2)
                    }
                    .buttonStyle(.glass)
                    .buttonBorderShape(.circle)
                }
                
                Button {
                    withAnimation {
                        dismissWindow(id: "autofillUnlock")
                    }
                } label: {
                    Text(verbatim: "Cancel")
                        .font(.subheadline)
                        .frame(maxWidth: .infinity)
                        .padding(2)
                }
                .buttonStyle(.glass)
                .buttonBorderShape(.capsule)
                
                Button {
                    withAnimation {
                        Unlock.instance.unlock { result in
                            if (result) {
                                dismissWindow(id: "autofillUnlock")
                            }
                        }
                    }
                } label: {
                    Text(verbatim: "Unlock")
                        .font(.subheadline)
                        .frame(maxWidth: .infinity)
                        .padding(2)
                }
                .buttonStyle(.glassProminent)
                .buttonBorderShape(.capsule)
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(.top, 16)
        .padding(.leading, 16)
        .padding(.trailing, 16)
        .padding(.bottom, 16)
        .frame(minWidth: 250, maxWidth: 250, minHeight: 275, maxHeight: 275, alignment: .topLeading)
        .focusEffectDisabled()
        .background(
            WindowConfigurator()
                .glassEffect(.regular, in: .rect(cornerRadius: 20))
        )
        .clipShape(RoundedRectangle(cornerRadius: 20))
        .modifier(Shake(amount: 32, animatableData: shakeAmount))
        .padding(.leading, 20 * 2)
        .padding(.trailing, 20 * 2)
        .onAppear {
            #if NON_XCODE_BUILD
                UnlockBridge.setupCallbacks()
            #endif
        }
        .onChange(of: ToastStore.instance.toasts) {
            withAnimation(.easeInOut(duration: 0.4)) {
                shakeAmount += 1
            }
        }
    }
}

#Preview {
    AutofillUnlockView()
}
