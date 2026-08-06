import SwiftUI

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
            
            HStack {
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
                        Unlock.instance.unlock()
                        dismissWindow(id: "autofillUnlock")
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
            .glassEffect(.regular, in: .rect(cornerRadius: 20)))
        .clipShape(RoundedRectangle(cornerRadius: 20))
        .onAppear {
            #if NON_XCODE_BUILD
                UnlockBridge.setupCallbacks()
            #endif
        }
    }
}

#Preview {
    AutofillUnlockView()
}
