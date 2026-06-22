import SwiftUI
import SwiftUIColor

struct Toast: Identifiable, Equatable {
    let id: UUID = UUID()
    let message: String
    var icon: String = "exclamationmark.warninglight"
}

struct ToastView: View {
    @State public var toast: Toast
    var body: some View {
        VStack {
            HStack {
                Image(systemName: toast.icon)
                    .imageScale(.medium)
                Text(toast.message)
                    .font(.caption)
            }
            .padding(8)
            .background(.orange.opacity(0.2), in: RoundedRectangle(cornerRadius: 8))
            .shadow(radius: 6)
        }
        .background(Color(.windowBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
    }
}

struct ToastModifier: ViewModifier {
    @Binding var toasts: [Toast]
    
    init(toasts: Binding<[Toast]>) {
        self._toasts = toasts
    }
    
    func body(content: Content) -> some View {
        content.overlay(alignment: .topTrailing) {
            VStack(alignment: .trailing, spacing: 8) {
                ForEach(toasts.prefix(3)) { toast in
                    ToastView(toast: toast)
                        .transition(.move(edge: .trailing).combined(with: .opacity))
                        .onAppear {
                            DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) {
                                withAnimation {
                                    toasts.removeAll { $0.id == toast.id }
                                }
                            }
                        }
                }
            }
            .padding(.top, 16)
            .padding(.trailing, 16)
            .animation(.spring(duration: 0.3), value: toasts)
        }
    }
}

extension View {
    func toast(_ toasts: Binding<[Toast]>) -> some View {
        modifier(ToastModifier(toasts: toasts))
    }
}

#Preview {
    ToastView(toast: Toast(message: "TestMSG"))
}

