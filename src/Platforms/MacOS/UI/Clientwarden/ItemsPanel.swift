import SwiftUI

struct ItemsPanel: View {
    @State private var elements: [ItemElement]
    @State private var appliedAnim: Set<UUID> = []
    @State private var done: Bool = false
    
    init(elements: [ItemElement]) {
        self.elements = elements
        self.appliedAnim = []
    }
    
    var body: some View {
        VStack() {
            /*
             * TODO: 0x01 - FIX Animation
             */
            ForEach(elements) { item in
                ItemElementView(data: item)
            }
            
            Spacer()
        }
        .frame(maxWidth: .infinity)
        .padding(8)
        .animation(.spring(response: 0.4, dampingFraction: 0.8), value: elements)
    }
}

#Preview {
    PreviewData().test1()
}
