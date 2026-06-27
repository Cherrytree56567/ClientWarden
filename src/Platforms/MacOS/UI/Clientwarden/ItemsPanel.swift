import SwiftUI

@Observable
final class ItemsPanel {
    static let instance = ItemsPanel()

    public var elements: [ItemElement] = []
    public var filteredElements: [ItemElement] = []
    public var searchQuery: String = ""

    public var cb_query: ((String) -> [ItemElement])?
    public var cb_new: (() -> Bool)?

    func update(data: [ItemElement]) {
        elements = data
        filteredElements = data
        searchQuery = ""
    }

    func query() {
        if let results = cb_query?(searchQuery) {
            filteredElements = results
        } else {
            g_toastStore.toasts.append(Toast(message: "No callback set for query"))
        }
    }

    func newItem() {
        if let res = cb_new?() {
            if (res) {

            } else {
                g_toastStore.toasts.append(Toast(message: "No callback create Item"))
            }
        } else {
            g_toastStore.toasts.append(Toast(message: "No callback set for New Item"))
        }
    }
}
struct ItemsPanelView: View {
    @Bindable var data: ItemsPanel = ItemsPanel.instance
    @FocusState private var isFocused: Bool

    var body: some View {
        VStack() {
            HStack {
                TextField("Search", text: $data.searchQuery)
                    .textFieldStyle(.plain)
                    .padding(8)
                    .glassEffect(.regular.interactive())
                    .focused($isFocused)
                    .onChange(of: data.searchQuery) { _,_ in
                        data.query()
                    }
                    .onExitCommand {
                        isFocused = false
                    }
                Button {
                    data.newItem()
                } label: {
                    Image(systemName: "plus")
                        .font(.subheadline)
                        .padding(8)
                        .frame(width: 32, height: 32)
                        .contentShape(.circle)
                }
                .buttonStyle(.plain)
                .glassEffect(.regular.interactive(), in: Circle())
            }
            if (data.searchQuery != "" && data.filteredElements.isEmpty) {
                ContentUnavailableView(
                    "No Items Found",
                    systemImage: "magnifyingglass",
                    description: Text("Couldn't find any items!")
                )
            } else if (data.searchQuery == "" && data.filteredElements.isEmpty) {
                ContentUnavailableView(
                    "No Items",
                    systemImage: "tray",
                    description: Text("Create some items!")
                )
            } else {
                ScrollView {
                    ForEach(data.filteredElements) { item in
                        ItemElementView(data: item)
                    }
                }
                .scrollIndicators(.never)
            }

            Spacer()
        }
        .frame(maxWidth: .infinity)
        .padding(8)
        .animation(.spring(response: 0.4, dampingFraction: 0.8), value: data.elements)
    }
}
#Preview {
    PreviewData().test1()
}
