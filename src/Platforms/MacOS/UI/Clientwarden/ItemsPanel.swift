import SwiftUI

@objcMembers
@Observable
final class ItemsPanel: NSObject {
    static let instance = ItemsPanel()

    public var elements: [ItemElement] = []
    public var filteredElements: [ItemElement] = []
    public var searchQuery: String = ""

    @objc public var cb_query: ((String) -> [ItemElement])?
    @objc public var cb_new: ((ItemType) -> ItemElement)?

    func update(data: [ItemElement]) {
        elements = data
        filteredElements = data
        searchQuery = ""
    }

    func refresh(data: [ItemElement]) {
        elements = data
        query()
    }

    func query() {
        if (searchQuery.isEmpty) {
            filteredElements = elements
        } else if let results = cb_query?(searchQuery) {
            filteredElements = results
        } else {
            ToastStore.instance.toasts.append(Toast(message: "No callback set for query"))
        }
    }

    func newItem(itemType: ItemType) {
        if let res = cb_new?(itemType) {
            if (res != nil) {
                elements.append(res)
                query()
                SidePanel.instance.viewItem(cb_uuid: res.uuid)
            }
        } else {
            ToastStore.instance.toasts.append(Toast(message: "No callback set for New Item"))
        }
    }
}
struct ItemsPanelView: View {
    @Bindable var data: ItemsPanel = ItemsPanel.instance
    @FocusState private var isFocused: Bool
    @State private var showNewItemCallout: Bool = false

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
                    showNewItemCallout = true
                } label: {
                    Image(systemName: "plus")
                        .font(.subheadline)
                        .padding(8)
                        .frame(width: 32, height: 32)
                        .contentShape(.circle)
                }
                .buttonStyle(.plain)
                .glassEffect(.regular.interactive(), in: Circle())
                .popover(isPresented: $showNewItemCallout, arrowEdge: .leading) {
                    Menu {
                        Button("Login") {
                            data.newItem(itemType: ItemType.Login)
                            showNewItemCallout = false
                        }
                        Button("Card") {
                            data.newItem(itemType: ItemType.Card)
                            showNewItemCallout = false
                        }
                        Button("Identity") {
                            data.newItem(itemType: ItemType.Identity)
                            showNewItemCallout = false
                        }
                        Button("Note") {
                            data.newItem(itemType: ItemType.Note)
                            showNewItemCallout = false
                        }
                        Button("SSH Key") {
                            data.newItem(itemType: ItemType.SSHKey)
                            showNewItemCallout = false
                        }
                    } label: {
                        Label("Add Item", systemImage: "plus.circle")
                    }
                    .menuStyle(.borderlessButton)
                    .padding(.top, 5)
                    .padding(.bottom, 5)
                }
            }
            .padding(8)
            .padding(.bottom, -8)
            GeometryReader { geo in
                ScrollView {
                    if (data.searchQuery != "" && data.filteredElements.isEmpty) {
                        Spacer()
                        ContentUnavailableView(
                            "No Items Found",
                            systemImage: "magnifyingglass",
                            description: Text("Couldn't find any items!")
                        )
                        .frame(minWidth: geo.size.width, minHeight: geo.size.height)
                    } else if (data.searchQuery == "" && data.filteredElements.isEmpty) {
                        Spacer()
                        ContentUnavailableView(
                            "No Items",
                            systemImage: "tray",
                            description: Text("Create some items!")
                        )
                        .frame(minWidth: geo.size.width, minHeight: geo.size.height)
                    } else {
                        VStack {
                            ForEach(data.filteredElements) { item in
                                ItemElementView(data: item)
                            }
                        }
                        .padding(12)
                    }
                }
                .scrollIndicators(.never)
                .background {
                    RoundedRectangle(cornerRadius: 0, style: .continuous)
                        .stroke(lineWidth: 0)
                        .glassEffect(.regular.interactive(), in: .rect(cornerRadius: 0))
                }
                .padding(.bottom, -9)
                .padding(.leading, -1)
                .padding(.trailing, -1)
            }

            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .animation(.spring(response: 0.4, dampingFraction: 0.8), value: data.elements)
        .onAppear {
            ItemsPanelBridge.setupCallbacks()
        }
        .task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                if (!Task.isCancelled) {
                    NavigationPanel.instance.loadCurrentTab(refresh: true)
                }
            }
        }
    }
}
#Preview {
    PreviewData().test1()
}
