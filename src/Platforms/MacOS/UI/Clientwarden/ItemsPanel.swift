import SwiftUI

@objcMembers
@Observable
final class ItemsPanel: NSObject {
    static let instance = ItemsPanel()

    public var elements: [ItemElement] = []
    public var filteredElements: [ItemElement] = []
    public var searchQuery: String = ""
    public var refreshNum: Int = 0
    public var selectedItems: [UUID] = []

    @objc public var cb_query: ((String) -> [ItemElement])?
    @objc public var cb_new: ((ItemType) -> ItemElement)?

    func update(data: [ItemElement]) {
        elements = data
        filteredElements = data
        searchQuery = ""
        selectedItems = []
    }

    func refresh(data: [ItemElement]) {
        refreshItems()
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
    
    func refreshItems() {
        self.refreshNum += 1
    }

    func newItem(itemType: ItemType) {
        if let res = cb_new?(itemType) {
            if (res != nil) {
                elements.append(res)
                query()
                SidePanel.instance.viewItem(cb_uuid: res.uuid)
                SidePanel.instance.editable = true
            }
        } else {
            ToastStore.instance.toasts.append(Toast(message: "No callback set for New Item"))
        }
    }
}

struct ItemsPanelView: View {
    @State private var refreshToken: Int = 0
    @Bindable var data: ItemsPanel = ItemsPanel.instance
    @FocusState private var isFocused: Bool
    @State private var showNewItemCallout: Bool = false
    @FocusState private var focused: Bool

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
            
            VStack {
                if (data.searchQuery != "" && data.filteredElements.isEmpty) {
                    Spacer()
                    ContentUnavailableView(
                        "No Items Found",
                        systemImage: "magnifyingglass",
                        description: Text("Couldn't find any items!")
                    )
                    .frame(width: .infinity, height: .infinity)
                    Spacer()
                } else if (data.searchQuery == "" && data.filteredElements.isEmpty) {
                    Spacer()
                    ContentUnavailableView(
                        "No Items",
                        systemImage: "tray",
                        description: Text("Create some items!")
                    )
                    Spacer()
                } else {
                    ScrollView {
                        VStack {
                            ForEach(data.filteredElements) { item in
                                ItemElementView(data: item, selected: (SidePanel.instance.viewable && SidePanel.instance.uuid == item.uuid) || data.selectedItems.contains(item.uuid)
                                )
                                .highPriorityGesture(
                                    TapGesture().onEnded {
                                        if (NSEvent.modifierFlags.contains(.shift)) {
                                            if (data.selectedItems.contains(item.uuid)) {
                                                data.selectedItems.removeAll {
                                                    $0 == item.uuid
                                                }
                                            } else {
                                                data.selectedItems.append(item.uuid)
                                            }
                                            if (SidePanel.instance.viewable) {
                                                data.selectedItems.append(SidePanel.instance.uuid)
                                            }
                                            SidePanel.instance.editable = false
                                            SidePanel.instance.viewable = false
                                        } else {
                                            withAnimation(.easeInOut(duration: 0.25)) {
                                                SidePanel.instance.viewItem(cb_uuid: item.uuid)
                                                data.selectedItems.removeAll()
                                            }
                                        }
                                    }
                                )
                                .draggable(
                                    /*
                                     * Had to compress this into a small block
                                     * bc other wise it wouldn't fit into XCode
                                     * btw this is the doc:
                                     * https://developer.apple.com/documentation/swiftui/adopting-drag-and-drop-using-swiftui
                                     */
                                    DragableItemElement(
                                        uuids: !data.selectedItems.isEmpty
                                        && data.selectedItems.contains(item.uuid)
                                        ? data.selectedItems : [item.uuid]
                                    )
                                ) {
                                    Image(systemName: "square.text.square.fill")
                                        .font(.system(size: 24))
                                        .frame(width: 32, height: 32)
                                        .overlay(alignment: .topTrailing) {
                                            if ((!data.selectedItems.isEmpty && data.selectedItems.contains(item.uuid) ? data.selectedItems : [item.uuid]).count > 0) {
                                                Text("\((!data.selectedItems.isEmpty && data.selectedItems.contains(item.uuid) ? data.selectedItems : [item.uuid]).count)")
                                                    .font(.system(size: 10, weight: .bold))
                                                    .foregroundStyle(.white)
                                                    .padding(4)
                                                    .background(Circle().fill(.blue))
                                                    .frame(minWidth: 32, minHeight: 32)
                                                    .offset(x: 6, y: 6)
                                            }
                                        }
                                }
                            }
                        }
                        .padding(12)
                    }
                    .scrollIndicators(.never)
                }
            }
            .background {
                RoundedRectangle(cornerRadius: 0, style: .continuous)
                    .stroke(lineWidth: 0)
                    .glassEffect(.regular.interactive(), in: .rect(cornerRadius: 0))
            }
            .padding(.bottom, -9)
            .padding(.leading, -1)
            .padding(.trailing, -1)
            .padding(.top, -8)

            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .animation(.spring(response: 0.4, dampingFraction: 0.8), value: data.elements)
        .focusable()
        .focusEffectDisabled()
        .focused($focused)
        .onAppear {
            #if NON_XCODE_BUILD
                ItemsPanelBridge.setupCallbacks()
            #endif
            DispatchQueue.main.async {
                focused = true
            }
        }
        .task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                if (!Task.isCancelled) {
                    NavigationPanel.instance.loadCurrentTab(refresh: true)
                }
            }
        }
        .onChange(of: data.refreshNum) { _, newVal in
            refreshToken = newVal
        }
        .onKeyPress(.escape) {
            if (data.selectedItems.isEmpty) {
                SidePanel.instance.viewable = false
                SidePanel.instance.editable = false
            } else {
                data.selectedItems.removeAll()
            }
            return .ignored
        }
    }
}
#Preview {
    PreviewData().test1()
}
