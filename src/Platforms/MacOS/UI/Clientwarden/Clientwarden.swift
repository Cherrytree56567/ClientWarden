import Foundation

struct Folder: Identifiable, Hashable {
    let id: UUID
    var name: String
    
    init(id: UUID, name: String) {
        self.id = id
        self.name = name
    }
}

enum ItemType {
    case Login
    case Card
    case Identity
    case Note
    case SSHKey
    
    var description: String {
        switch self {
            case .Login: return "Login"
            case .Card: return "Card"
            case .Identity: return "Identity"
            case .Note: return "Note"
            case .SSHKey: return "SSH Key"
        }
    }
}
