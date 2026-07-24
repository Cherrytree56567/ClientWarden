import Foundation

@objcMembers
class Folder: NSObject, Identifiable {
    public var id: UUID { uuid }
    @objc public var uuid: UUID
    @objc public var name: String

    init(uuid: UUID, name: String) {
        self.uuid = uuid
        self.name = name
        super.init()
    }
}

@objc
enum ItemType: Int {
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

enum LoginLinkedIDs : Int, CaseIterable {
    case Username = 100
    case Password = 101
    
    var description: String {
        switch self {
            case .Username: return "Username"
            case .Password: return "Password"
        }
    }
}

enum CardLinkedIDs : Int, CaseIterable {
    case CardholderName = 300
    case ExpMonth = 301
    case ExpYear = 302
    case Code = 303
    case Brand = 304
    case Number = 305
    
    var description: String {
        switch self {
            case .CardholderName: return "Cardholder Name"
            case .ExpMonth: return "Expiration Month"
            case .ExpYear: return "Expiration Year"
            case .Code: return "Code"
            case .Brand: return "Brand"
            case .Number: return "Number"
        }
    }
}

enum IdentityLinkedIDs : Int, CaseIterable {
    case Title = 400
    case MiddleName = 401
    case Address1 = 402
    case Address2 = 403
    case Address3 = 404
    case City = 405
    case State = 406
    case PostalCode = 407
    case Country = 408
    case Company = 409
    case Email = 410
    case Phone = 411
    case SSN = 412
    case Username = 413
    case PassportNumber = 414
    case LicenseNumber = 415
    case FirstName = 416
    case LastName = 417
    case FullName = 418
    
    var description: String {
        switch self {
            case .Title: return "Title"
            case .MiddleName: return "Middle Name"
            case .Address1: return "Address 1"
            case .Address2: return "Address 2"
            case .Address3: return "Address 3"
            case .City: return "City"
            case .State: return "State"
            case .PostalCode: return "Postal Code"
            case .Country: return "Country"
            case .Company: return "Company"
            case .Email: return "Email"
            case .Phone: return "Phone"
            case .SSN: return "Social Security Number"
            case .Username: return "Username"
            case .PassportNumber: return "Passport Number"
            case .LicenseNumber: return "License Number"
            case .FirstName: return "First Name"
            case .LastName: return "Last Name"
            case .FullName: return "Full Name"
        }
    }
}

extension UUID {
    static let empty = UUID(uuidString: "00000000-0000-0000-0000-000000000000")!
}
