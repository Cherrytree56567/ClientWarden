import SwiftUI

@objc
enum ImageType : Int {
    case bundle
    case appSupport
    case systemImage
}

@objcMembers
class ClientwardenImage: NSObject {
    @objc public let type: ImageType
    @objc public let path: String
    
    init(type: ImageType, path: String) {
        self.type = type
        self.path = path
    }
    
    func getImage() -> Image? {
        switch type {
            case .bundle:
                guard NSImage(named: NSImage.Name(path)) != nil else {
                    return nil
                }
                return Image(path)
            case .appSupport:
                guard let nsImage = NSImage(contentsOfFile: path) else {
                    return nil
                }
                return Image(nsImage: nsImage)
            case .systemImage:
                return Image(systemName: path)
        }
    }
    
    private static var appSupportPath: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    }
}
