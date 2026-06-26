import SwiftUI

enum ImageType {
    case bundle
    case appSupport
}

class ClientwardenImage {
    public let type: ImageType
    public let path: String
    
    init(type: ImageType, path: String) {
        self.type = type
        self.path = path
    }
    
    func getImage() -> Image? {
        switch type {
            case .bundle:
                guard NSImage(named: path) != nil else {
                    return nil
                }
                return Image(path)
            case .appSupport:
                let imagePath = Self.appSupportPath.appendingPathComponent(path)
                guard let nsImage = NSImage(contentsOfFile: imagePath.path) else {
                    return nil
                }
                return Image(nsImage: nsImage)
        }
    }
    
    private static var appSupportPath: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    }
}
