#include "ClipboardBridge.h"
#include "Clipboard.h"

@implementation CWClipboard {
    ClientWarden::Clipboard _clipboard;
}

- (void)copy:(NSString *)str {
    std::string s_str = std::string([str UTF8String]);
    _clipboard.Copy(s_str);
    if (!s_str.empty()) {
        void* p_str = const_cast<char*>(s_str.data());
        OPENSSL_cleanse(p_str, s_str.size());
    }
}

- (NSString *)paste {
    std::string s_str;
    _clipboard.Paste(s_str);
    return [NSString stringWithUTF8String:s_str.c_str()];
}

- (void)setDelay:(NSInteger)delay {
    _clipboard.SetDelay(static_cast<int>(delay));
}

@end