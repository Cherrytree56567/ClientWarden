#include "ClipboardBridge.h"
#include "Clipboard.h"
#include "Vault.h"

@implementation CWClipboard

- (void)copy:(NSString *)str {
    ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
    std::string s_str = std::string([str UTF8String]);
    v_inst.clipboard.Copy(s_str);
    if (!s_str.empty()) {
        void* p_str = const_cast<char*>(s_str.data());
        OPENSSL_cleanse(p_str, s_str.size());
    }
}

- (NSString *)paste {
    ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
    std::string s_str;
    v_inst.clipboard.Paste(s_str);
    return [NSString stringWithUTF8String:s_str.c_str()];
}

- (void)setDelay:(NSInteger)delay {
    ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
    v_inst.clipboard.SetDelay(static_cast<int>(delay));
}
- (NSInteger)getDelay {
    ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
    return v_inst.clipboard.GetDelay();
}

@end