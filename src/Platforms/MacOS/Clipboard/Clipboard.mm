#include "Clipboard.h"

#import <Cocoa/Cocoa.h>

@implementation CWClipboard {
    ClientWarden::Clipboard _clipboard;
}

- (void)copy:(NSString *)str {
    std::string s_str = std::string([str UTF8String]);
    _clipboard.Copy(cppStr);
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

namespace ClientWarden {
    void Clipboard::Copy(std::string& str) {
        NSPasteboard* pasteboard = [NSPasteboard generalPasteboard];
        [pasteboard clearContents];
 
        NSString* nsStr = [NSString stringWithUTF8String:str.c_str()];

        NSArray* types = @[NSPasteboardTypeString, @"org.nspasteboard.ConcealedType"];
        [pasteboard declareTypes:types owner:nil];
        [pasteboard setString:nsStr forType:NSPasteboardTypeString];
        [pasteboard setString:@"" forType:@"org.nspasteboard.ConcealedType"];

        NSInteger targetedChangeCount = [pasteboard changeCount];
        int delay = secureDelayClear;

        std::thread([delay, targetedChangeCount]() {
            std::this_thread::sleep_for(std::chrono::seconds(delay));

            NSPasteboard* pb = [NSPasteboard generalPasteboard];
            if ([pb changeCount] == targetedChangeCount) {
                [pb clearContents];
            }
        }).detach();

        if (!str.empty()) {
            void* strPtr = const_cast<char*>(str.data());
            OPENSSL_cleanse(strPtr, str.size());
        }
    }

    void Clipboard::Paste(std::string& str) {
        NSPasteboard* pasteboard = [NSPasteboard generalPasteboard];
        NSString* nsStr = [pasteboard stringForType:NSPasteboardTypeString];
    
        if (nsStr != nil) {
            str = std::string([nsStr UTF8String]);
        } else {
            str = "";
        }
    }
}