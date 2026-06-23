#pragma once
#include <openssl/crypto.h>
#include <string>
#include <thread>
#include <chrono>

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface CWClipboard : NSObject

- (void)copy:(NSString *)str;
- (NSString *)paste;
- (void)setDelay:(NSInteger)delay;

@end

NS_ASSUME_NONNULL_END

namespace ClientWarden {
    class Clipboard {
    public:
        Clipboard() {}

        void Copy(std::string& str);
        void Paste(std::string& str);

        void SetDelay(int delay) { secureDelayClear = delay; }
    private:
        int secureDelayClear = 30;
    };
}