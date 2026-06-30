#import "UnlockBridge.h"
#import <Cocoa/Cocoa.h>
#import "clientwarden-Swift.h"
#include "Vault.h"

@implementation UnlockBridge

+ (void)setupCallbacks {
    [self cb_getInfo];
    [self cb_unlock];
}

+ (void)cb_getInfo {
    Unlock.instance.cb_getInfo = ^bool {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

        std::string name = v_inst.GetName();
        NSString *n_name = [NSString stringWithUTF8String: name.c_str()];

        dispatch_async(dispatch_get_main_queue(), ^{
            Unlock.instance.username = n_name;
        });

        return true;
    };
}

+ (void)cb_unlock {
    Unlock.instance.cb_unlock = ^bool(NSString* password) {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

        std::string c_password = password.UTF8String;

        try {
            v_inst.Unlock(c_password);
        } catch (...) {
            return false;
        }

        v_inst.startRefreshThread();
        v_inst.startWSSLoop();
        v_inst.Sync();

        dispatch_async(dispatch_get_main_queue(), ^{
            ClientwardenWindow.instance.state = WindowStateVault;
        });

        return true;
    };
}

@end