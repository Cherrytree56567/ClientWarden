#import "CWAppBridge.h"
#import <Cocoa/Cocoa.h>
#import "clientwarden-Swift.h"
#include "Vault.h"

@implementation CWAppBridge

+ (void)setupCallbacks {
    [self cb_getState];
    [self cb_lock];
}

+ (void)cb_getState {
    ClientwardenWindow.instance.cb_getState = ^WindowState {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
        if (!v_inst.hasStoredSession()) {
            return WindowStateLogin;
        } else {
            return WindowStateUnlock;
        }
    };
}

+ (void)cb_lock {
    ClientwardenWindow.instance.cb_lock = ^bool {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
        v_inst.Lock();
        return true;
    };
}

@end