#import "ActivityMonitorBridge.h"
#import <Cocoa/Cocoa.h>
#include <thread>
#import "clientwarden-Swift.h"
#include "Vault.h"
#include "CBridge.h"

@implementation ActivityMonitorBridge

+ (void)setupCallbacks {
    [self cb_setLastInactivity];
}

+ (void)cb_setLastInactivity {
    ActivityMonitor.instance.cb_setLastInactivity = ^BOOL(NSDate * _Nonnull date) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            v_inst.inactivityTimer = (time_t)[date timeIntervalSince1970];

            return YES;
        } catch (...) {
            return NO;
        }
    };
}

@end