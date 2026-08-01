#import "SettingsBridge.h"
#import <Cocoa/Cocoa.h>
#import "clientwarden-Swift.h"
#include "Vault.h"

@implementation SettingsBridge

/*
 * Setup Callbacks will be called inside of the swift class
 * onAppear. Setup Callbacks will setup all the necessary
 * callbacks for that class.
 */
+ (void)setupCallbacks {
    [self cb_logout];
    [self cb_getScrshot];
    [self cb_setScrshot];
}

/*
 * Logout removes the vault.json, data.json, settings.json and the cw.log files,
 * and sets the state to LogOut
 */
+ (void)cb_logout {
    SettingsPanel.instance.cb_logout = ^BOOL() {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
            
            return (BOOL)v_inst.Logout();
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to log out"];
                [[ToastStore instance] addToast:toast];
            });
            
            return NO;
        }
    };
}

+ (void)cb_getScrshot {
    SettingsPanel.instance.cb_getScrshot = ^BOOL() {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
            
            return (BOOL)v_inst.GetScreenshotOption();
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to log out"];
                [[ToastStore instance] addToast:toast];
            });
            
            return NO;
        }
    };
}
+ (void)cb_setScrshot {
    SettingsPanel.instance.cb_setScrshot = ^BOOL(BOOL value) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
            
            v_inst.SetScreenshotOption((bool)value);

            return YES;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to log out"];
                [[ToastStore instance] addToast:toast];
            });
            
            return NO;
        }
    };
}

@end