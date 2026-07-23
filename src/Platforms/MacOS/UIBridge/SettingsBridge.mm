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
    SettingsPanel.instance.cb_logout = ^bool() {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
            
            return v_inst.Logout();
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to log out"];
                [[ToastStore instance] addToast:toast];
            });
            
            return false;
        }
    };
}

+ (void)cb_getScrshot {
    SettingsPanel.instance.cb_getScrshot = ^bool() {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
            
            return v_inst.GetScreenshotOption();
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to log out"];
                [[ToastStore instance] addToast:toast];
            });
            
            return false;
        }
    };
}
+ (void)cb_setScrshot {
    SettingsPanel.instance.cb_setScrshot = ^bool(bool value) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
            
            v_inst.SetScreenshotOption(value);

            return true;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to log out"];
                [[ToastStore instance] addToast:toast];
            });
            
            return false;
        }
    };
}

@end