#import "UIFeaturesBridge.h"
#import <Cocoa/Cocoa.h>
#import "clientwarden-Swift.h"
#include "Vault.h"

@implementation UIFeaturesBridge

/*
 * Setup Callbacks will be called inside of the swift class
 * onAppear. Setup Callbacks will setup all the necessary
 * callbacks for that class.
 */
+ (void)setupCallbacks {
    [self cb_checkAbove26_8_1];
}

/*
 * Query takes in a string and passes back an array of ItemElement
 * with all the items that match the search query
 */
+ (void)cb_checkAbove26_8_1 {
    UIFeatures.instance.cb_checkAbove26_8_1 = ^BOOL() {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            return (BOOL)v_inst.features.checkAbove26_8_1();
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to check above 26.8.1"];
                [[ToastStore instance] addToast:toast];
            });

            return NO;
        }
    };
}

@end