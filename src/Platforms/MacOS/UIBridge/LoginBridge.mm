#import "LoginBridge.h"
#import <Cocoa/Cocoa.h>
#import "clientwarden-Swift.h"
#include "Vault.h"

@implementation LoginBridge

/*
 * Setup Callbacks will be called inside of the swift class
 * onAppear. Setup Callbacks will setup all the necessary
 * callbacks for that class.
 */
+ (void)setupCallbacks {
    [self cb_login];
    [self cb_submitCode];
}

/*
 * Login takes in an email and password as well as a
 * vault, main, api, wss and icon URL and sets the URI
 * in the vault and sets up the vault for the new user.
 */
+ (void)cb_login {
    Login.instance.cb_login = ^bool(NSString* email, NSString* password, NSString* vaultURL, NSString* mainURL, 
                                                NSString* apiURL, NSString* wssURL, NSString* iconURL) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            v_inst.SetUris(vaultURL.UTF8String, mainURL.UTF8String, apiURL.UTF8String, iconURL.UTF8String, wssURL.UTF8String);

            std::string c_email = email.UTF8String;
            std::string c_password = password.UTF8String;

            ClientWarden::AuthState result = v_inst.Login(c_email, c_password);

            if (result == ClientWarden::AuthState::NeedsTOTP) {
                v_inst.codeType = ClientWarden::AuthState::NeedsTOTP;
                dispatch_async(dispatch_get_main_queue(), ^{
                    Login.instance.EmailPasswordView = false;
                });
                return true;
            } else if (result == ClientWarden::AuthState::NeedsEmailVerification) {
                v_inst.codeType = ClientWarden::AuthState::NeedsEmailVerification;
                dispatch_async(dispatch_get_main_queue(), ^{
                    Login.instance.EmailPasswordView = false;
                });
                return true;
            } else if (result != ClientWarden::AuthState::Authenticated) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    Toast* toast = [[Toast alloc] initWithMessage:@"Wrong Email or Password"];
                    [[ToastStore instance] addToast:toast];
                });
                return false;
            }

            if (v_inst.postLogin() != ClientWarden::NetworkState::Success) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    Toast* toast = [[Toast alloc] initWithMessage:@"Post Login Failed"];
                    [[ToastStore instance] addToast:toast];
                });
                return false;
            }

            v_inst.startRefreshThread();
            v_inst.startWSSLoop();
            v_inst.Sync();

            dispatch_async(dispatch_get_main_queue(), ^{
                ClientwardenWindow.instance.state = WindowStateVault;
            });

            return true;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast *toast = [[Toast alloc] initWithMessage:@"Login failed to Authenticate"];
                [[ToastStore instance] addToast:toast];
            });

            return false;
        }
    };
}

/*
 * SubmitCode is used when BitWarden requests a TOTP
 * code or a Device Verification code.
 */
+ (void)cb_submitCode {
    Login.instance.cb_submitCode = ^bool(NSString* code) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
            ClientWarden::AuthState result;

            std::string c_code = code.UTF8String;

            if (v_inst.codeType == ClientWarden::AuthState::NeedsEmailVerification) {
                result = v_inst.submitDeviceVerify(c_code);
            } else if (v_inst.codeType == ClientWarden::AuthState::NeedsTOTP) {
                result = v_inst.submitTOTP(c_code);
            } else {
                dispatch_async(dispatch_get_main_queue(), ^{
                    Login.instance.EmailPasswordView = true;
                });
                Toast* toast = [[Toast alloc] initWithMessage:@"Unknown code type"];
                [[ToastStore instance] addToast:toast];
                return false;
            }

            if (result != ClientWarden::AuthState::Authenticated) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    Login.instance.EmailPasswordView = true;
                });
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Authenticate"];
                [[ToastStore instance] addToast:toast];
                return false;
            }

            if (v_inst.postLogin() != ClientWarden::NetworkState::Success) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    Login.instance.EmailPasswordView = true;
                });
                Toast* toast = [[Toast alloc] initWithMessage:@"Post Login Failed"];
                [[ToastStore instance] addToast:toast];
                return false;
            }

            v_inst.startRefreshThread();
            v_inst.startWSSLoop();
            v_inst.Sync();

            dispatch_async(dispatch_get_main_queue(), ^{
                Login.instance.EmailPasswordView = true;
                ClientwardenWindow.instance.state = WindowStateVault;
            });

            return true;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to submit code"];
                [[ToastStore instance] addToast:toast];
            });
            return false;
        }
    };
}

@end