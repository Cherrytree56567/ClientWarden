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
    [self cb_usePasskey];
}

/*
 * Login takes in an email and password as well as a
 * vault, main, api, wss and icon URL and sets the URI
 * in the vault and sets up the vault for the new user.
 */
+ (void)cb_login {
    Login.instance.cb_login = ^BOOL(NSString* email, NSString* password, NSString* vaultURL, NSString* mainURL, 
                                                NSString* apiURL, NSString* wssURL, NSString* iconURL) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            v_inst.SetUris(vaultURL.UTF8String, mainURL.UTF8String, apiURL.UTF8String, iconURL.UTF8String, wssURL.UTF8String);

            std::string c_email = email.UTF8String;
            std::string c_password = password.UTF8String;

            bool result = v_inst.Login(c_email, c_password);

            if (!result) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    Toast* toast = [[Toast alloc] initWithMessage:@"Wrong Email or Password"];
                    [[ToastStore instance] addToast:toast];
                });
                return NO;
            }

            if (v_inst.state == ClientWarden::AuthState::WaitingForTOTP) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    Login.instance.ViewType = LoginViewTypeTOTP;
                    ClientwardenWindow.instance.state = WindowStateLogin;
                });
                return YES;
            } else if (v_inst.state == ClientWarden::AuthState::WaitingForDeviceVerif) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    Login.instance.ViewType = LoginViewTypeTOTP;
                    ClientwardenWindow.instance.state = WindowStateLogin;
                });
                return YES;
            } else if (v_inst.state == ClientWarden::AuthState::WaitingForPasskey) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    Login.instance.ViewType = LoginViewTypePasskey;
                    ClientwardenWindow.instance.state = WindowStateLogin;
                });
                return YES;
            }

            dispatch_async(dispatch_get_main_queue(), ^{
                ClientwardenWindow.instance.state = WindowStateVault;
            });

            return YES;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Login.instance.ViewType = LoginViewTypeLogin;
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Authenticate"];
                [[ToastStore instance] addToast:toast];
            });

            return NO;
        }
    };
}

/*
 * SubmitCode is used when BitWarden requests a TOTP
 * code or a Device Verification code.
 */
+ (void)cb_submitCode {
    Login.instance.cb_submitCode = ^BOOL(NSString* code) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::string c_code = code.UTF8String;
            bool result;

            if (v_inst.state == ClientWarden::AuthState::WaitingForDeviceVerif) {
                result = v_inst.Login(c_code);
            } else if (v_inst.state == ClientWarden::AuthState::WaitingForTOTP) {
                result = v_inst.Login(c_code);
            } else {
                dispatch_async(dispatch_get_main_queue(), ^{
                    Login.instance.ViewType = LoginViewTypeLogin;
                    Toast* toast = [[Toast alloc] initWithMessage:@"Unknown code type"];
                    [[ToastStore instance] addToast:toast];
                });
                return NO;
            }

            if (!result) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    Login.instance.ViewType = LoginViewTypeLogin;
                    Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Authenticate"];
                    [[ToastStore instance] addToast:toast];
                });
                return NO;
            }

            dispatch_async(dispatch_get_main_queue(), ^{
                Login.instance.ViewType = LoginViewTypeLogin;
                ClientwardenWindow.instance.state = WindowStateVault;
            });

            return YES;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to submit code"];
                [[ToastStore instance] addToast:toast];
            });
            return NO;
        }
    };
}

static LoginBridge* p_loginBridge = nil;

/*
 * usePasskey is used when BitWarden requests a Passkey
 * to be used to login.
 */
+ (void)cb_usePasskey {
    Login.instance.cb_usePasskey = ^BOOL() {
        try {
            p_loginBridge = [LoginBridge new];
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            keychain::Error e1;

            NSData* challenge = [NSData dataWithBytes:v_inst.passkeyChallenge.data() length:v_inst.passkeyChallenge.size()];
            NSString* rpID = [NSString stringWithUTF8String:keychain::getPassword(CWbundleID, "vaultURL", e1).c_str()];

            if (e1.type != keychain::ErrorType::NoError) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    Toast* toast = [[Toast alloc] initWithMessage:@"Failed to use KeyChain"];
                    [[ToastStore instance] addToast:toast];
                });
                return NO;
            }
            
            ASAuthorizationPlatformPublicKeyCredentialProvider* provider = 
                [[ASAuthorizationPlatformPublicKeyCredentialProvider alloc] initWithRelyingPartyIdentifier:rpID];

            ASAuthorizationPlatformPublicKeyCredentialAssertionRequest* request =
                [provider createCredentialAssertionRequestWithChallenge:challenge];

            ASAuthorizationController* controller = [[ASAuthorizationController alloc] initWithAuthorizationRequests:@[request]];
            controller.delegate = p_loginBridge;
            controller.presentationContextProvider = p_loginBridge;
            [controller performRequests];

            return YES;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to use passkey"];
                [[ToastStore instance] addToast:toast];
            });
            return NO;
        }
    };
}

#pragma mark - ASAuthorizationControllerDelegate

- (void)authorizationController:(ASAuthorizationController *)controller
    didCompleteWithAuthorization:(ASAuthorization *)authorization {
    ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

    ASAuthorizationPlatformPublicKeyCredentialAssertion* cred =
        (ASAuthorizationPlatformPublicKeyCredentialAssertion *)authorization.credential;

    NSData* credentialID = cred.credentialID;
    NSData* authData = cred.rawAuthenticatorData;
    NSData* clientData = cred.rawClientDataJSON;
    NSData* signature = cred.signature;
    
    std::string c_id = std::string((const char*)credentialID.bytes, credentialID.length);
    std::string c_authData = std::string((const char*)authData.bytes, authData.length);
    std::string c_clientData = std::string((const char*)clientData.bytes, clientData.length);
    std::string c_signature = std::string((const char*)signature.bytes, signature.length);

    bool result;

    if (v_inst.state == ClientWarden::AuthState::WaitingForPasskey) {
        result = v_inst.Login(c_id, c_authData, c_clientData, c_signature);
    } else {
        dispatch_async(dispatch_get_main_queue(), ^{
            Toast* toast = [[Toast alloc] initWithMessage:@"Failed to use passkey"];
            [[ToastStore instance] addToast:toast];
        });
        return;
    }

    if (!result) {
        dispatch_async(dispatch_get_main_queue(), ^{
            Toast* toast = [[Toast alloc] initWithMessage:@"Failed to use passkey"];
            [[ToastStore instance] addToast:toast];
        });
        return;
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        Login.instance.ViewType = LoginViewTypeLogin;
        ClientwardenWindow.instance.state = WindowStateVault;
    });
}

- (void)authorizationController:(ASAuthorizationController *)controller
            didCompleteWithError:(NSError *)error {
    dispatch_async(dispatch_get_main_queue(), ^{
        Toast* toast = [[Toast alloc] initWithMessage:@"Failed to use passkey"];
        [[ToastStore instance] addToast:toast];
    });
}

#pragma mark - Presentation

- (ASPresentationAnchor)presentationAnchorForAuthorizationController:(ASAuthorizationController *)controller {
    return NSApplication.sharedApplication.keyWindow ?: NSApplication.sharedApplication.windows.firstObject;
}

@end