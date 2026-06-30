#import "LoginBridge.h"
#import <Cocoa/Cocoa.h>
#import "clientwarden-Swift.h"
#include "Vault.h"

@implementation LoginBridge

+ (void)setupCallbacks {
    [self cb_login];
    [self cb_submitCode];
}

+ (void)cb_login {
    Login.instance.cb_login = ^bool(NSString* email, NSString* password, NSString* vaultURL, NSString* mainURL, 
                                                NSString* apiURL, NSString* wssURL, NSString* iconURL) {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

        v_inst.SetUris(vaultURL.UTF8String, mainURL.UTF8String, apiURL.UTF8String, iconURL.UTF8String, wssURL.UTF8String);

        std::string c_email = email.UTF8String;
        std::string c_password = password.UTF8String;

        ClientWarden::AuthState result = v_inst.Login(c_email, c_password);

        if (result == ClientWarden::AuthState::NeedsTOTP) {
            v_inst.codeType = ClientWarden::AuthState::NeedsTOTP;
            Login.instance.EmailPasswordView = false;
            return true;
        } else if (result == ClientWarden::AuthState::NeedsEmailVerification) {
            v_inst.codeType = ClientWarden::AuthState::NeedsEmailVerification;
            Login.instance.EmailPasswordView = false;
            return true;
        } else if (result != ClientWarden::AuthState::Authenticated) {
            return false;
        }

        if (v_inst.postLogin() != ClientWarden::NetworkState::Success) {
            return false;
        }

        v_inst.startRefreshThread();
        v_inst.startWSSLoop();
        v_inst.Sync();
        
        ClientwardenWindow.instance.state = WindowStateVault;

        return true;
    };
}

+ (void)cb_submitCode {
    Login.instance.cb_submitCode = ^bool(NSString* code) {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
        ClientWarden::AuthState result;

        std::string c_code = code.UTF8String;

        if (v_inst.codeType == ClientWarden::AuthState::NeedsEmailVerification) {
            result = v_inst.submitDeviceVerify(c_code);
        } else if (v_inst.codeType == ClientWarden::AuthState::NeedsTOTP) {
            result = v_inst.submitTOTP(c_code);
        } else {
            Login.instance.EmailPasswordView = true;
            return false;
        }

        if (result != ClientWarden::AuthState::Authenticated) {
            Login.instance.EmailPasswordView = true;
            return false;
        }

        if (v_inst.postLogin() != ClientWarden::NetworkState::Success) {
            Login.instance.EmailPasswordView = true;
            return false;
        }

        v_inst.startRefreshThread();
        v_inst.startWSSLoop();
        v_inst.Sync();

        Login.instance.EmailPasswordView = true;
        ClientwardenWindow.instance.state = WindowStateVault;

        return true;
    };
}

@end