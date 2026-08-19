#import <Foundation/Foundation.h>
#import <AuthenticationServices/AuthenticationServices.h>

@interface LoginBridge : NSObject <ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding>
+ (void)setupCallbacks;
@end