#import <Foundation/Foundation.h>
#import <AuthenticationServices/AuthenticationServices.h>

@interface DarwinNotifs : NSObject <ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding>
+ (void)setupDarwinNotifs;
@end