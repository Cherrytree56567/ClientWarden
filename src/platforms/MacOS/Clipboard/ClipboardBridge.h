#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface CWClipboard : NSObject

- (void)copy:(NSString *)str;
- (NSString *)paste;
- (void)setDelay:(NSInteger)delay;
- (NSInteger)getDelay;

@end

NS_ASSUME_NONNULL_END