//
//  INXAsyncWritePacket.h
//  InnotechIMSDK
//
//  Created by jocer on 2019/8/21.
//  Copyright © 2019 jocer. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN
/**
 * INXAsyncWritePacket包含任何给定写入的指令。
 **/
@interface INXAsyncWritePacket : NSObject
{
@public
    NSData *buffer;
    NSUInteger bytesDone;
    long tag;
    NSTimeInterval timeout;
}
- (id)initWithData:(NSData *)d timeout:(NSTimeInterval)t tag:(long)i;
@end

NS_ASSUME_NONNULL_END
